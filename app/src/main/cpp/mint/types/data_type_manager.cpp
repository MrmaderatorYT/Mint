#include "mint/types/data_type_manager.h"

#include <algorithm>
#include <limits>
#include <memory>
#include <set>
#include <sstream>
#include <utility>
#include <functional>
#include "mint/analysis/user_prototype.h"

namespace mint {
namespace {

Status bad(const std::string& message) {
    return Status::error(ErrorCode::kBadFormat, "type library: " + message);
}

bool initial(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
}
bool digit(char c) { return c >= '0' && c <= '9'; }
bool space(char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; }

struct Primitive { const char* name; u8 size; bool isSigned; bool integer; };
constexpr Primitive kPrimitives[] = {
    {"void", 0, false, false}, {"bool", 1, false, true}, {"char", 1, false, true},
    {"u8", 1, false, true}, {"u16", 2, false, true}, {"u32", 4, false, true},
    {"u64", 8, false, true}, {"i8", 1, true, true}, {"i16", 2, true, true},
    {"i32", 4, true, true}, {"i64", 8, true, true},
    {"f32", 4, true, false}, {"f64", 8, true, false},
};
const Primitive* primitive(const std::string& name) {
    for (const auto& p : kPrimitives) if (name == p.name) return &p;
    return nullptr;
}
bool reserved(const std::string& name) {
    return primitive(name) || name == "pointer" || name == "struct" ||
           name == "packed" || name == "union" || name == "enum";
}

struct Node;
using Type = std::shared_ptr<Node>;
struct Field { std::string name; Type type; bool hasOffset = false; u64 offset = 0; };
struct Node {
    enum Kind { kNamed, kPointer, kArray, kStruct, kUnion, kEnum } kind = kNamed;
    std::string name;
    Type child;
    u64 count = 0;
    bool packed = false;
    std::vector<Field> fields;
    std::vector<DataTypeEnumerator> enums;
};

std::string canonical(const Type& n) {
    switch (n->kind) {
        case Node::kNamed: return n->name;
        case Node::kPointer: return canonical(n->child) + "*";
        case Node::kArray: return canonical(n->child) + "[" + std::to_string(n->count) + "]";
        case Node::kStruct:
        case Node::kUnion: {
            std::string s = n->kind == Node::kUnion ? "union{" : n->packed ? "packed{" : "struct{";
            for (size_t i = 0; i < n->fields.size(); ++i) {
                if (i) s += ';';
                const auto& f = n->fields[i];
                s += f.name + ":" + canonical(f.type);
                if (f.hasOffset) s += "@" + std::to_string(f.offset);
            }
            return s + '}';
        }
        case Node::kEnum: {
            std::string s = "enum:" + canonical(n->child) + '{';
            for (size_t i = 0; i < n->enums.size(); ++i) {
                if (i) s += ';';
                s += n->enums[i].name + "=" + std::to_string(n->enums[i].value);
            }
            return s + '}';
        }
    }
    return {};
}

class Parser {
public:
    explicit Parser(const std::string& text) : text_(text) {}
    Status declaration(std::string* name, Type* type) {
        if (text_.size() > DataTypeManager::kMaxDeclarationBytes) return bad("declaration exceeds 16 KiB");
        *name = identifier();
        if (name->empty() || reserved(*name)) return bad("invalid or reserved definition name");
        if (!take('=')) return bad("expected '=' after definition name");
        *type = expression(0u);
        return finish(*type);
    }
    Status expression(Type* type) {
        if (text_.size() > DataTypeManager::kMaxDeclarationBytes) return bad("expression exceeds 16 KiB");
        *type = expression(0u);
        return finish(*type);
    }
private:
    void skip() { while (pos_ < text_.size() && space(text_[pos_])) ++pos_; }
    bool take(char c) {
        skip();
        if (pos_ < text_.size() && text_[pos_] == c) { ++pos_; return true; }
        return false;
    }
    bool peek(char c) { skip(); return pos_ < text_.size() && text_[pos_] == c; }
    std::string identifier() {
        skip();
        const auto start = pos_;
        if (pos_ >= text_.size() || !initial(text_[pos_])) return {};
        ++pos_;
        while (pos_ < text_.size() && (initial(text_[pos_]) || digit(text_[pos_]))) ++pos_;
        if (pos_ - start > 128) { error_ = "identifier exceeds 128 bytes"; return {}; }
        return text_.substr(start, pos_ - start);
    }
    bool number(u64* value) {
        skip();
        unsigned base = 10;
        if (pos_ + 1 < text_.size() && text_[pos_] == '0' &&
            (text_[pos_ + 1] == 'x' || text_[pos_ + 1] == 'X')) { pos_ += 2; base = 16; }
        const auto start = pos_;
        *value = 0;
        while (pos_ < text_.size()) {
            char c = text_[pos_];
            unsigned v = digit(c) ? static_cast<unsigned>(c - '0') :
                (c >= 'a' && c <= 'f') ? static_cast<unsigned>(c - 'a' + 10) :
                (c >= 'A' && c <= 'F') ? static_cast<unsigned>(c - 'A' + 10) : 16;
            if (v >= base) break;
            if (*value > (std::numeric_limits<u64>::max() - v) / base) {
                error_ = "integer overflow"; return false;
            }
            *value = *value * base + v;
            ++pos_;
        }
        if (pos_ == start) { error_ = "expected integer"; return false; }
        return true;
    }
    bool signedNumber(i64* value) {
        bool negative = take('-');
        if (!negative) take('+');
        u64 magnitude = 0;
        if (!number(&magnitude)) return false;
        constexpr u64 max = static_cast<u64>(std::numeric_limits<i64>::max());
        if (magnitude > max + (negative ? 1 : 0)) { error_ = "enum value exceeds signed 64-bit range"; return false; }
        *value = negative ? (magnitude == max + 1 ? std::numeric_limits<i64>::min() : -static_cast<i64>(magnitude))
                          : static_cast<i64>(magnitude);
        return true;
    }
    Type expression(unsigned depth) {
        if (depth >= 64) { error_ = "nesting exceeds 64 levels"; return {}; }
        auto name = identifier();
        if (name.empty()) { if (error_.empty()) error_ = "expected type name"; return {}; }
        auto n = std::make_shared<Node>();
        if (name == "struct" || name == "packed" || name == "union") {
            n->kind = name == "union" ? Node::kUnion : Node::kStruct;
            n->packed = name == "packed";
            if (!take('{')) { error_ = "expected '{' after aggregate"; return {}; }
            std::set<std::string> names;
            while (!take('}')) {
                if (n->fields.size() >= 256) { error_ = "aggregate exceeds 256 fields"; return {}; }
                Field f;
                f.name = identifier();
                if (f.name.empty() || !names.insert(f.name).second || !take(':')) {
                    error_ = "expected unique field name and ':'"; return {};
                }
                f.type = expression(depth + 1);
                if (!f.type) return {};
                if (take('@')) { f.hasOffset = true; if (!number(&f.offset)) return {}; }
                n->fields.push_back(std::move(f));
                if (peek('}')) continue;
                if (!take(';')) { error_ = "expected ';' or '}' after field"; return {}; }
            }
            if (n->fields.empty()) { error_ = "empty aggregates are not supported"; return {}; }
        } else if (name == "enum") {
            n->kind = Node::kEnum;
            if (!take(':')) { error_ = "expected ':' and enum integer type"; return {}; }
            n->child = expression(depth + 1);
            if (!n->child || !take('{')) { error_ = "expected enum body '{'"; return {}; }
            std::set<std::string> names;
            while (!take('}')) {
                if (n->enums.size() >= 1024) { error_ = "enum exceeds 1024 values"; return {}; }
                DataTypeEnumerator e;
                e.name = identifier();
                if (e.name.empty() || !names.insert(e.name).second || !take('=') || !signedNumber(&e.value)) {
                    if (error_.empty()) error_ = "expected unique enumerator and integer value";
                    return {};
                }
                n->enums.push_back(std::move(e));
                if (peek('}')) continue;
                if (!take(';')) { error_ = "expected ';' or '}' after enumerator"; return {}; }
            }
            if (n->enums.empty()) { error_ = "empty enums are not supported"; return {}; }
        } else if (name == "pointer") {
            n->kind = Node::kPointer;
            n->child = std::make_shared<Node>();
            n->child->name = "void";
        } else {
            n->kind = Node::kNamed;
            n->name = std::move(name);
        }
        unsigned suffixes = 0;
        for (;;) {
            if (++suffixes + depth >= 64) { error_ = "nesting exceeds 64 levels"; return {}; }
            if (take('*')) {
                auto p = std::make_shared<Node>();
                p->kind = Node::kPointer; p->child = n; n = std::move(p);
            } else if (take('[')) {
                u64 count = 0;
                if (!number(&count) || !take(']') || !count || count > DataTypeManager::kMaxTypeBytes) {
                    if (error_.empty()) error_ = "array needs a positive bounded length and ']'";
                    return {};
                }
                auto a = std::make_shared<Node>();
                a->kind = Node::kArray; a->child = n; a->count = count; n = std::move(a);
            } else break;
        }
        return n;
    }
    Status finish(const Type& type) {
        skip();
        if (!type || !error_.empty()) return bad(error_.empty() ? "invalid expression" : error_);
        if (pos_ != text_.size()) return bad("unexpected character at byte " + std::to_string(pos_));
        return Status::success();
    }
    const std::string& text_;
    size_t pos_ = 0;
    std::string error_;
};

using Library = std::map<std::string, Type>;
Status parseLibrary(const std::map<std::string, std::string>& declarations, Library* out) {
    for (const auto& item : declarations) {
        Type type;
        auto s = Parser(item.second).expression(&type);
        if (!s.ok()) return s;
        out->emplace(item.first, std::move(type));
    }
    return Status::success();
}

// Validate names even behind a pointer without recursing through definitions:
// pointers break layout cycles, but must not hide a misspelled/deleted type.
Status references(const Type& n, const Library& library) {
    if (n->kind == Node::kNamed && !primitive(n->name) && library.find(n->name) == library.end())
        return bad("unknown type '" + n->name + "'");
    if (n->child) { auto s = references(n->child, library); if (!s.ok()) return s; }
    for (const auto& f : n->fields) { auto s = references(f.type, library); if (!s.ok()) return s; }
    return Status::success();
}

bool alignUp(u64 value, u32 alignment, u64* out) {
    if (value > DataTypeManager::kMaxTypeBytes - (alignment - 1)) return false;
    *out = (value + alignment - 1) / alignment * alignment;
    return *out <= DataTypeManager::kMaxTypeBytes;
}

class Resolver {
public:
    Resolver(const Library& library, u8 pointerSize,
             const std::map<std::string, DataTypeLayout>* initialCache = nullptr)
        : library_(library), pointerSize_(pointerSize), initialCache_(initialCache) {}
    const std::map<std::string, DataTypeLayout>& cachedLayouts() const { return cache_; }
    Status layout(const Type& n, DataTypeLayout* out, unsigned depth = 0) {
        if (depth >= 64) return bad("dependent layout exceeds 64 levels");
        *out = {};
        out->expression = canonical(n);
        switch (n->kind) {
            case Node::kNamed: {
                if (const auto* p = primitive(n->name)) {
                    out->size = p->size;
                    out->alignment = std::max<u32>(p->size, 1);
                    out->isSigned = p->isSigned;
                    out->isFloating = !p->integer && p->size != 0;
                    return Status::success();
                }
                auto cached = cache_.find(n->name);
                if (cached != cache_.end()) { *out = cached->second; out->expression = n->name; return Status::success(); }
                if (initialCache_) {
                    auto initial = initialCache_->find(n->name);
                    if (initial != initialCache_->end()) { *out = initial->second; out->expression = n->name; return Status::success(); }
                }
                auto it = library_.find(n->name);
                if (it == library_.end()) return bad("unknown type '" + n->name + "'");
                if (!active_.insert(n->name).second) return bad("by-value cycle through '" + n->name + "'");
                auto s = layout(it->second, out, depth + 1);
                active_.erase(n->name);
                if (s.ok()) { out->expression = n->name; cache_[n->name] = *out; }
                return s;
            }
            case Node::kPointer: {
                // An identifier may name this aggregate recursively: its full
                // storage is validated as a library definition. Inline target
                // expressions still need validation, otherwise a pointer could
                // conceal an impossible void array or overlapping aggregate.
                if (n->child->kind != Node::kNamed) {
                    DataTypeLayout target;
                    auto s = layout(n->child, &target, depth + 1);
                    if (!s.ok()) return s;
                }
                out->kind = DataTypeKind::kPointer;
                out->size = out->alignment = pointerSize_;
                return Status::success();
            }
            case Node::kArray: {
                DataTypeLayout element;
                auto s = layout(n->child, &element, depth + 1);
                if (!s.ok()) return s;
                if (!element.size || element.size > DataTypeManager::kMaxTypeBytes / n->count)
                    return bad("array element is void or array size exceeds 1 GiB");
                out->kind = DataTypeKind::kArray;
                out->size = element.size * n->count;
                out->alignment = element.alignment;
                return Status::success();
            }
            case Node::kEnum: {
                DataTypeLayout base;
                auto s = layout(n->child, &base, depth + 1);
                if (!s.ok()) return s;
                // Integer aliases are allowed, but floats, aggregates and an
                // enum-as-enum-base are rejected instead of inventing an ABI.
                if (base.kind != DataTypeKind::kPrimitive || !base.size ||
                    !integerBase(n->child, 0)) return bad("enum base must be an integer primitive or alias");
                for (const auto& e : n->enums) {
                    if (!base.isSigned && e.value < 0) return bad("negative enum value in unsigned type");
                    const unsigned bits = static_cast<unsigned>(base.size * 8);
                    if (bits < 64) {
                        const i64 min = base.isSigned ? -(i64(1) << (bits - 1)) : 0;
                        const i64 max = base.isSigned ? (i64(1) << (bits - 1)) - 1 : (i64(1) << bits) - 1;
                        if (e.value < min || e.value > max) return bad("enum value does not fit its integer base");
                    }
                }
                out->kind = DataTypeKind::kEnum;
                out->size = base.size; out->alignment = base.alignment; out->isSigned = base.isSigned;
                out->enumerators = n->enums;
                return Status::success();
            }
            case Node::kStruct:
            case Node::kUnion: {
                out->kind = n->kind == Node::kUnion ? DataTypeKind::kUnion : DataTypeKind::kStruct;
                out->packed = n->packed;
                u64 end = 0;
                for (const auto& f : n->fields) {
                    DataTypeLayout field;
                    auto s = layout(f.type, &field, depth + 1);
                    if (!s.ok()) return s;
                    if (!field.size) return bad("field '" + f.name + "' has void storage");
                    u32 alignment = n->packed ? 1 : field.alignment;
                    u64 offset = 0;
                    if (f.hasOffset) {
                        offset = f.offset;
                        if ((n->kind == Node::kUnion && offset != 0) || offset % alignment)
                            return bad("field '" + f.name + "' has an invalid/misaligned explicit offset");
                    } else if (n->kind == Node::kStruct && !alignUp(end, alignment, &offset)) {
                        return bad("aggregate alignment exceeds 1 GiB");
                    }
                    if (n->kind == Node::kStruct && offset < end)
                        return bad("field '" + f.name + "' overlaps preceding storage");
                    if (offset > DataTypeManager::kMaxTypeBytes || field.size > DataTypeManager::kMaxTypeBytes - offset)
                        return bad("aggregate exceeds 1 GiB");
                    end = std::max(end, offset + field.size);
                    out->alignment = std::max(out->alignment, alignment);
                    out->fields.push_back({f.name, canonical(f.type), offset, field.size, alignment});
                }
                if (!alignUp(end, out->alignment, &out->size)) return bad("aggregate size exceeds 1 GiB");
                return Status::success();
            }
        }
        return bad("unknown expression");
    }
private:
    bool integerBase(const Type& n, unsigned depth) const {
        if (depth >= 64 || n->kind != Node::kNamed) return false;
        if (const auto* p = primitive(n->name)) return p->integer;
        auto it = library_.find(n->name);
        return it != library_.end() && integerBase(it->second, depth + 1);
    }
    const Library& library_;
    u8 pointerSize_;
    const std::map<std::string, DataTypeLayout>* initialCache_;
    std::map<std::string, DataTypeLayout> cache_;
    std::set<std::string> active_;
};

}  // namespace

struct DataTypeCompiled {
    Library library;
    std::map<std::string, DataTypeLayout> layouts;
};

Status DataTypeManager::cHeader(std::string* output) const {
    if(!output)return bad("missing C header output");
    std::ostringstream text;text<<"#include <stdint.h>\n#include <stddef.h>\n";
    text<<"_Static_assert(sizeof(void*) == "<<static_cast<unsigned>(pointerSize_)<<", \"Mint target pointer width\");\n";
    if(!compiled_){*output=text.str();return Status::success();}
    const auto& library=compiled_->library;
    auto aggregate=[](const Type& node){return node->kind==Node::kStruct || node->kind==Node::kUnion;};
    for(const auto& item:library) {
        if(!userIdentifier(item.first))return bad("type name is not a C identifier: "+item.first);
        if(aggregate(item.second))text<<"typedef "<<(item.second->kind==Node::kUnion?"union ":"struct ")<<"mint_type_"<<item.first<<' '<<item.first<<";\n";
    }
    std::map<std::string,int> visited;std::vector<std::string> order;
    std::function<Status(const std::string&,unsigned)> visit;
    std::function<Status(const Type&,bool,unsigned)> dependencies;
    dependencies=[&](const Type& node,bool pointer,unsigned depth)->Status {
        if(depth>128)return bad("C declaration dependency depth exceeded");
        if(node->kind==Node::kNamed) {
            const auto found=library.find(node->name);
            if(found==library.end() || (pointer && aggregate(found->second)))return Status::success();
            return visit(node->name,depth+1);
        }
        if(node->kind==Node::kPointer)return dependencies(node->child,true,depth+1);
        if(node->kind==Node::kArray || node->kind==Node::kEnum)return dependencies(node->child,false,depth+1);
        for(const auto& field:node->fields){auto status=dependencies(field.type,false,depth+1);if(!status.ok())return status;}
        return Status::success();
    };
    visit=[&](const std::string& name,unsigned depth)->Status {
        if(visited[name]==2)return Status::success();
        if(visited[name]==1)return bad("recursive typedef aliases cannot be represented in C: "+name);
        visited[name]=1;auto status=dependencies(library.at(name),false,depth+1);if(!status.ok())return status;
        visited[name]=2;order.push_back(name);return Status::success();
    };
    for(const auto& item:library){auto status=visit(item.first,0);if(!status.ok())return status;}
    Resolver resolver(library,pointerSize_,&compiled_->layouts);
    std::function<Status(const Type&,const std::string&,std::string*,unsigned)> declaration;
    declaration=[&](const Type& node,const std::string& name,std::string* result,unsigned depth)->Status {
        if(depth>128)return bad("C declaration nesting exceeds limit");
        if(node->kind==Node::kNamed) {
            static const std::map<std::string,std::string> names={{"u8","uint8_t"},{"u16","uint16_t"},{"u32","uint32_t"},{"u64","uint64_t"},{"i8","int8_t"},{"i16","int16_t"},{"i32","int32_t"},{"i64","int64_t"},{"bool","uint8_t"},{"f32","float"},{"f64","double"}};
            auto found=names.find(node->name);*result=(found==names.end()?node->name:found->second)+" "+name;return Status::success();
        }
        if(node->kind==Node::kPointer)return declaration(node->child,node->child->kind==Node::kArray?"(*"+name+")":"*"+name,result,depth+1);
        if(node->kind==Node::kArray)return declaration(node->child,name+"["+std::to_string(node->count)+"]",result,depth+1);
        if(node->kind==Node::kEnum)return declaration(node->child,name,result,depth+1);
        DataTypeLayout layout;auto status=resolver.layout(node,&layout);if(!status.ok())return status;
        std::ostringstream body;body<<(node->kind==Node::kUnion?"union":"struct")<<" __attribute__((packed, aligned("<<layout.alignment<<"))) {\n";
        std::set<std::string> fields;for(const auto& field:node->fields) {
            if(!userIdentifier(field.name))return bad("field name is not a C identifier: "+field.name);
            fields.insert(field.name);
        }
        u64 end=0;size_t padding=0;
        auto pad=[&](u64 size) {std::string label;do{label="mint_padding_"+std::to_string(padding++);}while(fields.count(label));fields.insert(label);body<<"  uint8_t "<<label<<'['<<size<<"];\n";};
        for(size_t i=0;i<node->fields.size();++i) {
            const auto& field=node->fields[i];const auto& location=layout.fields[i];
            if(node->kind==Node::kStruct && location.offset>end)pad(location.offset-end);
            std::string rendered;status=declaration(field.type,field.name,&rendered,depth+1);if(!status.ok())return status;
            body<<"  "<<rendered<<";\n";end=std::max(end,location.offset+location.size);
        }
        if(node->kind==Node::kStruct && layout.size>end)pad(layout.size-end);
        body<<"} "<<name;*result=body.str();return Status::success();
    };
    for(const auto& name:order) {
        const auto& node=library.at(name);std::string rendered;
        auto status=declaration(node,aggregate(node)?"":name,&rendered,0);if(!status.ok())return status;
        if(aggregate(node)) {
            const auto at=rendered.find(" {");rendered.insert(at," mint_type_"+name);text<<rendered<<";\n";
        } else text<<"typedef "<<rendered<<";\n";
        const auto& layout=compiled_->layouts.at(name);
        text<<"_Static_assert(sizeof("<<name<<") == "<<layout.size<<", \"Mint layout: "<<name<<"\");\n";
        for(const auto& field:layout.fields)text<<"_Static_assert(offsetof("<<name<<", "<<field.name<<") == "<<field.offset<<", \"Mint field offset\");\n";
        if(text.tellp()>static_cast<std::streamoff>(kMaxLibraryBytes))return Status::error(ErrorCode::kTooLarge,"C type header exceeds 1 MiB");
    }
    *output=text.str();return Status::success();
}

bool DataTypeManager::validName(const std::string& name) {
    if (name.empty() || name.size() > 128 || !initial(name[0])) return false;
    for (char c : name) if (!initial(c) && !digit(c)) return false;
    return !reserved(name);
}

Status DataTypeManager::validate() {
    if (pointerSize_ != 4 && pointerSize_ != 8) return bad("pointer size must be 4 or 8");
    if (definitions_.size() > kMaxDefinitions || serialize().size() > kMaxLibraryBytes)
        return Status::error(ErrorCode::kTooLarge, "type library exceeds resource budget");
    auto compiled = std::make_shared<DataTypeCompiled>();
    auto s = parseLibrary(definitions_, &compiled->library);
    if (!s.ok()) return s;
    Resolver resolver(compiled->library, pointerSize_);
    for (const auto& item : compiled->library) {
        s = references(item.second, compiled->library);
        if (!s.ok()) return s;
        DataTypeLayout layout;
        auto named = std::make_shared<Node>();
        named->name = item.first;
        s = resolver.layout(named, &layout);
        if (!s.ok()) return bad(item.first + ": " + s.message());
    }
    compiled->layouts = resolver.cachedLayouts();
    compiled_ = std::move(compiled);
    return Status::success();
}

Status DataTypeManager::define(const std::string& declaration) {
    std::string name;
    Type type;
    auto s = Parser(declaration).declaration(&name, &type);
    if (!s.ok()) return s;
    DataTypeManager candidate = *this;
    candidate.definitions_[name] = canonical(type);
    s = candidate.validate();
    if (s.ok()) { definitions_.swap(candidate.definitions_); compiled_ = std::move(candidate.compiled_); }
    return s;
}

Status DataTypeManager::erase(const std::string& name) {
    if (definitions_.find(name) == definitions_.end()) return Status::error(ErrorCode::kNotFound, "type not found: " + name);
    DataTypeManager candidate = *this;
    candidate.definitions_.erase(name);
    auto s = candidate.validate();
    if (s.ok()) { definitions_.swap(candidate.definitions_); compiled_ = std::move(candidate.compiled_); }
    return s;
}

Status DataTypeManager::resolve(const std::string& expression, DataTypeLayout* out) const {
    if (!out) return bad("null layout result");
    if (pointerSize_ != 4 && pointerSize_ != 8) return bad("pointer size must be 4 or 8");
    Type type;
    auto s = Parser(expression).expression(&type);
    if (!s.ok()) return s;
    static const Library empty;
    const auto& library = compiled_ ? compiled_->library : empty;
    s = references(type, library);
    if (!s.ok()) return s;
    DataTypeLayout result;
    s = Resolver(library, pointerSize_, compiled_ ? &compiled_->layouts : nullptr).layout(type, &result);
    if (s.ok()) *out = std::move(result);
    return s;
}

std::vector<DataTypeDefinition> DataTypeManager::definitions() const {
    std::vector<DataTypeDefinition> result;
    if (!compiled_) return result;
    for (const auto& item : definitions_) {
        auto found = compiled_->layouts.find(item.first);
        if (found == compiled_->layouts.end()) continue;
        DataTypeLayout layout = found->second;
        layout.expression = item.first;
        result.push_back({item.first, item.first + "=" + item.second, std::move(layout)});
    }
    return result;
}

std::string DataTypeManager::declarationFor(const std::string& name) const {
    auto it = definitions_.find(name);
    return it == definitions_.end() ? std::string() : it->first + "=" + it->second;
}

std::string DataTypeManager::renderDefinitions() const {
    std::ostringstream out;
    out << "Type library (" << unsigned(pointerSize_ * 8) << "-bit pointers)\n";
    out << "Builtins: u8/u16/u32/u64, i8/i16/i32/i64, f32/f64, bool, char, void, pointer\n";
    for (const auto& item : definitions()) {
        out << '\n' << item.declaration << "\n  size=" << item.layout.size << " alignment=" << item.layout.alignment << '\n';
        for (const auto& f : item.layout.fields)
            out << "  +0x" << std::hex << f.offset << std::dec << " " << f.name << ": " << f.type << " (" << f.size << " bytes)\n";
    }
    return out.str();
}

std::string DataTypeManager::serialize() const {
    std::string result = "MINT_TYPES 1 " + std::to_string(pointerSize_) + '\n';
    for (const auto& item : definitions_) result += item.first + '=' + item.second + '\n';
    return result;
}

Status DataTypeManager::deserialize(const std::string& text) {
    if (text.size() > kMaxLibraryBytes) return Status::error(ErrorCode::kTooLarge, "type library exceeds 1 MiB");
    const std::string header = "MINT_TYPES 1 " + std::to_string(pointerSize_) + '\n';
    if (text.compare(0, header.size(), header) != 0) return bad("invalid version or pointer size in library header");
    DataTypeManager candidate(pointerSize_);
    size_t pos = header.size();
    while (pos < text.size()) {
        const auto end = text.find('\n', pos);
        if (end == std::string::npos) return bad("library must end in newline");
        std::string name;
        Type type;
        const auto line = text.substr(pos, end - pos);
        auto s = Parser(line).declaration(&name, &type);
        if (!s.ok()) return s;
        if (!candidate.definitions_.emplace(name, canonical(type)).second) return bad("duplicate definition '" + name + "'");
        if (candidate.definitions_.size() > kMaxDefinitions) return Status::error(ErrorCode::kTooLarge, "too many type definitions");
        pos = end + 1;
    }
    auto s = candidate.validate();
    if (s.ok()) { definitions_.swap(candidate.definitions_); compiled_ = std::move(candidate.compiled_); }
    return s;
}

}  // namespace mint
