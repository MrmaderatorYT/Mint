#include "mint/analysis/program.h"
#include "mint/analysis/user_prototype.h"
#include "mint/types/signature_library.h"
#include <cctype>
#include <fstream>
#include <unistd.h>
#include <fcntl.h>
#include <cstdio>
#include <cerrno>
#include <cstring>
#include <algorithm>
#include <tuple>

namespace mint {
Status Program::open(const std::string& path, const std::string& source) {
    State loaded;
    std::ifstream input(path,std::ios::binary);
    if (!input) {
        if (access(path.c_str(),F_OK)==0 || errno != ENOENT) return Status::error(ErrorCode::kIoError,"cannot read project");
    } else {
        input.seekg(0,std::ios::end);
        if (input.tellg()>16*1024*1024) return Status::error(ErrorCode::kTooLarge,"project exceeds 16 MiB");
        input.seekg(0);
        char magic[8]; u32 count = 0;
        if (!input.read(magic,8) || (std::memcmp(magic,"MINTPR01",8)!=0 && std::memcmp(magic,"MINTPR02",8)!=0 && std::memcmp(magic,"MINTPR03",8)!=0 && std::memcmp(magic,"MINTPR04",8)!=0) || !input.read(reinterpret_cast<char*>(&count),4) || count>100000)
            return Status::error(ErrorCode::kBadFormat,"invalid/newer project format");
        for (u32 i=0;i<count;++i) {
            Address address; u32 kindSize, valueSize;
            if (!input.read(reinterpret_cast<char*>(&address),8) || !input.read(reinterpret_cast<char*>(&kindSize),4) || !input.read(reinterpret_cast<char*>(&valueSize),4) || kindSize>32 || valueSize>1024*1024 || ((std::memcmp(magic,"MINTPR03",8)!=0 && std::memcmp(magic,"MINTPR04",8)!=0) && valueSize>65536))
                return Status::error(ErrorCode::kBadFormat,"truncated project record");
            std::string kind(kindSize,'\0'),value(valueSize,'\0');
            if (!input.read(kind.data(),kindSize) || !input.read(value.data(),valueSize)) return Status::error(ErrorCode::kTruncated,"truncated project value");
            if (value.find('\0')!=std::string::npos || (kind!="name" && kind!="comment" && kind!="bookmark" && kind!="data" && kind!="prototype" && kind!="type-library" && kind!="signature-library" && kind!="function" && kind!="patch" && kind!="source" && kind!="locals"))
                return Status::error(ErrorCode::kBadFormat,"invalid project annotation");
            if (kind=="name" && !userIdentifier(value)) return Status::error(ErrorCode::kBadFormat,"invalid project symbol");
            if (kind=="prototype") {UserPrototype prototype; if (!parseUserPrototype(value,&prototype).ok()) return Status::error(ErrorCode::kBadFormat,"invalid project prototype");}
            if (!loaded.emplace(Key{address,kind},value).second) return Status::error(ErrorCode::kBadFormat,"duplicate project annotation");
        }
        if (input.peek()!=std::char_traits<char>::eof()) return Status::error(ErrorCode::kBadFormat,"trailing project data");
    }
    if (!source.empty()) {
        auto bound=loaded.find({0,"source"});
        if (bound!=loaded.end() && bound->second!=source) return Status::error(ErrorCode::kBadFormat,"project belongs to a different binary or raw configuration");
        loaded[{0,"source"}]=source;
    }
    DataTypeManager types(types_.pointerSize()); auto status=validate(loaded,&types); if (!status.ok()) return status;
    if (!source.empty()) {auto previousPath=path_;path_=path;status=save(loaded);path_=previousPath;if(!status.ok())return status;}
    path_ = path; state_ = std::move(loaded); types_=std::move(types); memory_={};undo_.clear(); redo_.clear(); ++revision_; invalidateReferences();
    return Status::success();
}
std::string Program::get(Address address, const std::string& kind) const {
    auto it = state_.find({address,kind}); return it == state_.end() ? "" : it->second;
}
std::vector<ProgramAnnotation> Program::annotations() const {
    std::vector<ProgramAnnotation> result;
    for (const auto& e : state_) result.push_back({e.first.first,e.first.second,e.second});
    return result;
}
Status Program::save(const State& state) {
    if (path_.empty()) return Status::error(ErrorCode::kIoError, "open a persistent project first");
    if (state.size()>100000) return Status::error(ErrorCode::kTooLarge,"too many project annotations");
    std::string data("MINTPR04",8);
    auto append = [&](const auto& value) { data.append(reinterpret_cast<const char*>(&value),sizeof(value)); };
    const u32 count = static_cast<u32>(state.size()); append(count);
    for (const auto& e : state) {
        append(e.first.first); const u32 kindSize=static_cast<u32>(e.first.second.size()),valueSize=static_cast<u32>(e.second.size());
        append(kindSize); append(valueSize); data+=e.first.second; data+=e.second;
        if (data.size()>16*1024*1024) return Status::error(ErrorCode::kTooLarge,"project exceeds 16 MiB");
    }
    std::string temporary = path_+".tmp.XXXXXX";
    int fd = mkstemp(temporary.data());
    if (fd<0) return Status::error(ErrorCode::kIoError,"cannot create project transaction");
    size_t written=0; bool ok=true;
    while (written<data.size()) {
        const auto n=write(fd,data.data()+written,data.size()-written);
        if (n<0 && errno==EINTR) continue;
        if (n<=0) {ok=false;break;} written+=static_cast<size_t>(n);
    }
    if (ok) ok=fsync(fd)==0;
    if (close(fd)!=0) ok=false;
    if (ok) ok=std::rename(temporary.c_str(),path_.c_str())==0;
    if (!ok) {std::remove(temporary.c_str());return Status::error(ErrorCode::kIoError,"cannot commit project transaction");}
    return Status::success();
}
Status Program::edit(Address address, const std::string& kind, const std::string& value) {
    if(kind=="source")return Status::error(ErrorCode::kBadFormat,"source identity is read-only");
    if (kind != "name" && kind != "comment" && kind != "bookmark" && kind != "data" && kind != "prototype" && kind != "type-library" && kind != "signature-library" && kind != "function" && kind != "patch" && kind != "source" && kind != "locals")
        return Status::error(ErrorCode::kBadFormat, "unknown annotation kind");
    if (value.size() > ((kind=="type-library" || kind=="signature-library" || kind=="locals") ? 1024*1024u : 4096u) || value.find('\0') != std::string::npos)
        return Status::error(ErrorCode::kTooLarge, "annotation exceeds its limit (4 KiB; type library 1 MiB) or contains NUL");
    if (kind == "name" && !value.empty()) {
        if (!userIdentifier(value)) return Status::error(ErrorCode::kBadFormat,"name must be a non-keyword C identifier");
        for (const auto& e : state_) if (e.first.second == "name" && e.first.first != address && e.second == value)
            return Status::error(ErrorCode::kBadFormat, "duplicate user symbol");
    }
    if (kind == "prototype") { UserPrototype prototype; auto status=parseUserPrototype(value,&prototype); if (!status.ok()) return status; }
    State next = state_;
    if (value.empty()) next.erase({address,kind}); else next[{address,kind}] = value;
    if (next == state_) return Status::success();
    DataTypeManager types(types_.pointerSize()); auto validity=validate(next,&types); if (!validity.ok()) return validity;
    auto status = save(next); if (!status.ok()) return status;
    if (undo_.size() == 64) undo_.erase(undo_.begin());
    const auto previous=state_.find({address,kind});
    undo_.push_back({{address,kind},previous==state_.end()?"":previous->second,value,previous!=state_.end(),!value.empty()});
    state_ = std::move(next); types_=std::move(types); redo_.clear(); ++revision_;
    if(kind=="data" || kind=="function" || kind=="patch" || kind=="type-library") invalidateReferences(kind=="patch");
    return Status::success();
}
Status Program::validate(const State& state, DataTypeManager* types) const {
    *types=importedTypes_;
    const auto library=state.find({0,"type-library"});
    if (library!=state.end()) {
        auto status=types->deserialize(library->second); if (!status.ok()) return status;
        std::string combined=types->serialize();
        for(const auto& definition:importedTypes_.definitions())
            if(types->declarationFor(definition.name).empty())combined+=definition.declaration+'\n';
        // Deserialize as one library so mutually recursive pointer definitions
        // work. If an explicit user override makes an imported layout invalid,
        // keep that user's valid library instead of rejecting their project.
        auto candidate=*types;if(candidate.deserialize(combined).ok())*types=std::move(candidate);
    }
    std::vector<std::string> names;
    for(const auto& e:state) {
        const auto& kind=e.first.second;
        if(e.second.empty() || e.second.size()>((kind=="type-library" || kind=="signature-library" || kind=="locals")?1024*1024u:4096u))return Status::error(ErrorCode::kBadFormat,"invalid project value length");
        if((kind=="type-library" || kind=="signature-library" || kind=="source") && e.first.first!=0)return Status::error(ErrorCode::kBadFormat,"invalid project-level annotation address");
        if(kind=="signature-library"){SignatureLibrary signatures;const auto status=signatures.deserialize(e.second);if(!status.ok())return status;}
        if(kind=="locals") {
            std::vector<LocalVariableEdit> edits;auto status=parseLocalVariableEdits(e.second,&edits);if(!status.ok())return status;
            for(const auto& edit:edits)if(!edit.type.empty()) {
                DataTypeLayout layout;status=types->resolve(localTypeExpression(edit.type),&layout);if(!status.ok())return status;
                if(!layout.size || layout.size>16 || (layout.kind!=DataTypeKind::kPrimitive && layout.kind!=DataTypeKind::kPointer && layout.kind!=DataTypeKind::kEnum))
                    return Status::error(ErrorCode::kUnsupported,"local types must be scalar/pointer/enum occupying 1..16 bytes");
            }
        }
        if(kind=="function" && e.second!="code")return Status::error(ErrorCode::kBadFormat,"invalid function seed");
        if(kind=="name")names.push_back(e.second);
    }
    std::sort(names.begin(),names.end());if(std::adjacent_find(names.begin(),names.end())!=names.end())return Status::error(ErrorCode::kBadFormat,"duplicate user symbol");
    for (const auto& e:state) if (e.first.second=="data" && e.second!="cstring") {
        DataTypeLayout layout; auto status=types->resolve(e.second,&layout);
        if (!status.ok()) return status;
        if (!layout.size || layout.size>16*1024*1024) return Status::error(ErrorCode::kTooLarge,"data object must occupy 1..16 MiB");
    }
    return Status::success();
}
Status Program::replay(const Change& change,bool forward) {
    State next=state_;
    const bool present=forward ? change.hasAfter : change.hadBefore;
    if (present) next[change.key]=forward ? change.after : change.before; else next.erase(change.key);
    DataTypeManager types(types_.pointerSize()); auto status=validate(next,&types); if (!status.ok()) return status;
    status=save(next); if (!status.ok()) return status;
    state_=std::move(next); types_=std::move(types); ++revision_;
    const auto& kind=change.key.second;
    if(kind=="data" || kind=="function" || kind=="patch" || kind=="type-library") invalidateReferences(kind=="patch");
    return Status::success();
}
Status Program::undo() {
    if (undo_.empty()) return Status::error(ErrorCode::kNotFound, "nothing to undo");
    auto status = replay(undo_.back(),false); if (!status.ok()) return status;
    redo_.push_back(std::move(undo_.back())); undo_.pop_back(); return Status::success();
}
Status Program::redo() {
    if (redo_.empty()) return Status::error(ErrorCode::kNotFound, "nothing to redo");
    auto status = replay(redo_.back(),true); if (!status.ok()) return status;
    undo_.push_back(std::move(redo_.back())); redo_.pop_back(); return Status::success();
}
void Program::invalidateReferences(bool retainGroups) {
    references_.clear();incoming_.clear();outgoing_.clear();referencesReady_=false;
    if(!retainGroups)referenceGroups_.clear();
}
void Program::setReferences(std::vector<Reference> references) {
    invalidateReferences();references_=std::move(references);
    for (size_t i=0;i<references_.size();++i) {incoming_[references_[i].to].push_back(i);outgoing_[references_[i].from].push_back(i);}
    referencesReady_=true;
}
void Program::setReferenceGroups(std::vector<ReferenceGroup> groups) {
    std::vector<Reference> references;
    for(const auto& group:groups)references.insert(references.end(),group.references.begin(),group.references.end());
    std::sort(references.begin(),references.end(),[](const auto& a,const auto& b){return std::tie(a.from,a.to,a.kind)<std::tie(b.from,b.to,b.kind);});
    references.erase(std::unique(references.begin(),references.end(),[](const auto& a,const auto& b){return a.from==b.from && a.to==b.to && a.kind==b.kind;}),references.end());
    setReferences(std::move(references));referenceGroups_=std::move(groups);
}
std::vector<Program::Reference> Program::referencesAt(Address address) const {
    std::vector<size_t> indices;
    auto collect=[&](const auto& map) {auto it=map.find(address);if(it!=map.end())indices.insert(indices.end(),it->second.begin(),it->second.end());};
    collect(incoming_);collect(outgoing_);std::sort(indices.begin(),indices.end());indices.erase(std::unique(indices.begin(),indices.end()),indices.end());
    std::vector<Reference> result;for(size_t i:indices)result.push_back(references_[i]);return result;
}
Status Program::setImportedTypes(const DataTypeManager& types) {
    auto previous=importedTypes_;importedTypes_=types;
    DataTypeManager candidate(types.pointerSize());auto status=validate(state_,&candidate);
    if(!status.ok()){importedTypes_=std::move(previous);return status;}
    types_=std::move(candidate);invalidateReferences();return Status::success();
}
std::vector<LocalVariableEdit> Program::locals(Address functionEntry) const {
    std::vector<LocalVariableEdit> result;parseLocalVariableEdits(get(functionEntry,"locals"),&result);return result;
}
Status Program::editLocal(Address functionEntry,const std::string& identity,const std::string& name,const std::string& type) {
    auto edits=locals(functionEntry);
    auto found=std::find_if(edits.begin(),edits.end(),[&](const auto& edit){return edit.identity==identity;});
    if(name.empty()&&type.empty()) {if(found!=edits.end())edits.erase(found);}
    else if(found==edits.end())edits.push_back({identity,name,type});
    else *found={identity,name,type};
    const auto serialized=serializeLocalVariableEdits(edits);std::vector<LocalVariableEdit> validated;
    auto status=parseLocalVariableEdits(serialized,&validated);if(!status.ok())return status;
    return edit(functionEntry,"locals",serialized);
}
} // namespace mint
