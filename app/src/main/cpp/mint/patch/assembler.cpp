#include "mint/patch/assembler.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <limits>
#include <map>
#include <string>
#include <utility>

namespace mint {
namespace {

constexpr size_t kMaxBytes = 1024, kMaxInstructions = 1024, kMaxSource = 65536;
struct Number { bool negative = false; u64 magnitude = 0; };
struct Register { unsigned id = 0, width = 0; bool sp = false, zero = false; };
struct Instruction { std::string op; std::vector<std::string> args; size_t line = 1; };
struct Statement { std::vector<std::string> labels; Instruction instruction; bool hasInstruction = false; };
using Labels = std::map<std::string, Address>;

Status bad(const std::string& detail) { return Status::error(ErrorCode::kBadFormat, "assembler: " + detail); }
std::string trim(const std::string& text) {
    size_t start = 0, end = text.size();
    while (start < end && std::isspace(static_cast<unsigned char>(text[start]))) ++start;
    while (end > start && std::isspace(static_cast<unsigned char>(text[end - 1]))) --end;
    return text.substr(start, end - start);
}
std::string lower(std::string text) {
    for (char& c : text) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    return text;
}
bool identifier(const std::string& text) {
    if (text.empty() || text.size() > 128 || !((text[0] >= 'a' && text[0] <= 'z') || (text[0] >= 'A' && text[0] <= 'Z') || text[0] == '_')) return false;
    for (char c : text) if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_')) return false;
    return true;
}
bool number(std::string text, Number* out) {
    text = trim(text); if (!text.empty() && text[0] == '#') text = trim(text.substr(1));
    Number result;
    if (!text.empty() && (text[0] == '-' || text[0] == '+')) { result.negative = text[0] == '-'; text.erase(0, 1); }
    unsigned base = 10;
    if (text.size() >= 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) { base = 16; text.erase(0, 2); }
    if (text.empty()) return false;
    for (char c : text) {
        unsigned digit = c >= '0' && c <= '9' ? static_cast<unsigned>(c - '0') :
            c >= 'a' && c <= 'f' ? static_cast<unsigned>(c - 'a' + 10) :
            c >= 'A' && c <= 'F' ? static_cast<unsigned>(c - 'A' + 10) : 99;
        if (digit >= base || result.magnitude > (std::numeric_limits<u64>::max() - digit) / base) return false;
        result.magnitude = result.magnitude * base + digit;
    }
    if (!result.magnitude) result.negative = false;
    *out = result; return true;
}
bool unsignedValue(const std::string& text, u64 max, u64* out) {
    Number n; if (!number(text, &n) || n.negative || n.magnitude > max) return false;
    *out = n.magnitude; return true;
}
bool signedValue(const std::string& text, unsigned bits, i64* out) {
    Number n; if (!number(text, &n)) return false;
    const u64 limit = u64(1) << (bits - 1);
    if (n.magnitude > (n.negative ? limit : limit - 1)) return false;
    if (n.negative) *out = n.magnitude == (u64(1) << 63) ? std::numeric_limits<i64>::min() : -static_cast<i64>(n.magnitude);
    else *out = static_cast<i64>(n.magnitude);
    return true;
}
bool bitValue(const std::string& text, unsigned bits, u64* out) {
    Number n; if (!number(text, &n)) return false;
    if (n.negative) {
        if (n.magnitude > (u64(1) << (bits - 1))) return false;
        *out = u64(0) - n.magnitude;
    } else {
        if (bits < 64 && n.magnitude >= (u64(1) << bits)) return false;
        *out = n.magnitude;
    }
    if (bits < 64) *out &= (u64(1) << bits) - 1;
    return true;
}
bool displacement(Address pc, Address target, unsigned bits, unsigned alignment, i64* out) {
    if (target % alignment) return false;
    const u64 maxNegative = u64(1) << (bits - 1);
    if (target >= pc) {
        const u64 value = target - pc;
        if (value >= maxNegative || value % alignment) return false;
        *out = static_cast<i64>(value);
    } else {
        const u64 value = pc - target;
        if (value > maxNegative || value % alignment) return false;
        *out = -static_cast<i64>(value);
    }
    return true;
}
void emit(std::vector<u8>* bytes, u64 word, unsigned width) {
    for (unsigned i = 0; i < width; ++i) bytes->push_back(static_cast<u8>(word >> (i * 8)));
}
bool operands(const std::string& text, std::vector<std::string>* out) {
    if (trim(text).empty()) return true;
    int square = 0, paren = 0; size_t start = 0;
    for (size_t i = 0; i <= text.size(); ++i) {
        if (i < text.size()) {
            if (text[i] == '[') ++square; else if (text[i] == ']') --square;
            else if (text[i] == '(') ++paren; else if (text[i] == ')') --paren;
            if (square < 0 || paren < 0 || square > 1 || paren > 1) return false;
        }
        if (i == text.size() || (text[i] == ',' && !square && !paren)) {
            const std::string arg = trim(text.substr(start, i - start));
            if (arg.empty()) return false;
            out->push_back(arg); start = i + 1;
        }
    }
    return square == 0 && paren == 0 && out->size() <= kMaxInstructions;
}
Status parse(const std::string& source, std::vector<Statement>* statements) {
    if (source.size() > kMaxSource) return Status::error(ErrorCode::kTooLarge, "assembler source exceeds 64 KiB");
    std::string text; size_t line = 1, startLine = 1, instructionCount = 0, labelCount = 0;
    bool comment = false;
    auto finish = [&]() -> Status {
        std::string pending = trim(text); text.clear();
        if (pending.empty()) return Status::success();
        Statement statement; statement.instruction.line = startLine;
        while (true) {
            const auto colon = pending.find(':');
            if (colon == std::string::npos) break;
            const std::string label = trim(pending.substr(0, colon));
            if (!identifier(label)) return bad("invalid label on line " + std::to_string(startLine));
            if (++labelCount > kMaxInstructions) return Status::error(ErrorCode::kTooLarge, "assembler label limit");
            statement.labels.push_back(label); pending = trim(pending.substr(colon + 1));
        }
        if (!pending.empty()) {
            const auto split = pending.find_first_of(" \t\r");
            statement.instruction.op = lower(pending.substr(0, split));
            if (split != std::string::npos && !operands(pending.substr(split + 1), &statement.instruction.args)) return bad("invalid operands on line " + std::to_string(startLine));
            if (++instructionCount > kMaxInstructions) return Status::error(ErrorCode::kTooLarge, "assembler instruction limit");
            statement.hasInstruction = true;
        }
        statements->push_back(std::move(statement)); return Status::success();
    };
    for (size_t i = 0; i < source.size(); ++i) {
        const unsigned char c = static_cast<unsigned char>(source[i]);
        if ((c < 32 && c != '\n' && c != '\r' && c != '\t') || c >= 127) return bad("source must be ASCII without control characters");
        if (c == '\n' || (!comment && c == ';')) {
            Status status = finish(); if (!status.ok()) return status;
            if (c == '\n') { ++line; comment = false; }
            startLine = line; continue;
        }
        if (comment) continue;
        if (c == '/' && i + 1 < source.size() && source[i + 1] == '/') { comment = true; ++i; continue; }
        text.push_back(static_cast<char>(c));
    }
    Status status = finish(); if (!status.ok()) return status;
    if (!instructionCount) return bad("no instructions");
    return Status::success();
}
bool target(const std::string& text, Address pc, const Labels& labels, bool firstPass, Address* result) {
    const auto expression=trim(text);const auto operatorAt=expression.find_first_of("+-",1);
    if(operatorAt!=std::string::npos){Address base=0;u64 delta=0;if(!target(trim(expression.substr(0,operatorAt)),pc,labels,firstPass,&base)||!unsignedValue(expression.substr(operatorAt+1),kNoAddress-1,&delta))return false;if(expression[operatorAt]=='+'){if(base>kNoAddress-1-delta)return false;*result=base+delta;}else{if(base<delta)return false;*result=base-delta;}return true;}
    Number n;
    if (number(text, &n)) { if (n.negative || n.magnitude == kNoAddress) return false; *result = n.magnitude; return true; }
    const auto found = labels.find(text);
    if (found != labels.end()) { *result = found->second; return true; }
    if (firstPass && identifier(text)) { *result = pc; return true; }
    return false;
}
bool a64Reg(const std::string& text, Register* out) {
    const std::string name = lower(text); Register r;
    if (name == "sp" || name == "wsp") { r.id = 31; r.width = name == "sp" ? 64 : 32; r.sp = true; }
    else if (name == "xzr" || name == "wzr") { r.id = 31; r.width = name[0] == 'x' ? 64 : 32; r.zero = true; }
    else {
        u64 id = 0;
        if (name.size() < 2 || (name[0] != 'x' && name[0] != 'w') || !unsignedValue(name.substr(1), 30, &id)) return false;
        r.id = static_cast<unsigned>(id); r.width = name[0] == 'x' ? 64 : 32;
    }
    *out = r; return true;
}
bool armReg(const std::string& text, Register* out, bool pc = false) {
    const std::string name = lower(text); u64 id = 0;
    if (name == "sp") id = 13; else if (name == "lr") id = 14; else if (name == "pc") id = 15;
    else if (name.size() < 2 || name[0] != 'r' || !unsignedValue(name.substr(1), 15, &id)) return false;
    if (id == 15 && !pc) return false;
    *out = {static_cast<unsigned>(id), 32, id == 13, false}; return true;
}
bool x86Reg(const std::string& text, bool wide, Register* out) {
    const std::string name = lower(text);
    static const char* r64[] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"};
    static const char* r32[] = {"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"};
    for (unsigned i = 0; i < 8; ++i) {
        if (name == r32[i]) { *out = {i, 32, i == 4, false}; return true; }
        if (wide && name == r64[i]) { *out = {i, 64, i == 4, false}; return true; }
    }
    if (!wide || name.size() < 2 || name[0] != 'r') return false;
    const bool dword = name.back() == 'd';
    u64 id = 0;
    if (!unsignedValue(name.substr(1, name.size() - 1 - (dword ? 1 : 0)), 15, &id) || id < 8) return false;
    *out = {static_cast<unsigned>(id), dword ? 32u : 64u, false, false}; return true;
}
bool rvReg(const std::string& text, Register* out) {
    const std::string name = lower(text); u64 id = 0;
    static const char* abi[] = {"zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1", "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6"};
    for (unsigned i = 0; i < 32; ++i) if (name == abi[i] || (name == "fp" && i == 8)) { *out = {i, 0, i == 2, i == 0}; return true; }
    if (name.size() < 2 || name[0] != 'x' || !unsignedValue(name.substr(1), 31, &id)) return false;
    *out = {static_cast<unsigned>(id), 0, id == 2, id == 0}; return true;
}
int condition(const std::string& name) {
    static const char* names[] = {"eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "al"};
    if (name == "hs") return 2; if (name == "lo") return 3;
    for (int i = 0; i < 15; ++i) if (name == names[i]) return i;
    return -1;
}
bool squareAddress(const std::string& text, std::string* base, std::string* offset) {
    if (text.size() < 3 || text.front() != '[' || text.back() != ']') return false;
    std::vector<std::string> args;
    if (!operands(text.substr(1, text.size() - 2), &args) || args.empty() || args.size() > 2) return false;
    *base = args[0]; *offset = args.size() == 2 ? args[1] : "0"; return true;
}
bool rvAddress(const std::string& text, std::string* base, std::string* offset) {
    const auto paren = text.find('(');
    if (paren == std::string::npos || text.back() != ')') return false;
    *base = trim(text.substr(paren + 1, text.size() - paren - 2)); *offset = trim(text.substr(0, paren));
    if (offset->empty()) *offset = "0";
    return true;
}

Status a64(const Instruction& insn, Address pc, const Labels& labels, bool first, std::vector<u8>* out) {
    const auto& a = insn.args; const auto& op = insn.op;
    Register d, n, m; u64 immediate = 0; i64 relative = 0; Address destination = 0;
    auto word = [&](u32 value) { emit(out, value, 4); return Status::success(); };
    if (op == "nop" && a.empty()) return word(0xd503201f);
    if ((op == "ret" || op == "br" || op == "blr") && (a.size() == 1 || (op == "ret" && a.empty()))) {
        if (a.empty()) n = {30, 64, false, false};
        else if (!a64Reg(a[0], &n) || n.width != 64 || n.sp || n.zero) return bad("expected x0..x30 branch register");
        return word((op == "ret" ? 0xd65f0000u : op == "br" ? 0xd61f0000u : 0xd63f0000u) | (n.id << 5));
    }
    if ((op == "b" || op == "bl" || op.compare(0, 2, "b.") == 0) && a.size() == 1) {
        const int cc = op.compare(0, 2, "b.") == 0 ? condition(op.substr(2)) : -1;
        if ((op != "b" && op != "bl" && cc < 0) || !target(a[0], pc, labels, first, &destination) ||
            !displacement(pc, destination, cc >= 0 ? 21 : 28, 4, &relative)) return bad("AArch64 branch target/range/alignment");
        if (cc >= 0) return word(0x54000000u | ((static_cast<u32>(relative / 4) & 0x7ffff) << 5) | static_cast<u32>(cc));
        return word((op == "bl" ? 0x94000000u : 0x14000000u) | (static_cast<u32>(relative / 4) & 0x3ffffff));
    }
    if ((op == "cbz" || op == "cbnz") && a.size() == 2) {
        if (!a64Reg(a[0], &d) || d.sp || !target(a[1], pc, labels, first, &destination) || !displacement(pc, destination, 21, 4, &relative)) return bad("AArch64 compare-branch operands/range");
        return word((d.width == 64 ? 0xb4000000u : 0x34000000u) | (op == "cbnz" ? 0x1000000u : 0) | ((static_cast<u32>(relative / 4) & 0x7ffff) << 5) | d.id);
    }
    if((op=="tbz"||op=="tbnz")&&a.size()==3){u64 bit=0;if(!a64Reg(a[0],&d)||d.sp||!unsignedValue(a[1],d.width-1,&bit)||!target(a[2],pc,labels,first,&destination)||!displacement(pc,destination,16,4,&relative))return bad("test-bit branch register/bit/range");return word(0x36000000u|(op=="tbnz"?0x01000000u:0)|((static_cast<u32>(bit)&32)<<26)|((static_cast<u32>(bit)&31)<<19)|((static_cast<u32>(relative/4)&0x3fff)<<5)|d.id);}
    if((op=="adr"||op=="adrp")&&a.size()==2){if(!a64Reg(a[0],&d)||d.width!=64||d.sp||d.zero||!target(a[1],pc,labels,first,&destination))return bad("ADR destination/target");if(op=="adrp"){if(!displacement(pc&~Address(4095),destination&~Address(4095),33,4096,&relative))return bad("ADRP page displacement");relative/=4096;}else if(!displacement(pc,destination,21,1,&relative))return bad("ADR displacement");const u32 bits=static_cast<u32>(relative);return word((op=="adrp"?0x90000000u:0x10000000u)|((bits&3)<<29)|((bits>>2&0x7ffff)<<5)|d.id);}
    if((op=="and"||op=="orr"||op=="eor"||op=="ands"||op=="bic"||op=="orn"||op=="eon"||op=="bics")&&(a.size()==3||a.size()==4)){
        if(!a64Reg(a[0],&d)||!a64Reg(a[1],&n)||!a64Reg(a[2],&m)||d.sp||n.sp||m.sp||d.width!=n.width||d.width!=m.width)return bad("logical register widths/SP");unsigned shift=0;u64 amount=0;if(a.size()==4){const auto text=lower(a[3]);const auto split=text.find(' ');if(split==std::string::npos||!unsignedValue(text.substr(split+1),d.width-1,&amount))return bad("logical shift operand");const auto kind=text.substr(0,split);shift=kind=="lsl"?0:kind=="lsr"?1:kind=="asr"?2:kind=="ror"?3:4;if(shift==4)return bad("logical shift kind");}
        const bool inverted=op=="bic"||op=="orn"||op=="eon"||op=="bics";const unsigned operation=op=="orr"||op=="orn"?1:op=="eor"||op=="eon"?2:op=="ands"||op=="bics"?3:0;return word(0x0a000000u|(d.width==64?0x80000000u:0)|(operation<<29)|(shift<<22)|(inverted?1u<<21:0)|(m.id<<16)|(static_cast<u32>(amount)<<10)|(n.id<<5)|d.id);
    }
    if((op=="mul"||op=="mneg"||op=="madd"||op=="msub")&&a.size()==(op=="mul"||op=="mneg"?3u:4u)){Register accumulator;if(!a64Reg(a[0],&d)||!a64Reg(a[1],&n)||!a64Reg(a[2],&m)||d.sp||n.sp||m.sp||d.width!=n.width||d.width!=m.width)return bad("multiply register operands");accumulator={31,d.width,false,true};if(a.size()==4&&(!a64Reg(a[3],&accumulator)||accumulator.sp||accumulator.width!=d.width))return bad("multiply accumulator register");return word(0x1b000000u|(d.width==64?0x80000000u:0)|((op=="mneg"||op=="msub")?1u<<15:0)|(m.id<<16)|(accumulator.id<<10)|(n.id<<5)|d.id);}
    if((op=="stp"||op=="ldp")&&(a.size()==3||a.size()==4)){std::string memory=a[2],base,offset;unsigned mode=0;bool writeback=false;if(!memory.empty()&&memory.back()=='!'){memory.pop_back();mode=1;writeback=true;}if(a.size()==4){if(writeback)return bad("pair load/store cannot combine pre/post indexing");mode=2;writeback=true;}
        if(!a64Reg(a[0],&d)||!a64Reg(a[1],&n)||d.sp||n.sp||d.width!=n.width||!squareAddress(memory,&base,&offset)||!a64Reg(base,&m)||m.width!=64||m.zero)return bad("pair load/store register/address operands");if(a.size()==4){u64 zero=0;if(!unsignedValue(offset,0,&zero))return bad("post-index pair address must have zero inside offset");offset=a[3];}if(!signedValue(offset,10,&relative)||relative%static_cast<i64>(d.width/8)||relative/static_cast<i64>(d.width/8)<-64||relative/static_cast<i64>(d.width/8)>63)return bad("pair load/store signed scaled imm7");if(writeback&&!m.sp&&(m.id==d.id||m.id==n.id))return bad("pair writeback register overlaps data register");const u32 baseEncoding=mode==1?0x29800000u:mode==2?0x28800000u:0x29000000u;return word(baseEncoding|(d.width==64?0x80000000u:0)|(op=="ldp"?1u<<22:0)|((static_cast<u32>(relative/static_cast<i64>(d.width/8))&127)<<15)|(n.id<<10)|(m.id<<5)|d.id);}
    if ((op == "mov" || op == "movz" || op == "movn" || op == "movk") && a.size() >= 2 && a.size() <= 3) {
        if (!a64Reg(a[0], &d) || d.sp) {
            if (op != "mov" || a.size() != 2 || !a64Reg(a[0], &d)) return bad("move-wide destination register");
        }
        if (op == "mov" && a.size() == 2 && a64Reg(a[1], &n)) {
            if (d.width != n.width || ((d.sp || n.sp) && (d.zero || n.zero))) return bad("incompatible mov registers");
            if (d.sp || n.sp) return word((d.width == 64 ? 0x91000000u : 0x11000000u) | (n.id << 5) | d.id);
            return word((d.width == 64 ? 0xaa0003e0u : 0x2a0003e0u) | (n.id << 16) | d.id);
        }
        if (d.sp || d.zero) return bad("immediate move requires general-purpose destination");
        if (op != "mov") {
            u64 shift = 0;
            if (!unsignedValue(a[1], 65535, &immediate)) return bad("move-wide immediate must fit 16 bits");
            if (a.size() == 3) {
                const std::string sh = lower(a[2]);
                if (sh.compare(0, 4, "lsl ") != 0 || !unsignedValue(sh.substr(4), d.width - 16, &shift) || shift % 16) return bad("move-wide lsl must be a multiple of 16");
            }
            u32 encoding = op == "movz" ? 0x52800000u : op == "movn" ? 0x12800000u : 0x72800000u;
            if (d.width == 64) encoding |= 0x80000000u;
            return word(encoding | (static_cast<u32>(shift / 16) << 21) | (static_cast<u32>(immediate) << 5) | d.id);
        }
        if (a.size() != 2 || !bitValue(a[1], d.width, &immediate)) return bad("mov immediate width/range");
        const unsigned chunks = d.width / 16; unsigned zeros = 0, ones = 0;
        for (unsigned i = 0; i < chunks; ++i) { const u16 part = static_cast<u16>(immediate >> (i * 16)); zeros += part != 0; ones += part != 65535; }
        const bool invert = ones < zeros; const u16 fill = invert ? 65535 : 0; bool emitted = false;
        const bool uniform = (invert ? ones : zeros) == 0;
        for (unsigned i = 0; i < chunks; ++i) {
            const u16 part = static_cast<u16>(immediate >> (i * 16));
            if (part == fill && !(uniform && i == 0)) continue;
            u32 encoding = !emitted ? (invert ? 0x12800000u : 0x52800000u) : 0x72800000u;
            if (d.width == 64) encoding |= 0x80000000u;
            emit(out, encoding | (i << 21) | (static_cast<u32>(!emitted && invert ? static_cast<u16>(~part) : part) << 5) | d.id, 4);
            emitted = true;
        }
        return Status::success();
    }
    if (op == "add" || op == "sub" || op == "adds" || op == "subs" || op == "cmp") {
        const bool compare = op == "cmp", flags = compare || op == "adds" || op == "subs";
        const bool subtract = compare || op == "sub" || op == "subs";
        if (a.size() != (compare ? 2u : 3u) && a.size() != (compare ? 3u : 4u)) return bad("add/sub/cmp operand count");
        const size_t source = compare ? 0 : 1, rhs = compare ? 1 : 2;
        if (!a64Reg(a[source], &n)) return bad("arithmetic source register");
        if (compare) d = {31, n.width, false, true}; else if (!a64Reg(a[0], &d) || d.width != n.width) return bad("arithmetic register widths");
        if (a64Reg(a[rhs], &m)) {
            if (a.size() != rhs + 1 || d.sp || n.sp || m.sp || m.width != n.width) return bad("register arithmetic does not accept SP/shifts");
            return word((n.width == 64 ? 0x8b000000u : 0x0b000000u) | (subtract ? 0x40000000u : 0) | (flags ? 0x20000000u : 0) | (m.id << 16) | (n.id << 5) | d.id);
        }
        if (n.zero || (flags ? d.sp : d.zero) || !unsignedValue(a[rhs], 4095, &immediate)) return bad("immediate arithmetic registers/12-bit immediate");
        u32 shift = 0;
        if (a.size() == rhs + 2) { const std::string sh = lower(a.back()); if (sh != "lsl #12" && sh != "lsl 12") return bad("immediate arithmetic supports only lsl #12"); shift = 1u << 22; }
        return word((n.width == 64 ? 0x91000000u : 0x11000000u) | (subtract ? 0x40000000u : 0) | (flags ? 0x20000000u : 0) | shift | (static_cast<u32>(immediate) << 10) | (n.id << 5) | d.id);
    }
    if ((op == "ldr" || op == "str" || op == "ldrb" || op == "strb" || op == "ldrh" || op == "strh") && a.size() == 2) {
        std::string base, offset;
        if (!a64Reg(a[0], &d) || d.sp || !squareAddress(a[1], &base, &offset) || !a64Reg(base, &n) || n.width != 64 || n.zero) return bad("load/store register or [xN/sp,#offset]");
        const unsigned width = op.back() == 'b' ? 1 : op.back() == 'h' ? 2 : d.width / 8;
        if (width < 4 && d.width != 32) return bad("byte/halfword load/store requires w register");
        if (!unsignedValue(offset, 4095 * width, &immediate) || immediate % width) return bad("load/store unsigned scaled offset");
        const u32 encoding = width == 8 ? 0xf9000000u : width == 4 ? 0xb9000000u : width == 2 ? 0x79000000u : 0x39000000u;
        return word(encoding | (op.compare(0, 2, "ld") == 0 ? 0x400000u : 0) | (static_cast<u32>(immediate / width) << 10) | (n.id << 5) | d.id);
    }
    return bad("unsupported AArch64 mnemonic/operand form: " + op);
}

void rex(std::vector<u8>* out, unsigned width, unsigned reg, unsigned rm) {
    const u8 value = static_cast<u8>(0x40 | (width == 64 ? 8 : 0) | ((reg >> 3) << 2) | (rm >> 3));
    if (value != 0x40) emit(out, value, 1);
}
int x86Condition(const std::string& op) {
    static const std::pair<const char*, int> names[] = {
        {"jo",0},{"jno",1},{"jb",2},{"jc",2},{"jnae",2},{"jae",3},{"jnb",3},{"jnc",3},
        {"je",4},{"jz",4},{"jne",5},{"jnz",5},{"jbe",6},{"jna",6},{"ja",7},{"jnbe",7},
        {"js",8},{"jns",9},{"jp",10},{"jpe",10},{"jnp",11},{"jpo",11},
        {"jl",12},{"jnge",12},{"jge",13},{"jnl",13},{"jle",14},{"jng",14},{"jg",15},{"jnle",15}};
    for (const auto& name : names) if (op == name.first) return name.second;
    return -1;
}
struct X86Memory {int base=-1,index=-1;unsigned scale=1,width=0,addressWidth=0;i64 displacement=0;bool rip=false;std::string relative;};
bool x86Memory(std::string text,bool wide,X86Memory* output){
    text=trim(text);X86Memory memory;memory.addressWidth=wide?64:32;
    for(const auto& prefix:{std::pair<const char*,unsigned>{"byte",8},{"word",16},{"dword",32},{"qword",64}})if(lower(text).compare(0,std::strlen(prefix.first),prefix.first)==0){memory.width=prefix.second;text=trim(text.substr(std::strlen(prefix.first)));if(lower(text).compare(0,3,"ptr")==0)text=trim(text.substr(3));break;}
    if(text.size()<3||text.front()!='['||text.back()!=']')return false;text=text.substr(1,text.size()-2);text.erase(std::remove_if(text.begin(),text.end(),[](unsigned char c){return std::isspace(c);}),text.end());
    if(lower(text).compare(0,3,"rel")==0){if(!wide||!identifier(text.substr(3)))return false;memory.rip=true;memory.relative=text.substr(3);*output=memory;return true;}
    size_t at=0;bool hasTerm=false,negative=false,hasAddressWidth=false;
    while(at<text.size()){
        if(text[at]=='+'||text[at]=='-'){negative=text[at++]=='-';if(at==text.size())return false;}else if(hasTerm)return false;
        const auto finish=text.find_first_of("+-",at);const auto token=text.substr(at,finish==std::string::npos?std::string::npos:finish-at);if(token.empty())return false;hasTerm=true;Register reg;const auto star=token.find('*');
        if(lower(token)=="rip"){if(!wide||negative||memory.rip||memory.base!=-1||memory.index!=-1)return false;memory.rip=true;}
        else if(x86Reg(star==std::string::npos?token:token.substr(0,star),wide,&reg)){
            if(negative||memory.rip||reg.width!=(wide?64u:32u))return false;hasAddressWidth=true;
            if(star!=std::string::npos){u64 scale=0;if(memory.index!=-1||!unsignedValue(token.substr(star+1),8,&scale)||(scale!=1&&scale!=2&&scale!=4&&scale!=8)||reg.id==4)return false;memory.index=static_cast<int>(reg.id);memory.scale=static_cast<unsigned>(scale);}
            else if(memory.base==-1)memory.base=static_cast<int>(reg.id);else if(memory.index==-1&&reg.id!=4)memory.index=static_cast<int>(reg.id);else return false;
        }else {i64 value=0;if(!signedValue((negative?"-":"")+token,32,&value)){if(memory.rip&&identifier(token)&&!negative&&memory.relative.empty())memory.relative=token;else return false;}else {if((value>0&&memory.displacement>std::numeric_limits<i32>::max()-value)||(value<0&&memory.displacement<std::numeric_limits<i32>::min()-value))return false;memory.displacement+=value;}}
        negative=false;if(finish==std::string::npos)break;at=finish;
    }if(!hasTerm||(!memory.relative.empty()&&memory.displacement))return false;(void)hasAddressWidth;*output=memory;return true;
}
Status x86MemoryEncoding(const X86Memory& memory,unsigned reg,unsigned width,u8 opcode,Address pc,const Labels& labels,bool first,const std::vector<u8>& immediate,std::vector<u8>* out){
    std::vector<u8> bytes;if(width==16)emit(&bytes,0x66,1);
    u8 prefix=0x40|(width==64?8:0)|((reg>>3)<<2)|(memory.index>=8?2:0)|(memory.base>=8?1:0);if(prefix!=0x40)emit(&bytes,prefix,1);emit(&bytes,opcode,1);
    i64 displacementValue=memory.displacement;const bool noBase=memory.base<0,hasSib=!memory.rip&&(memory.index>=0||(memory.base>=0&&(memory.base&7)==4)||noBase);
    unsigned mode=0,dispBytes=0;if(memory.rip||noBase)dispBytes=4;else if(displacementValue||((memory.base&7)==5)){mode=displacementValue>=-128&&displacementValue<=127?1:2;dispBytes=mode==1?1:4;}
    emit(&bytes,(mode<<6)|((reg&7)<<3)|(memory.rip?5:hasSib?4:static_cast<unsigned>(memory.base)&7),1);
    if(hasSib){unsigned scale=memory.scale==8?3:memory.scale==4?2:memory.scale==2?1:0;emit(&bytes,(scale<<6)|((memory.index<0?4:unsigned(memory.index)&7)<<3)|(noBase?5:unsigned(memory.base)&7),1);}
    if(!memory.relative.empty()){Address destination=0;if(!target(memory.relative,pc,labels,first,&destination)||pc>kNoAddress-bytes.size()-dispBytes-immediate.size()||!displacement(pc+bytes.size()+dispBytes+immediate.size(),destination,32,1,&displacementValue))return bad("RIP-relative target exceeds signed displacement range");}
    emit(&bytes,static_cast<u64>(displacementValue),dispBytes);bytes.insert(bytes.end(),immediate.begin(),immediate.end());out->insert(out->end(),bytes.begin(),bytes.end());return Status::success();
}
Status x86Encode(const Instruction& insn, Address pc, const Labels& labels, bool first, bool wide, std::vector<u8>* out) {
    const auto& a = insn.args; const auto& op = insn.op;
    Register d, n; u64 immediate = 0; i64 signedImmediate = 0;
    X86Memory memory;
    if(a.size()==2){const bool destinationMemory=x86Memory(a[0],wide,&memory),sourceMemory=!destinationMemory&&x86Memory(a[1],wide,&memory);
        if(destinationMemory||sourceMemory){const auto& other=destinationMemory?a[1]:a[0];const bool reg=x86Reg(other,wide,&d);const unsigned width=memory.width?memory.width:reg?d.width:0;if(!width||(width!=32&&width!=64)||(!wide&&width==64)||(reg&&d.width!=width))return bad("x86 memory requires a matching 32/64-bit register or explicit dword/qword width");
            unsigned opcode=0,group=0;bool alu=true;if(op=="add"){opcode=0x01;group=0;}else if(op=="or"){opcode=0x09;group=1;}else if(op=="adc"){opcode=0x11;group=2;}else if(op=="sbb"){opcode=0x19;group=3;}else if(op=="and"){opcode=0x21;group=4;}else if(op=="sub"){opcode=0x29;group=5;}else if(op=="xor"){opcode=0x31;group=6;}else if(op=="cmp"){opcode=0x39;group=7;}else if(op=="test")opcode=0x85;else alu=false;
            if(reg){if(op=="mov")opcode=destinationMemory?0x89:0x8b;else if(op=="lea"&&!destinationMemory)opcode=0x8d;else if(!alu)return bad("unsupported x86 memory operation");else if(sourceMemory&&op!="test")opcode+=2;return x86MemoryEncoding(memory,d.id,width,static_cast<u8>(opcode),pc,labels,first,{},out);}
            if(!destinationMemory||(op!="mov"&&!alu))return bad("x86 memory source needs a register destination");if((width==64&&!signedValue(other,32,&signedImmediate))||(width==32&&!bitValue(other,32,&immediate)))return bad("memory immediate cannot be represented without truncation");if(width==64)immediate=static_cast<u32>(signedImmediate);const bool small=op!="mov"&&op!="test"&&signedValue(other,8,&signedImmediate);std::vector<u8> encoded;emit(&encoded,small?static_cast<u8>(signedImmediate):immediate,small?1:4);return x86MemoryEncoding(memory,op=="mov"||op=="test"?0:group,width,op=="mov"?0xc7:op=="test"?0xf7:small?0x83:0x81,pc,labels,first,encoded,out);
        }
    }
    if (a.empty()) {
        if (op == "nop") { emit(out, 0x90, 1); return Status::success(); }
        if (op == "ret") { emit(out, 0xc3, 1); return Status::success(); }
        if (op == "int3") { emit(out, 0xcc, 1); return Status::success(); }
        if (op == "ud2") { emit(out, 0x0b0f, 2); return Status::success(); }
        if (op == "leave") { emit(out, 0xc9, 1); return Status::success(); }
    }
    if (op == "ret" && a.size() == 1 && unsignedValue(a[0], 65535, &immediate)) { emit(out, 0xc2, 1); emit(out, immediate, 2); return Status::success(); }
    if ((op == "push" || op == "pop") && a.size() == 1) {
        if (!x86Reg(a[0], wide, &d) || d.width != (wide ? 64u : 32u)) return bad("push/pop requires native-width register");
        rex(out, 32, 0, d.id); emit(out, (op == "push" ? 0x50u : 0x58u) + (d.id & 7), 1); return Status::success();
    }
    const int cc = x86Condition(op);
    if ((op == "jmp" || op == "call" || cc >= 0) && a.size() == 1) {
        if (cc < 0 && x86Reg(a[0], wide, &d)) {
            if (d.width != (wide ? 64u : 32u)) return bad("indirect branch requires native-width register");
            rex(out, 32, 0, d.id); emit(out, 0xff, 1); emit(out, 0xc0 | ((op == "call" ? 2u : 4u) << 3) | (d.id & 7), 1); return Status::success();
        }
        const unsigned size = cc >= 0 ? 6 : 5;
        Address destination = 0; i64 relative = 0;
        if (pc > std::numeric_limits<Address>::max() - size || !target(a[0], pc + size, labels, first, &destination) ||
            (!wide && destination > 0xffffffffu) || !displacement(pc + size, destination, 32, 1, &relative)) return bad("x86 near branch target exceeds rel32/address range");
        if (cc >= 0) { emit(out, 0x0f, 1); emit(out, 0x80u + static_cast<unsigned>(cc), 1); }
        else emit(out, op == "call" ? 0xe8 : 0xe9, 1);
        emit(out, static_cast<u32>(relative), 4); return Status::success();
    }
    if ((op == "inc" || op == "dec") && a.size() == 1 && x86Reg(a[0], wide, &d)) {
        rex(out, d.width, 0, d.id); emit(out, 0xff, 1); emit(out, 0xc0 | (op == "dec" ? 8 : 0) | (d.id & 7), 1); return Status::success();
    }
    if (a.size() == 2 && x86Reg(a[0], wide, &d)) {
        const bool registerSource = x86Reg(a[1], wide, &n);
        if (op == "mov") {
            if (registerSource) {
                if (d.width != n.width) return bad("mov register widths differ");
                rex(out, d.width, n.id, d.id); emit(out, 0x89, 1); emit(out, 0xc0 | ((n.id & 7) << 3) | (d.id & 7), 1); return Status::success();
            }
            if (!bitValue(a[1], d.width, &immediate)) return bad("mov immediate exceeds register width");
            if (d.width == 64 && signedValue(a[1], 32, &signedImmediate)) {
                rex(out, 64, 0, d.id); emit(out, 0xc7, 1); emit(out, 0xc0 | (d.id & 7), 1); emit(out, static_cast<u32>(signedImmediate), 4);
            } else {
                rex(out, d.width, 0, d.id); emit(out, 0xb8 + (d.id & 7), 1); emit(out, immediate, d.width / 8);
            }
            return Status::success();
        }
        unsigned opcode = 0, group = 0; bool arithmetic = true;
        if (op == "add") { opcode = 0x01; group = 0; }
        else if (op == "or") { opcode = 0x09; group = 1; }
        else if (op == "adc") { opcode = 0x11; group = 2; }
        else if (op == "sbb") { opcode = 0x19; group = 3; }
        else if (op == "and") { opcode = 0x21; group = 4; }
        else if (op == "sub") { opcode = 0x29; group = 5; }
        else if (op == "xor") { opcode = 0x31; group = 6; }
        else if (op == "cmp") { opcode = 0x39; group = 7; }
        else if (op == "test") opcode = 0x85;
        else arithmetic = false;
        if (arithmetic && registerSource) {
            if (d.width != n.width) return bad("ALU register widths differ");
            rex(out, d.width, n.id, d.id); emit(out, opcode, 1); emit(out, 0xc0 | ((n.id & 7) << 3) | (d.id & 7), 1); return Status::success();
        }
        if (arithmetic) {
            if ((d.width == 64 && !signedValue(a[1], 32, &signedImmediate)) ||
                (d.width == 32 && !bitValue(a[1], 32, &immediate))) return bad("ALU immediate cannot be represented without truncation/sign change");
            if (d.width == 64) immediate = static_cast<u32>(signedImmediate);
            const bool small = op != "test" && signedValue(a[1], 8, &signedImmediate);
            rex(out, d.width, 0, d.id); emit(out, op == "test" ? 0xf7 : small ? 0x83 : 0x81, 1);
            emit(out, 0xc0 | ((op == "test" ? 0 : group) << 3) | (d.id & 7), 1);
            emit(out, small ? static_cast<u8>(signedImmediate) : immediate, small ? 1 : 4); return Status::success();
        }
    }
    return bad("unsupported x86 mnemonic/operand form: " + op);
}

bool armImmediate(u32 value, u32* encoded) {
    for (unsigned rotation = 0; rotation < 16; ++rotation) {
        const unsigned shift = rotation * 2;
        const u32 candidate = shift ? (value << shift) | (value >> (32 - shift)) : value;
        if (candidate <= 255) { *encoded = (rotation << 8) | candidate; return true; }
    }
    return false;
}
Status armEncode(const Instruction& insn, Address pc, const Labels& labels, bool first, std::vector<u8>* out) {
    const auto& a = insn.args;std::string op=insn.op;int predicate=14;const auto dot=op.find('.');
    if(dot!=std::string::npos&&op[0]!='b'){predicate=condition(op.substr(dot+1));if(predicate<0)return bad("invalid ARM predicate suffix");op=op.substr(0,dot);}
    bool flags=false;if(op=="adds"||op=="subs"||op=="ands"||op=="orrs"||op=="eors"||op=="movs"||op=="mvns"){flags=true;op.pop_back();}
    Register d, n, m; u64 immediate = 0; u32 operand = 0;
    auto word = [&](u32 value) {if(predicate!=14)value=(value&0x0fffffffu)|(static_cast<u32>(predicate)<<28);emit(out, value, 4); return Status::success(); };
    if (op == "nop" && a.empty()) return word(0xe320f000);
    if (op == "ret" && a.empty()) return word(0xe12fff1e);
    if ((op == "bx" || op == "blx") && a.size() == 1 && armReg(a[0], &n)) return word((op == "bx" ? 0xe12fff10u : 0xe12fff30u) | n.id);
    int cc = -1;
    if (op.compare(0, 2, "b.") == 0) cc = condition(op.substr(2));
    else if (op.size() == 3 && op[0] == 'b') cc = condition(op.substr(1));
    if ((op == "b" || op == "bl" || cc >= 0) && a.size() == 1) {
        Address destination = 0; i64 relative = 0;
        if (pc > 0xfffffff7u || !target(a[0], pc + 8, labels, first, &destination) || destination > 0xffffffffu || !displacement(pc + 8, destination, 26, 4, &relative)) return bad("ARM branch address/range/alignment");
        return word((static_cast<u32>(cc >= 0 ? cc : 14) << 28) | (op == "bl" ? 0x0b000000u : 0x0a000000u) | (static_cast<u32>(relative / 4) & 0xffffff));
    }
    if ((op == "mov" || op == "mvn" || op == "movw" || op == "movt") && a.size() == 2 && armReg(a[0], &d)) {
        if (op == "mov" && armReg(a[1], &m)) return word(0xe1a00000u | (flags?1u<<20:0) | (d.id << 12) | m.id);
        if (op == "movw" || op == "movt") {
            if (!unsignedValue(a[1], 65535, &immediate)) return bad("ARM movw/movt immediate exceeds 16 bits");
            return word((op == "movw" ? 0xe3000000u : 0xe3400000u) | ((static_cast<u32>(immediate) & 0xf000) << 4) | (d.id << 12) | (static_cast<u32>(immediate) & 0xfff));
        }
        if (!bitValue(a[1], 32, &immediate)) return bad("ARM move immediate exceeds 32 bits");
        if (armImmediate(static_cast<u32>(immediate), &operand)) return word((op == "mvn" ? 0xe3e00000u : 0xe3a00000u) | (flags?1u<<20:0) | (d.id << 12) | operand);
        if (op == "mvn") return bad("ARM mvn immediate is not rotated-8-bit encodable");
        if(flags)return bad("flag-setting mov immediate cannot expand without changing flag semantics");
        word(0xe3000000u | ((static_cast<u32>(immediate) & 0xf000) << 4) | (d.id << 12) | (static_cast<u32>(immediate) & 0xfff));
        if (immediate >> 16) word(0xe3400000u | ((static_cast<u32>(immediate >> 16) & 0xf000) << 4) | (d.id << 12) | (static_cast<u32>(immediate >> 16) & 0xfff));
        return Status::success();
    }
    if ((op == "add" || op == "sub" || op == "and"||op=="orr"||op=="eor"||op == "cmp") && a.size() == (op == "cmp" ? 2u : 3u)) {
        const bool compare = op == "cmp"; const size_t source = compare ? 0 : 1, rhs = compare ? 1 : 2;
        if (!armReg(a[source], &n) || (!compare && !armReg(a[0], &d))) return bad("ARM arithmetic register");
        u32 encoding = compare ? 0xe1500000u : op == "sub" ? 0xe0400000u :op=="and"?0xe0000000u:op=="orr"?0xe1800000u:op=="eor"?0xe0200000u:0xe0800000u;if(flags)encoding|=1u<<20;
        if (armReg(a[rhs], &m)) operand = m.id;
        else {
            if (!bitValue(a[rhs], 32, &immediate) || !armImmediate(static_cast<u32>(immediate), &operand)) return bad("ARM arithmetic immediate is not rotated-8-bit encodable");
            encoding |= 1u << 25;
        }
        return word(encoding | (n.id << 16) | (compare ? 0 : d.id << 12) | operand);
    }
    if ((op == "ldr" || op == "str") && a.size() == 2) {
        std::string base, offset; i64 displacementValue = 0;
        if (!armReg(a[0], &d) || !squareAddress(a[1], &base, &offset) || !armReg(base, &n, true) || !signedValue(offset, 13, &displacementValue) || displacementValue < -4095 || displacementValue > 4095) return bad("ARM load/store [rN,#signed imm12]");
        return word((op == "ldr" ? 0xe5100000u : 0xe5000000u) | (displacementValue >= 0 ? 0x800000u : 0) | (n.id << 16) | (d.id << 12) | static_cast<u32>(displacementValue < 0 ? -displacementValue : displacementValue));
    }
    return bad("unsupported ARM mnemonic/operand form: " + op);
}

void thumbWideMove(std::vector<u8>* out, unsigned reg, u16 immediate, bool top) {
    emit(out, (top ? 0xf2c0u : 0xf240u) | ((immediate >> 12) & 15) | (((immediate >> 11) & 1) << 10), 2);
    emit(out, (((immediate >> 8) & 7) << 12) | (reg << 8) | (immediate & 255), 2);
}
Status thumbEncode(const Instruction& insn, Address pc, const Labels& labels, bool first, std::vector<u8>* out) {
    const auto& a = insn.args; const auto& op = insn.op;
    Register d, n, m; u64 immediate = 0;
    auto half = [&](u16 value) { emit(out, value, 2); return Status::success(); };
    if (op == "nop" && a.empty()) return half(0xbf00);
    if (op == "ret" && a.empty()) return half(0x4770);
    if ((op == "bx" || op == "blx") && a.size() == 1 && armReg(a[0], &n)) return half(static_cast<u16>((op == "bx" ? 0x4700 : 0x4780) | (n.id << 3)));
    int cc = -1;
    if (op.compare(0, 2, "b.") == 0) cc = condition(op.substr(2));
    else if (op.size() == 3 && op[0] == 'b') cc = condition(op.substr(1));
    if ((op == "b" || op == "bl" || cc >= 0) && a.size() == 1) {
        Address destination = 0; i64 relative = 0;
        if (pc > 0xfffffffbu || !target(a[0], pc + 4, labels, first, &destination) || destination > 0xffffffffu ||
            !displacement(pc + 4, destination, op == "bl" ? 25 : cc >= 0 ? 9 : 12, 2, &relative) || cc == 14) return bad("Thumb branch target/range/alignment");
        if (op == "bl") {
            const u32 bits = static_cast<u32>(relative);
            const u32 s = (bits >> 24) & 1, i1 = (bits >> 23) & 1, i2 = (bits >> 22) & 1;
            const u32 j1 = !(i1 ^ s), j2 = !(i2 ^ s);
            emit(out, 0xf000u | (s << 10) | ((bits >> 12) & 0x3ff), 2);
            emit(out, 0xd000u | (j1 << 13) | (j2 << 11) | ((bits >> 1) & 0x7ff), 2);
            return Status::success();
        }
        if (cc >= 0) return half(static_cast<u16>(0xd000 | (cc << 8) | (static_cast<u32>(relative / 2) & 255)));
        return half(static_cast<u16>(0xe000 | (static_cast<u32>(relative / 2) & 0x7ff)));
    }
    if ((op == "mov" || op == "movs" || op == "movw" || op == "movt") && a.size() == 2 && armReg(a[0], &d)) {
        if (op == "mov" && armReg(a[1], &n)) return half(static_cast<u16>(0x4600 | ((d.id & 8) << 4) | (n.id << 3) | (d.id & 7)));
        if (op == "movs") {
            if (d.id > 7 || !unsignedValue(a[1], 255, &immediate)) return bad("Thumb movs requires low register and imm8");
            return half(static_cast<u16>(0x2000 | (d.id << 8) | immediate));
        }
        if (d.id >= 13) return bad("Thumb move-wide destination must be r0..r12");
        if (op == "movw" || op == "movt") {
            if (!unsignedValue(a[1], 65535, &immediate)) return bad("Thumb movw/movt immediate exceeds 16 bits");
            thumbWideMove(out, d.id, static_cast<u16>(immediate), op == "movt"); return Status::success();
        }
        if (!bitValue(a[1], 32, &immediate)) return bad("Thumb mov immediate exceeds 32 bits");
        thumbWideMove(out, d.id, static_cast<u16>(immediate), false);
        if (immediate >> 16) thumbWideMove(out, d.id, static_cast<u16>(immediate >> 16), true);
        return Status::success();
    }
    if ((op == "add" || op == "sub") && a.size() == 2 && armReg(a[0], &d)) {
        if (d.id == 13 && unsignedValue(a[1], 508, &immediate) && immediate % 4 == 0) return half(static_cast<u16>(0xb000 | (op == "sub" ? 0x80 : 0) | (immediate / 4)));
        if (op == "add" && armReg(a[1], &m)) return half(static_cast<u16>(0x4400 | ((d.id & 8) << 4) | (m.id << 3) | (d.id & 7)));
        return bad("Thumb non-flag add/sub supports add Rd,Rm or add/sub sp,#multiple-of-4");
    }
    if ((op == "adds" || op == "subs") && a.size() >= 2 && a.size() <= 3) {
        if (!armReg(a[0], &d) || d.id > 7) return bad("Thumb adds/subs requires low registers");
        if (a.size() == 2) {
            if (!unsignedValue(a[1], 255, &immediate)) return bad("Thumb adds/subs two-operand imm8");
            return half(static_cast<u16>((op == "subs" ? 0x3800 : 0x3000) | (d.id << 8) | immediate));
        }
        if (!armReg(a[1], &n) || n.id > 7) return bad("Thumb adds/subs source low register");
        if (armReg(a[2], &m) && m.id <= 7) return half(static_cast<u16>((op == "subs" ? 0x1a00 : 0x1800) | (m.id << 6) | (n.id << 3) | d.id));
        if (!unsignedValue(a[2], 7, &immediate)) return bad("Thumb adds/subs three-operand imm3");
        return half(static_cast<u16>((op == "subs" ? 0x1e00 : 0x1c00) | (immediate << 6) | (n.id << 3) | d.id));
    }
    if (op == "cmp" && a.size() == 2 && armReg(a[0], &n)) {
        if (armReg(a[1], &m)) return half(static_cast<u16>((n.id <= 7 && m.id <= 7 ? 0x4280 : 0x4500) | ((n.id & 8) << 4) | (m.id << 3) | (n.id & 7)));
        if (n.id <= 7 && unsignedValue(a[1], 255, &immediate)) return half(static_cast<u16>(0x2800 | (n.id << 8) | immediate));
        return bad("Thumb cmp immediate requires low register and imm8");
    }
    if ((op == "ldr" || op == "str") && a.size() == 2) {
        std::string base, offset;
        if (!armReg(a[0], &d) || d.id > 7 || !squareAddress(a[1], &base, &offset) || !armReg(base, &n) || !unsignedValue(offset, n.id == 13 ? 1020 : 124, &immediate) || immediate % 4) return bad("Thumb word load/store requires low register and aligned positive offset");
        if (n.id == 13) return half(static_cast<u16>((op == "ldr" ? 0x9800 : 0x9000) | (d.id << 8) | (immediate / 4)));
        if (n.id > 7) return bad("Thumb load/store base requires r0..r7/sp");
        return half(static_cast<u16>((op == "ldr" ? 0x6800 : 0x6000) | ((immediate / 4) << 6) | (n.id << 3) | d.id));
    }
    return bad("unsupported Thumb mnemonic/operand form: " + op);
}

u32 rvI(unsigned rd, unsigned rs, i64 immediate, unsigned funct3 = 0, unsigned opcode = 0x13) {
    return (static_cast<u32>(immediate) & 0xfff) << 20 | (rs << 15) | (funct3 << 12) | (rd << 7) | opcode;
}
void rvLi(std::vector<u8>* out, unsigned rd, i64 value) {
    if (value >= -2048 && value <= 2047) { emit(out, rvI(rd, 0, value), 4); return; }
    // Signed division avoids overflow in rounding INT64_MAX up by 0x800.
    i64 upper = value / 4096, low = value % 4096;
    if (low > 2047) { low -= 4096; ++upper; }
    else if (low < -2048) { low += 4096; --upper; }
    rvLi(out, rd, upper);
    emit(out, rvI(rd, rd, 12, 1), 4);
    if (low) emit(out, rvI(rd, rd, low), 4);
}
Status rvEncode(const Instruction& insn, Address pc, const Labels& labels, bool first, bool wide, std::vector<u8>* out) {
    const auto& a = insn.args; const auto& op = insn.op;
    Register d, n, m; i64 immediate = 0; u64 bits = 0;
    auto word = [&](u32 value) { emit(out, value, 4); return Status::success(); };
    auto half=[&](u16 value){emit(out,value,2);return Status::success();};
    if(op=="c.nop"&&a.empty())return half(0x0001);
    if(op=="c.ebreak"&&a.empty())return half(0x9002);
    if((op=="c.li"||op=="c.addi"||(wide&&op=="c.addiw"))&&a.size()==2&&rvReg(a[0],&d)&&d.id&&signedValue(a[1],6,&immediate))return half(static_cast<u16>((op=="c.li"?0x4001:op=="c.addiw"?0x2001:0x0001)|((static_cast<u32>(immediate)>>5&1)<<12)|(d.id<<7)|((static_cast<u32>(immediate)&31)<<2)));
    if((op=="c.mv"||op=="c.add")&&a.size()==2&&rvReg(a[0],&d)&&rvReg(a[1],&n)&&d.id&&n.id)return half(static_cast<u16>((op=="c.mv"?0x8002:0x9002)|(d.id<<7)|(n.id<<2)));
    if((op=="c.jr"||op=="c.jalr")&&a.size()==1&&rvReg(a[0],&n)&&n.id)return half(static_cast<u16>((op=="c.jr"?0x8002:0x9002)|(n.id<<7)));
    if((op=="c.j"||(!wide&&op=="c.jal"))&&a.size()==1){Address destination=0;if(!target(a[0],pc,labels,first,&destination)||(!wide&&destination>0xffffffffu)||!displacement(pc,destination,12,2,&immediate))return bad("compressed jump target/range");const u32 v=static_cast<u32>(immediate);return half(static_cast<u16>((op=="c.j"?0xa001:0x2001)|((v>>11&1)<<12)|((v>>4&1)<<11)|((v>>8&3)<<9)|((v>>10&1)<<8)|((v>>6&1)<<7)|((v>>7&1)<<6)|((v>>1&7)<<3)|((v>>5&1)<<2)));}
    if((op=="c.beqz"||op=="c.bnez")&&a.size()==2&&rvReg(a[0],&n)&&n.id>=8&&n.id<=15){Address destination=0;if(!target(a[1],pc,labels,first,&destination)||(!wide&&destination>0xffffffffu)||!displacement(pc,destination,9,2,&immediate))return bad("compressed branch target/range");const u32 v=static_cast<u32>(immediate);return half(static_cast<u16>((op=="c.beqz"?0xc001:0xe001)|((v>>8&1)<<12)|((v>>3&3)<<10)|((n.id-8)<<7)|((v>>6&3)<<5)|((v>>1&3)<<3)|((v>>5&1)<<2)));}
    if((op=="c.lw"||op=="c.sw"||(wide&&(op=="c.ld"||op=="c.sd")))&&a.size()==2&&rvReg(a[0],&d)&&d.id>=8&&d.id<=15){std::string base,offset;u64 displacementValue=0;const bool doubleword=op=="c.ld"||op=="c.sd";if(!rvAddress(a[1],&base,&offset)||!rvReg(base,&n)||n.id<8||n.id>15||!unsignedValue(offset,doubleword?248:124,&displacementValue)||displacementValue%(doubleword?8:4))return bad("compressed memory needs x8..x15 and aligned unsigned offset");u16 encoded=static_cast<u16>((op=="c.lw"?0x4000:op=="c.sw"?0xc000:op=="c.ld"?0x6000:0xe000)|((displacementValue>>3&7)<<10)|((n.id-8)<<7)|((d.id-8)<<2));encoded|=doubleword?static_cast<u16>((displacementValue>>6&3)<<5):static_cast<u16>(((displacementValue>>2&1)<<6)|((displacementValue>>6&1)<<5));return half(encoded);}
    if (a.empty()) {
        if (op == "nop") return word(0x13);
        if (op == "ret") return word(0x8067);
        if (op == "ecall") return word(0x73);
        if (op == "ebreak") return word(0x100073);
    }
    if (op == "li" && a.size() == 2 && rvReg(a[0], &d)) {
        if (!bitValue(a[1], wide ? 64 : 32, &bits)) return bad("RISC-V li immediate exceeds XLEN");
        if (wide) immediate = bits <= static_cast<u64>(std::numeric_limits<i64>::max()) ? static_cast<i64>(bits) : -1 - static_cast<i64>(~bits);
        else immediate = bits & 0x80000000u ? static_cast<i64>(bits) - 0x100000000LL : static_cast<i64>(bits);
        rvLi(out, d.id, immediate); return Status::success();
    }
    if (op == "mv" && a.size() == 2 && rvReg(a[0], &d) && rvReg(a[1], &n)) return word(rvI(d.id, n.id, 0));
    if ((op == "j" || op == "call" || op == "jal") && (a.size() == 1 || (op == "jal" && a.size() == 2))) {
        d.id = op == "j" ? 0 : 1;
        if (a.size() == 2 && !rvReg(a[0], &d)) return bad("RISC-V jal destination register");
        Address destination = 0;
        if (!target(a.back(), pc, labels, first, &destination) || (!wide && destination > 0xffffffffu) || !displacement(pc, destination, 21, 2, &immediate)) return bad("RISC-V jal target exceeds aligned signed-21-bit range");
        const u32 value = static_cast<u32>(immediate);
        return word(((value >> 20) & 1) << 31 | ((value >> 1) & 0x3ff) << 21 | ((value >> 11) & 1) << 20 | ((value >> 12) & 255) << 12 | (d.id << 7) | 0x6f);
    }
    if (op == "jalr" && a.size() == 3 && rvReg(a[0], &d) && rvReg(a[1], &n) && signedValue(a[2], 12, &immediate)) return word(rvI(d.id, n.id, immediate, 0, 0x67));
    if (op == "jr" && a.size() == 1 && rvReg(a[0], &n)) return word(rvI(0, n.id, 0, 0, 0x67));
    const bool zeroBranch = op == "beqz" || op == "bnez";
    const bool branch = zeroBranch || op == "beq" || op == "bne" || op == "blt" || op == "bge" || op == "bltu" || op == "bgeu";
    if (branch && a.size() == (zeroBranch ? 2u : 3u)) {
        if (!rvReg(a[0], &n) || (!zeroBranch && !rvReg(a[1], &m))) return bad("RISC-V branch registers");
        if (zeroBranch) m.id = 0;
        Address destination = 0;
        if (!target(a.back(), pc, labels, first, &destination) || (!wide && destination > 0xffffffffu) || !displacement(pc, destination, 13, 2, &immediate)) return bad("RISC-V branch target exceeds aligned signed-13-bit range");
        const unsigned funct3 = op == "beq" || op == "beqz" ? 0 : op == "bne" || op == "bnez" ? 1 : op == "blt" ? 4 : op == "bge" ? 5 : op == "bltu" ? 6 : 7;
        const u32 value = static_cast<u32>(immediate);
        return word(((value >> 12) & 1) << 31 | ((value >> 5) & 63) << 25 | (m.id << 20) | (n.id << 15) | (funct3 << 12) | ((value >> 1) & 15) << 8 | ((value >> 11) & 1) << 7 | 0x63);
    }
    if ((op == "lui" || op == "auipc") && a.size() == 2 && rvReg(a[0], &d) && bitValue(a[1], 20, &bits)) return word((static_cast<u32>(bits) << 12) | (d.id << 7) | (op == "lui" ? 0x37 : 0x17));
    if (a.size() == 3 && rvReg(a[0], &d) && rvReg(a[1], &n)) {
        unsigned funct3 = 0, funct7 = 0; bool reg = true;
        if (op == "add" || (wide && op == "addw")) funct3 = 0;
        else if (op == "sub" || (wide && op == "subw")) { funct3 = 0; funct7 = 0x20; }
        else if (op == "sll") funct3 = 1; else if (op == "slt") funct3 = 2; else if (op == "sltu") funct3 = 3;
        else if (op == "xor") funct3 = 4; else if (op == "srl") funct3 = 5; else if (op == "sra") { funct3 = 5; funct7 = 0x20; }
        else if (op == "or") funct3 = 6; else if (op == "and") funct3 = 7; else reg = false;
        if (reg && rvReg(a[2], &m)) return word((funct7 << 25) | (m.id << 20) | (n.id << 15) | (funct3 << 12) | (d.id << 7) | ((op == "addw" || op == "subw") ? 0x3b : 0x33));
        bool imm = true; funct3 = 0;
        if (op == "addi" || (wide && op == "addiw")) funct3 = 0;
        else if (op == "slti") funct3 = 2; else if (op == "sltiu") funct3 = 3;
        else if (op == "xori") funct3 = 4; else if (op == "ori") funct3 = 6; else if (op == "andi") funct3 = 7; else imm = false;
        if (imm && signedValue(a[2], 12, &immediate)) return word(rvI(d.id, n.id, immediate, funct3, op == "addiw" ? 0x1b : 0x13));
        if ((op == "slli" || op == "srli" || op == "srai") && unsignedValue(a[2], wide ? 63 : 31, &bits)) return word(rvI(d.id, n.id, static_cast<i64>(bits), op == "slli" ? 1 : 5) | (op == "srai" ? 0x40000000u : 0));
    }
    const bool load = op == "lb" || op == "lbu" || op == "lh" || op == "lhu" || op == "lw" || (wide && (op == "ld" || op == "lwu"));
    const bool store = op == "sb" || op == "sh" || op == "sw" || (wide && op == "sd");
    if ((load || store) && a.size() == 2 && rvReg(a[0], &d)) {
        std::string base, offset;
        if (!rvAddress(a[1], &base, &offset) || !rvReg(base, &n) || !signedValue(offset, 12, &immediate)) return bad("RISC-V load/store signed imm12(register)");
        const unsigned funct3 = op == "lb" || op == "sb" ? 0 : op == "lh" || op == "sh" ? 1 : op == "lw" || op == "sw" ? 2 : op == "ld" || op == "sd" ? 3 : op == "lbu" ? 4 : op == "lhu" ? 5 : 6;
        if (load) return word(rvI(d.id, n.id, immediate, funct3, 3));
        const u32 value = static_cast<u32>(immediate) & 0xfff;
        return word((value >> 5) << 25 | (d.id << 20) | (n.id << 15) | (funct3 << 12) | ((value & 31) << 7) | 0x23);
    }
    return bad("unsupported RISC-V mnemonic/operand form: " + op);
}

Status encode(Arch arch, const Instruction& insn, Address pc, const Labels& labels, bool first, std::vector<u8>* out) {
    if(!insn.op.empty()&&insn.op[0]=='.'){
        unsigned width=insn.op==".byte"?1:insn.op==".short"||insn.op==".hword"?2:insn.op==".word"||insn.op==".long"?4:insn.op==".quad"?8:0;
        if(width){if(insn.args.empty())return bad("data directive needs values");for(const auto& value:insn.args){u64 bits=0;if(!bitValue(value,width*8,&bits)){Address address=0;if(!target(value,pc,labels,first,&address)|| (width<8&&address>=(u64(1)<<(width*8))))return bad("directive symbol/value does not fit its width");bits=address;}if(out->size()>kMaxBytes-width)return Status::error(ErrorCode::kTooLarge,"directive exceeds patch output budget");emit(out,bits,width);}return Status::success();}
        if(insn.op==".zero"||insn.op==".align"||insn.op==".org"){
            if(insn.args.empty()||insn.args.size()>2)return bad("fill/alignment directive requires value[,fill]");u64 value=0,fill=0;if(!unsignedValue(insn.args[0],kNoAddress-1,&value)||(insn.args.size()==2&&!unsignedValue(insn.args[1],255,&fill)))return bad("invalid directive value/fill");u64 count=value;
            if(insn.op==".align"){if(!value||value>1024||(value&(value-1)))return bad("alignment must be a power of two <=1024");count=(value-pc%value)%value;}
            else if(insn.op==".org"){if(value<pc)return bad(".org cannot move backwards");count=value-pc;}
            if(count>kMaxBytes-out->size())return Status::error(ErrorCode::kTooLarge,"directive padding exceeds1024 bytes");out->insert(out->end(),static_cast<size_t>(count),static_cast<u8>(fill));return Status::success();
        }return bad("unknown directive: "+insn.op);
    }
    switch (arch) {
        case Arch::kAArch64: return a64(insn, pc, labels, first, out);
        case Arch::kX86_64: return x86Encode(insn, pc, labels, first, true, out);
        case Arch::kX86_32: return x86Encode(insn, pc, labels, first, false, out);
        case Arch::kArm32: return armEncode(insn, pc, labels, first, out);
        case Arch::kThumb: return thumbEncode(insn, pc, labels, first, out);
        case Arch::kRiscV32: return rvEncode(insn, pc, labels, first, false, out);
        case Arch::kRiscV64: return rvEncode(insn, pc, labels, first, true, out);
        default: return Status::error(ErrorCode::kUnsupported, "assembler architecture is not supported");
    }
}

}  // namespace

Status assemble(Arch arch, Address address, const std::string& source, std::vector<u8>* output) {
    return assembleWithSymbols(arch,address,source,{},output);
}
Status assembleWithSymbols(Arch arch, Address address, const std::string& source,const std::map<std::string,Address>& symbols,std::vector<u8>* output) {
    if (!output) return Status::error(ErrorCode::kInternalError, "missing assembler output");
    const bool narrow = arch == Arch::kArm32 || arch == Arch::kThumb || arch == Arch::kX86_32 || arch == Arch::kRiscV32;
    const unsigned alignment = arch == Arch::kAArch64 || arch == Arch::kArm32 ? 4 : arch == Arch::kThumb || arch == Arch::kRiscV32 || arch == Arch::kRiscV64 ? 2 : 1;
    if (address == kNoAddress || address % alignment || (narrow && address > 0xffffffffu)) return bad("patch address is out of range or misaligned for its instruction mode");
    std::vector<Statement> statements;
    Status status = parse(source, &statements); if (!status.ok()) return status;
    Labels labels=symbols;for(const auto& symbol:labels)if(!identifier(symbol.first)||symbol.second==kNoAddress)return bad("invalid external symbol");if(labels.size()>4096)return Status::error(ErrorCode::kTooLarge,"external symbol budget exceeded");std::vector<u8> measured;
    for (const Statement& statement : statements) {
        if (address > std::numeric_limits<Address>::max() - measured.size()) return bad("patch address overflow");
        const Address pc = address + measured.size();
        for (const auto& label : statement.labels) if (!labels.emplace(label, pc).second) return bad("duplicate label: " + label);
        if (!statement.hasInstruction) continue;
        if(statement.instruction.op[0]!='.'&&pc%alignment)return bad("instruction after data directive is misaligned");status = encode(arch, statement.instruction, pc, labels, true, &measured);
        if (!status.ok()) return Status::error(status.code(), status.message() + " (line " + std::to_string(statement.instruction.line) + ")");
        if (measured.size() > kMaxBytes) return Status::error(ErrorCode::kTooLarge, "assembled patch exceeds 1024 bytes");
        if (address > std::numeric_limits<Address>::max() - measured.size() ||
            (narrow && measured.size() > u64(0x100000000ULL) - address)) return bad("patch crosses architecture address-space limit");
    }
    std::vector<u8> prepared;
    for (const Statement& statement : statements) {
        if (!statement.hasInstruction) continue;
        status = encode(arch, statement.instruction, address + prepared.size(), labels, false, &prepared);
        if (!status.ok()) return Status::error(status.code(), status.message() + " (line " + std::to_string(statement.instruction.line) + ")");
    }
    if (prepared.size() != measured.size()) return bad("instruction size changed during label resolution");
    *output = std::move(prepared); return Status::success();
}

std::string assemblerSyntax(Arch arch) {
    const std::string common = "Little-endian; newline/semicolon separators; // comments; case-sensitive labels; decimal/0x and optional # immediates. Branch targets are absolute addresses, labels or symbol+/-offset. .byte/.short/.word/.quad/.zero/.align/.org directives; externally resolved absolute symbols. Maximum1024 bytes/instructions; no macros or implicit truncation. ";
    switch (arch) {
        case Arch::kAArch64: return common + "A64: nop; ret/br/blr; b/bl/b.cc/cbz/cbnz/tbz/tbnz; adr/adrp label; mov/movz/movn/movk; add/sub/adds/subs/cmp; shifted-register and/orr/eor/ands/bic/orn/eon/bics; mul/mneg/madd/msub; ldr/str/ldrb/strb/ldrh/strh; ldp/stp signed scaled offset, pre-index ! and post-index writeback. GPR scalar forms only; SIMD/FP/system mnemonics remain unsupported.";
        case Arch::kX86_64: case Arch::kX86_32: return common + "Intel x86: nop; ret [imm16]; int3; ud2; leave; push/pop native-width register; mov Rd,Rs/imm/memory and memory,Rs/imm; lea Rd,memory; add/or/adc/sbb/and/sub/xor/cmp/test register/memory forms; inc/dec Rd; jmp/call target or native register; Jcc target (rel32). 32/64-bit GPRs; memory [base+index*1/2/4/8+signed_disp32] and RIP-relative [rel label]/[rip+disp32], dword/qword qualifiers. mov r64,imm expands to sign-extended imm32 or full imm64 as required.";
        case Arch::kArm32: return common + "ARM32: nop; ret/bx/blx; b/bl/b.cc target (PC+8); mov/mvn/movw/movt; add/sub/and/orr/eor/cmp register or rotated immediate; ldr/str [Rn,#signed imm12]. Explicit .condition suffix and adds/subs/ands/orrs/eors/movs/mvns flag-setting forms; no PC destinations or unsafe flag-setting pseudo-move expansion.";
        case Arch::kThumb: return common + "Thumb/Thumb-2: nop; ret (=bx lr); bx/blx Rn; b/b.cc narrow target; bl target (PC+4); mov Rd,Rs or imm32 (non-flag-setting MOVW/MOVT); movw/movt Rd,imm16; movs low Rd,imm8; adds/subs low Rd,imm8 or Rd,Rn,Rm/imm3; add Rd,Rm; add/sub sp,#multiple-of-4; cmp Rn,Rm/imm8; ldr/str low Rd,[low Rn/sp,#scaled offset]. Even addresses, no implicit ARM/Thumb interworking, no IT blocks.";
        case Arch::kRiscV32: case Arch::kRiscV64: return common + "RISC-V base integer (x0..x31 or ABI names): nop/ret/ecall/ebreak; mv/li; arithmetic/bitwise/register/immediate/shift; lui/auipc; j/call/jal/jalr/jr and conditional branches; integer loads/stores. RV64 also ld/lwu/sd/addw/subw/addiw. Compressed c.nop/c.ebreak/c.li/c.addi/c.mv/c.add/c.jr/c.jalr/c.j/c.beqz/c.bnez/c.lw/c.sw; RV32 c.jal, RV64 c.addiw/c.ld/c.sd. No FP/vector/atomic assembler or far-call relaxation.";
        default: return "No built-in assembler for this architecture.";
    }
}

}  // namespace mint
