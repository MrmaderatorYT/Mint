#include "mint/session.h"
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <sstream>
#include <tuple>
#include <fstream>
#include <fcntl.h>
#include <unistd.h>
#include <cerrno>
#include <functional>
#include "mint/analysis/demangle.h"
#include "mint/analysis/reference_analysis.h"
#include "mint/ssa/ssa_builder.h"
#include "mint/ir/normalize.h"
#include "mint/analysis/abi_model.h"

namespace mint {
namespace {
std::string hex(Address a) { char b[32]; std::snprintf(b,sizeof(b),"%llx",static_cast<unsigned long long>(a)); return b; }
std::string lower(std::string s) { for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c))); return s; }
std::string oneLine(std::string s) { for (char& c : s) if (c == '\n' || c == '\r' || c == '\t') c = ' '; return s; }
Status patchBytes(const std::string& text,std::vector<u8>* result) {
    result->clear();std::istringstream input(text);std::string token;
    while(input>>token) {
        if(token.size()!=2 || !std::isxdigit(static_cast<unsigned char>(token[0])) || !std::isxdigit(static_cast<unsigned char>(token[1])))return Status::error(ErrorCode::kBadFormat,"patch requires hex bytes, e.g. 1f 20 03 d5");
        result->push_back(static_cast<u8>(std::stoul(token,nullptr,16)));if(result->size()>1024)return Status::error(ErrorCode::kTooLarge,"patch exceeds 1024 bytes");
    }
    return Status::success();
}
u64 cstringSize(const MemoryMap& memory,Address address) {
    const auto bytes=memory.viewAt(address,4096);
    for(size_t i=0;i<bytes.size();++i)if(bytes.data()[i]==0)return i+1;
    return 0;
}
}
u64 Session::dataSize(Address address,const std::string& type,const DataTypeManager& types) const {
    if(type=="cstring")return cstringSize(image_.memory(),address);
    DataTypeLayout layout;return types.resolve(type,&layout).ok()?layout.size:0;
}
Status Session::openRawPath(const std::string& path,Arch arch,Address base,Address entry) {
    beginOpen();
    auto status=file_.open(path);if(!status.ok())return status;
    status=image_.loadRaw(file_.view(),arch,base,entry);if(!status.ok())return status;
    status=renderer_.open(arch);if(!status.ok())return status;
    if(lifter_.ready() && lifter_.arch()!=arch)lifter_.open(arch);
    loadDebugInfo();
    kind_=InputKind::kElf;loaded_=true;return Status::success();
}
Status Session::attachProject(const std::string& path) {
    bool debugStateAccepted = false;
    struct DebugRollback {
        DwarfReport& current; std::string& digest; DwarfReport old; std::string oldDigest; bool& accepted;
        ~DebugRollback() { if (!accepted) { current = std::move(old); digest = std::move(oldDigest); } }
    } debugRollback{debugInfo_, externalDebugDigest_, debugInfo_, externalDebugDigest_, debugStateAccepted};
    const auto debugStatus = restoreExternalDebug(path); if (!debugStatus.ok()) return debugStatus;
    // A stable fingerprint is an accidental-mismatch guard, not a security hash.
    u64 fingerprint=14695981039346656037ull;for(size_t i=0;i<file_.size();++i){fingerprint^=file_.view().data()[i];fingerprint*=1099511628211ull;}
    // Keep legacy builtin fingerprints, but never bind different external
    // decoders through archName(custom) == "unknown". The registry is immutable
    // within a process; its stable ID and interpretation metadata survive reopen.
    std::string architecture=archName(image_.arch());
    if(static_cast<u8>(image_.arch())>=128) {
        ArchitectureDescription description;
        if(!architectureDescription(image_.arch(),&description))return Status::error(ErrorCode::kUnsupported,"project decoder is not registered");
        architecture=description.id+"#"+std::to_string(static_cast<u8>(description.architecture))+"/"+
            std::to_string(description.pointerSize)+"/"+std::to_string(description.minInstructionSize)+"/"+
            std::to_string(description.maxInstructionSize)+"/"+std::to_string(description.instructionAlignment)+"/"+
            std::to_string(description.elfMachine)+"/"+std::to_string(description.elfClass);
    }
    const auto source=std::string(image_.formatName())+":"+architecture+":"+hex(image_.entryPoint())+":"+hex(image_.imageBase())+":"+hex(fingerprint);
    Program candidate(image_.pointerSize());auto status=candidate.setImportedTypes(importedDebugTypes());if(!status.ok())return status;
    status=candidate.open(path,source);if(!status.ok())return status;
    ElfImage trial;
    if(!isDexLike()){status=prepareUserImage(candidate.annotations(),candidate.types(),&trial);if(!status.ok())return status;}
    program_=std::move(candidate);debugStateAccepted=true;
    analysisCachePath_=isDexLike()?"":path+".analysis";
    allowCacheRestore_=true;analysisCacheDiagnostic_.clear();
    status=applyUserModel();if(!status.ok())return status;
    if(!analyzed_) return Status::success();
    analyzed_=false;programReport_={};return analyze();
}
Status Session::openMachOPath(const std::string& path,Arch architecture) {
    beginOpen();auto status=file_.open(path);if(!status.ok())return status;
    status=image_.load(file_.view());if(!status.ok())return status;
    if(image_.format()!=ImageFormat::kMachO64)return Status::error(ErrorCode::kBadFormat,"explicit slice import requires Mach-O");
    if(image_.arch()!=architecture){status=image_.loadMachOSlice(file_.view(),architecture);if(!status.ok())return status;}
    if(image_.arch()!=architecture)return Status::error(ErrorCode::kUnsupported,"requested Mach-O architecture is absent");
    status=renderer_.open(architecture);if(!status.ok())return status;loadDebugInfo();
    kind_=InputKind::kElf;loaded_=true;return Status::success();
}
Status Session::applyUserModel() {
    if(isDexLike())return Status::success();
    ElfImage trial;auto status=prepareUserImage(program_.annotations(),program_.types(),&trial);if(!status.ok())return status;
    image_=std::move(trial);program_.bindMemory(image_.memory());
    signatures_=SignatureLibrary{};const auto library=program_.get(0,"signature-library");
    if(!library.empty()){status=signatures_.deserialize(library);if(!status.ok())return status;}
    return Status::success();
}
Status Session::prepareUserImage(const std::vector<ProgramAnnotation>& annotations,const DataTypeManager& types,ElfImage* result) const {
    *result=image_;result->resetPatches();std::vector<std::pair<Address,Address>> patchRanges;
    for(const auto& entry:annotations)if(entry.kind=="patch") {
        std::vector<u8> bytes;auto status=patchBytes(entry.value,&bytes);if(!status.ok())return status;
        status=result->applyPatch(entry.address,ByteView(bytes.data(),bytes.size()));if(!status.ok())return status;
        patchRanges.push_back({entry.address,entry.address+bytes.size()});
    }
    std::sort(patchRanges.begin(),patchRanges.end());for(size_t i=1;i<patchRanges.size();++i)if(patchRanges[i].first<patchRanges[i-1].second)return Status::error(ErrorCode::kBadFormat,"overlapping persisted patches");
    std::vector<std::pair<Address,Address>> dataRanges;
    for(const auto& entry:annotations) {
        if(entry.kind!="type-library" && entry.kind!="signature-library" && entry.kind!="source" && !result->memory().isMapped(entry.address))return Status::error(ErrorCode::kBadFormat,"persisted annotation address is not mapped");
        if(entry.kind=="signature-library") {SignatureLibrary library;auto status=library.deserialize(entry.value);if(!status.ok())return status;status=library.validateFor(*result);if(!status.ok())return status;}
        if(entry.kind=="function" && (entry.value!="code" || !result->memory().isExecutable(entry.address) || (result->arch()==Arch::kAArch64 && entry.address%4)))return Status::error(ErrorCode::kBadFormat,"invalid persisted function seed");
        if(entry.kind=="data") {
            u64 size=0;
            if(entry.value=="cstring")size=cstringSize(result->memory(),entry.address);
            else {DataTypeLayout layout;auto status=types.resolve(entry.value,&layout);if(!status.ok())return status;size=layout.size;}
            const auto* segment=result->memory().segmentAt(entry.address);
            if(!segment || !size || size>segment->end()-entry.address)return Status::error(ErrorCode::kBadFormat,"invalid persisted data range");
            dataRanges.push_back({entry.address,entry.address+size});
        }
    }
    std::sort(dataRanges.begin(),dataRanges.end());
    for(size_t i=1;i<dataRanges.size();++i)if(dataRanges[i].first<dataRanges[i-1].second)return Status::error(ErrorCode::kBadFormat,"overlapping persisted data ranges");
    for(const auto& entry:annotations)if(entry.kind=="function") {
        auto it=std::upper_bound(dataRanges.begin(),dataRanges.end(),std::make_pair(entry.address,~Address{0}));
        if(it!=dataRanges.begin()){--it;if(entry.address<it->second)return Status::error(ErrorCode::kBadFormat,"function seed lies inside defined data");}
    }
    return Status::success();
}
Status Session::reanalyze() {
    prototypeEvidence_={};prototypeEvidenceBuilt_=false;
    analyzed_=false;cancel_.store(false);programReport_={};program_.invalidateReferences();
    auto status=applyUserModel();if(!status.ok())return status;
    const bool previous=allowCacheRestore_;allowCacheRestore_=false;
    analysisCacheDiagnostic_.clear();status=analyze();allowCacheRestore_=previous;return status;
}
Status Session::defineType(const std::string& declaration) {
    auto types=program_.types();auto status=types.define(declaration);if(!status.ok())return status;
    return editAnnotation(0,"type-library",types.serialize());
}
Status Session::importLibrary(const std::string& text,bool signatures) {
    if(isDexLike())return Status::error(ErrorCode::kUnsupported,"libraries require a native Program");
    if(signatures) {
        SignatureLibrary library;auto status=library.deserialize(text);if(!status.ok())return status;
        status=library.validateFor(image_);if(!status.ok())return status;
        return editAnnotation(0,"signature-library",library.serialize());
    }
    DataTypeManager incoming(image_.pointerSize());auto status=incoming.deserialize(text);if(!status.ok())return status;
    // Merge as one candidate so imported forward/recursive pointers are atomic.
    std::string merged="MINT_TYPES 1 "+std::to_string(image_.pointerSize())+'\n';
    for(const auto& definition:program_.types().definitions())if(incoming.declarationFor(definition.name).empty())merged+=definition.declaration+'\n';
    for(const auto& definition:incoming.definitions())merged+=definition.declaration+'\n';
    DataTypeManager candidate(image_.pointerSize());status=candidate.deserialize(merged);if(!status.ok())return status;
    return editAnnotation(0,"type-library",candidate.serialize());
}
Status Session::eraseType(const std::string& name) {
    if(!importedDebugTypes().declarationFor(name).empty())return Status::error(ErrorCode::kUnsupported,"DWARF-derived types are reproduced on reopen; replace the definition rather than silently erasing imported evidence");
    auto types=program_.types();auto status=types.erase(name);if(!status.ok())return status;
    return editAnnotation(0,"type-library",types.serialize());
}
Status Session::editAnnotation(Address address, const std::string& kind, const std::string& value) {
    if (isDexLike()) return Status::error(ErrorCode::kUnsupported,"program edits require a native binary");
    if (kind=="source")return Status::error(ErrorCode::kBadFormat,"source identity is read-only");
    if (kind!="type-library" && kind!="signature-library" && !image_.memory().isMapped(address)) return Status::error(ErrorCode::kNotFound,"address is not mapped");
    if (kind=="function" && !value.empty() && (value!="code" || !image_.memory().isExecutable(address)))return Status::error(ErrorCode::kBadFormat,"function seed requires executable address and value 'code'");
    if(kind=="function" && !value.empty()) {
        if(image_.arch()==Arch::kAArch64 && address%4)return Status::error(ErrorCode::kBadFormat,"AArch64 function entry must be 4-byte aligned");
        for(const auto& e:program_.annotations())if(e.kind=="data" && address>=e.address && address-e.address<dataSize(e.address,e.value,program_.types()))return Status::error(ErrorCode::kBadFormat,"function seed lies inside defined data");
    }
    if (kind=="patch" && !value.empty()) {
        std::vector<u8> bytes;auto status=patchBytes(value,&bytes);if(!status.ok())return status;
        u64 offset;if(bytes.empty() || !image_.fileOffsetAt(address,bytes.size(),&offset))return Status::error(ErrorCode::kBadFormat,"patch must be uniquely mapped and file-backed");
        for(const auto& e:program_.annotations())if(e.kind=="patch" && e.address!=address) {
            std::vector<u8> other;patchBytes(e.value,&other);
            if(e.address<address+bytes.size() && address<e.address+other.size())return Status::error(ErrorCode::kBadFormat,"patch overlaps another patch");
        }
    }
    if (kind == "prototype" && !value.empty()) {
        UserPrototype prototype; auto status=parseUserPrototype(value,&prototype); if (!status.ok()) return status;
        if (!analyzer_.functionAt(address)) return Status::error(ErrorCode::kNotFound,"prototype requires a function entry");
        const auto mode=image_.architectureAt(address);
        if(prototype.callingConvention.empty() && image_.format()==ImageFormat::kPe64 && mode==Arch::kX86_64)prototype.callingConvention="windows64";
        AbiModel model;status=buildAbiModel(mode,prototype,&model,[this](const std::string& type,DataTypeLayout* layout){return program_.types().resolve(type,layout);});
        if(!status.ok())return status;
    }
    if(kind=="signature-library" && !value.empty()) {
        SignatureLibrary library;auto status=library.deserialize(value);if(!status.ok())return status;
        status=library.validateFor(image_);if(!status.ok())return status;
    }
    if (kind == "data" && !value.empty()) {
        u64 width = dataSize(address,value,program_.types());
        if(!width || width>16*1024*1024)return Status::error(ErrorCode::kBadFormat,"invalid/oversized data type");
        if (value == "cstring") {
            std::string text;
            if (!image_.memory().readCString(address,&text,4096)) return Status::error(ErrorCode::kBadFormat,"cstring must terminate within 4096 bytes");
            width = text.size()+1;
        }
        const auto* segment = image_.memory().segmentAt(address);
        if (width > segment->end() - address) return Status::error(ErrorCode::kTruncated,"data crosses a memory segment");
        for(const auto& e:program_.annotations())if(e.kind=="function" && e.address>=address && e.address-address<width)return Status::error(ErrorCode::kBadFormat,"data overlaps an explicit function seed");
        for (const auto& entry : program_.annotations()) if (entry.kind == "data") {
            u64 other = dataSize(entry.address,entry.value,program_.types());
            if (entry.value == "cstring") { std::string text; if (image_.memory().readCString(entry.address,&text,4096)) other = text.size()+1; }
            if (entry.address != address && entry.address < address + width && address < entry.address + other)
                return Status::error(ErrorCode::kBadFormat,"data overlaps another definition");
        }
    }
    if(kind=="type-library") {
        DataTypeManager types(image_.pointerSize());auto status=types.deserialize(value);if(!status.ok())return status;
        std::vector<std::pair<Address,u64>> ranges;
        for(const auto& e:program_.annotations())if(e.kind=="data") {
            const auto width=dataSize(e.address,e.value,types);const auto* segment=image_.memory().segmentAt(e.address);
            if(!segment || !width || width>segment->end()-e.address)return Status::error(ErrorCode::kBadFormat,"type edit would invalidate a mapped data definition");
            for(const auto& seed:program_.annotations())if(seed.kind=="function" && seed.address>=e.address && seed.address-e.address<width)return Status::error(ErrorCode::kBadFormat,"type edit would overlap a function seed");
            ranges.push_back({e.address,e.address+width});
        }
        std::sort(ranges.begin(),ranges.end());for(size_t i=1;i<ranges.size();++i)if(ranges[i].first<ranges[i-1].second)return Status::error(ErrorCode::kBadFormat,"type edit would overlap data definitions");
    }
    const bool structural=kind=="data" || kind=="function" || kind=="patch" || kind=="type-library";
    ElfImage trial;
    if(structural) {
        auto entries=program_.annotations();entries.erase(std::remove_if(entries.begin(),entries.end(),[&](const auto& e){return e.address==address && e.kind==kind;}),entries.end());
        if(!value.empty())entries.push_back({address,kind,value});
        auto types=program_.types();if(kind=="type-library"){auto status=types.deserialize(value);if(!status.ok())return status;}
        auto status=prepareUserImage(entries,types,&trial);if(!status.ok())return status;
    }
    const auto before=program_.annotations();
    auto status=program_.edit(address,kind,value);
    if(!status.ok())return status;status=updateAfterEdit(before,structural?&trial:nullptr);
    if(status.ok())notifyPluginEvent(MINT_EVENT_ANNOTATION_CHANGED,address,kind);return status;
}
Status Session::undoEdit(bool redo) {
    const auto before=program_.annotations();
    auto status = redo ? program_.redo() : program_.undo();
    return status.ok()?updateAfterEdit(before):status;
}
std::string Session::nameAt(Address address) const {
    auto name = program_.get(address,"name");
    if (!name.empty()) return name;
    for(const auto& debug:debugInfo_.functions)if(debug.entry==address) {
        if(!debug.linkageName.empty())return debug.linkageName;
        if(!debug.name.empty())return debug.name;
    }
    const auto* function = analyzer_.functionAt(address);
    if (function && !function->name.empty()) return function->name;
    return image_.describeAddress(address);
}
std::string Session::displayNameAt(Address address) const { return demangleSymbol(nameAt(address)); }
std::string Session::memoryBlocksText() const {
    std::string out="Format: "+std::string(image_.formatName())+" | "+architectureName(image_.arch())+" | revision "+std::to_string(program_.revision())+"\n";
    out+=analysisStatusText();
    for(const auto& block:program_.memory().segments()) {
        out+=hex(block.start)+"\t"+block.name+" [0x"+hex(block.start)+", 0x"+hex(block.end())+") ";
        out+=(block.flags&kMemRead)?"r":"-";out+=(block.flags&kMemWrite)?"w":"-";out+=block.executable()?"x":"-";
        out+=" | file-backed "+std::to_string(block.data.size())+" / "+std::to_string(block.size)+" bytes\n";
    }
    return out;
}
std::string Session::provenanceText(Address address) const {
    const Function* fn=analyzer_.functionContaining(address);
    if(!fn)return "No discovered function contains this address.\n";
    std::string out="Function: "+displayNameAt(fn->entry)+" @ 0x"+hex(fn->entry)+"\nOrigin: "+functionOriginName(fn->origin)+"\n";
    out+="Confidence: "+std::string(fn->origin==FunctionOrigin::kLinearSweep?"heuristic":"metadata, direct reachability, or explicit user decision")+" (not a proof of semantics)\n";
    out+="Incomplete flow: "+std::string(fn->incomplete?"yes":"no")+"\nIndirect jumps: "+std::to_string(fn->indirectJumps)+"; recovered sites: "+std::to_string(fn->resolvedIndirectJumps.size())+"\nUndecodable sites: "+std::to_string(fn->undecodableSites)+"\n";
    const auto evidence=analyzer_.indirectFlowReports().find(fn->entry);
    if(evidence!=analyzer_.indirectFlowReports().end())for(const auto& site:evidence->second.sites) {
        out+="\n0x"+hex(site.address)+(site.call?" indirect call":" indirect branch")+": "+(site.complete?"closed static target set":"partial / unresolved")+"\n";
        for(const auto& target:site.targets)out+="  target 0x"+hex(target.address)+" ("+archName(target.decodeArch)+"; raw pointer 0x"+hex(target.rawPointer)+")\n";
        for(const auto& source:site.provenance)out+="  evidence: "+source+"\n";
        for(const auto& range:site.dependencies)out+="  dependency [0x"+hex(range.start)+", 0x"+hex(range.end)+")\n";
        if(!site.reason.empty())out+="  "+site.reason+'\n';
    }
    out+="Memory SSA/aliasing and indirect calls are not fully modeled; pseudo-C remains an analysis view.\n";
    return out;
}
Status Session::exportPatchedCopy(const std::string& path) const {
    if(isDexLike() || !loaded_)return Status::error(ErrorCode::kUnsupported,"patched export requires native input");
    // O_EXCL also refuses the original input and existing exports. The mapped
    // source is never writable; cleanup only removes this newly created file.
    int fd=::open(path.c_str(),O_WRONLY|O_CREAT|O_EXCL,0600);
    if(fd<0)return Status::error(ErrorCode::kIoError,"export destination must be a new writable file");
    bool ok=true;size_t written=0;
    while(written<file_.size()) {
        auto n=::write(fd,file_.view().data()+written,std::min<size_t>(file_.size()-written,1024*1024));
        if(n<0 && errno==EINTR)continue;if(n<=0){ok=false;break;}written+=static_cast<size_t>(n);
    }
    for(const auto& entry:program_.annotations())if(ok && entry.kind=="patch") {
        std::vector<u8> bytes;u64 offset=0;
        ok=patchBytes(entry.value,&bytes).ok() && image_.fileOffsetAt(entry.address,bytes.size(),&offset);
        size_t at=0;
        while(ok && at<bytes.size()) {
            auto n=::pwrite(fd,bytes.data()+at,bytes.size()-at,static_cast<off_t>(offset+at));
            if(n<0 && errno==EINTR)continue;if(n<=0){ok=false;break;}at+=static_cast<size_t>(n);
        }
    }
    if(ok)ok=::fsync(fd)==0;if(::close(fd)!=0)ok=false;
    if(!ok){::unlink(path.c_str());return Status::error(ErrorCode::kIoError,"patched export failed; incomplete new file removed");}
    return Status::success();
}
UserPrototype Session::prototypeAt(Address address) const {
    UserPrototype result;const auto user=program_.get(address,"prototype");
    auto effective=[&](UserPrototype candidate){if(candidate.valid() && candidate.callingConvention.empty() && image_.format()==ImageFormat::kPe64 && image_.architectureAt(address)==Arch::kX86_64)candidate.callingConvention="windows64";return candidate;};
    if(!user.empty()){parseUserPrototype(user,&result);return effective(result);}
    for(const auto& function:debugInfo_.functions)if(function.entry==address && !function.prototype.empty()) {
        const auto mode=image_.architectureAt(address);
        UserPrototype candidate;AbiModel model;
        if(parseUserPrototype(function.prototype,&candidate).ok()) {candidate=effective(candidate);
            if(buildAbiModel(mode,candidate,&model,[this](const std::string& type,DataTypeLayout* layout){return program_.types().resolve(type,layout);}).ok())return candidate;}
    }
    if(signatures_.abi()!=SignatureAbi::kUnknown) {
        for(const auto& symbol:image_.symbols())if(!symbol.undefined && symbol.value==address){auto candidate=signatures_.prototypeFor(symbol.name);if(candidate.valid())return effective(candidate);}
        const auto imported=image_.pltStubs().find(address);
        if(imported!=image_.pltStubs().end()){auto candidate=signatures_.prototypeFor(imported->second);if(candidate.valid())return effective(candidate);}
    }
    return result;
}
std::vector<Session::ListingRow> Session::programListing(Address start, size_t limit) {
    std::vector<ListingRow> rows;
    if (!analyzed_ || isDexLike()) return rows;
    limit = std::min<size_t>(limit,4096);
    const auto& memory = image_.memory(); Address cursor = start;
    for (const auto& segment : memory.segments()) {
        if (cursor >= segment.end()) continue;
        cursor = std::max(cursor,segment.start);
        while (cursor < segment.end() && rows.size() < limit) {
            ListingRow row; row.address = cursor;
            const auto* insn = analyzer_.code().find(cursor);
            auto type = program_.get(cursor,"data");
            if (insn) {
                row.size = insn->size; row.flow = insn->flow; row.target = insn->target;
                DecodedInsn decoded; row.text = renderInstruction(cursor,&decoded) ? decoded.text() : "(bad)";
                row.comment = commentFor(*insn);
            } else {
                row.size = type.empty()?1:static_cast<u32>(dataSize(cursor,type,program_.types()));
                if(!row.size)row.size=1;
                row.size = static_cast<u32>(std::min<u64>(row.size,segment.end()-cursor));
                if (type == "cstring") {
                    std::string value;
                    if (memory.readCString(cursor,&value,4096)) {
                        row.size = static_cast<u32>(value.size()+1);
                        row.text = "cstring \"" + oneLine(value) + "\"";
                    } else row.text = "cstring (unterminated; byte shown)";
                }
                if (row.text.empty()) {
                    u64 value = 0; memory.read(cursor,&value,std::min<u32>(row.size,8));
                    row.text = (type.empty() ? "db" : type) + " 0x" + hex(value);
                }
                DataTypeLayout layout;
                if (!type.empty() && program_.types().resolve(type,&layout).ok() && layout.kind==DataTypeKind::kPointer && layout.size==image_.pointerSize()) {
                    Address target;
                    if (image_.resolvePointer(cursor,&target)) { row.target = target; row.comment = nameAt(target); }
                }
            }
            const auto label = program_.get(cursor,"name");
            if (!label.empty()) row.text = label + ":  " + row.text;
            const auto comment = program_.get(cursor,"comment");
            if (!comment.empty()) row.comment += (row.comment.empty() ? "" : " | ") + comment;
            const auto bookmark = program_.get(cursor,"bookmark");
            if (!bookmark.empty()) row.comment += " [bookmark: " + bookmark + "]";
            const auto source=sourceLocationText(cursor);
            if(!source.empty())row.comment+=std::string(row.comment.empty()?"":" | ")+"DWARF "+source;
            u8 bytes[24]{}; const size_t count = std::min<size_t>(row.size,sizeof(bytes));
            if (memory.read(cursor,bytes,count)) {
                std::string prefix; char byte[4];
                for (size_t i=0;i<count;++i) { std::snprintf(byte,sizeof(byte),"%02x ",bytes[i]); prefix += byte; }
                row.text = prefix + "  " + row.text;
            }
            rows.push_back(std::move(row)); cursor += rows.back().size;
        }
        if (rows.size() == limit) break;
    }
    return rows;
}
Program::ReferenceGroup Session::globalReferences() const {
    Program::ReferenceGroup group;
    for (const auto& reloc : image_.relocations()) {
        Address target; if (image_.resolvePointer(reloc.offset,&target) && image_.memory().isMapped(target))
            group.references.push_back({reloc.offset,target,"relocation"});
    }
    for(const auto& entry:program_.annotations())if(entry.kind=="data") {
        DataTypeLayout layout;if(!program_.types().resolve(entry.value,&layout).ok() || layout.kind!=DataTypeKind::kPointer || layout.size!=image_.pointerSize())continue;
        Address target;if(image_.resolvePointer(entry.address,&target))group.references.push_back({entry.address,target,"user pointer"});
    }
    return group;
}
Program::ReferenceGroup Session::functionReferences(const Function& function) {
    Program::ReferenceGroup group;group.owner=function.entry;
    const auto indirect=analyzer_.indirectFlowReports().find(function.entry);
    if(indirect!=analyzer_.indirectFlowReports().end())for(const auto& site:indirect->second.sites) {
        for(const auto& dependency:site.dependencies)group.dependencies.push_back({dependency.start,dependency.end});
        for(const auto& target:site.targets)group.references.push_back({site.address,target.address,
            std::string(site.call?"indirect call":"indirect branch")+(site.complete?" (closed static set)":" (candidate)")});
    }
    for(auto address:function.instructions)if(const auto* insn=analyzer_.code().find(address)) {
        group.dependencies.push_back({address,address+insn->size});
        if(insn->hasKnownTarget())group.references.push_back({address,image_.canonicalAddress(insn->target),insn->flow==FlowKind::kCall?"call":"branch"});
    }
    if(!lifter_.ready() || lifter_.arch()!=image_.architectureAt(function.entry)) {
        if(!lifter_.open(image_.architectureAt(function.entry)).ok()){group.conservative=true;return group;}
    }
    IrFunction ir;if(!lifter_.liftFunction(function,image_.memory(),&ir).ok()){group.conservative=true;return group;}
    for(const auto& insn:ir.insns)for(const auto& operand:{insn.a,insn.b,insn.c})
        if(operand.isConstant() && operand.size>=4 && operand.offset && image_.memory().isMapped(operand.offset))
            group.references.push_back({insn.address,operand.offset,"address candidate"});
    if(ir.insns.size()>100000){group.conservative=true;return group;}
    normalizeRegisterAccesses(&ir);SsaFunction ssa;
    if(buildSsa(ir,&ssa).ok())collectSsaReferences(ssa,image_,&group);
    else group.conservative=true;
    return group;
}
void Session::buildReferences() {
    if(program_.referencesReady() || !analyzed_ || isDexLike())return;
    std::vector<Program::ReferenceGroup> groups;groups.push_back(globalReferences());
    for(const auto& function:analyzer_.functions()) {
        if(cancel_.load())return;
        groups.push_back(functionReferences(function));
    }
    referenceGroupsUpdated_=analyzer_.functions().size();
    program_.setReferenceGroups(std::move(groups));
    saveAnalysisCache();
}
void Session::refreshReferences(const std::vector<CodeAnalyzer::AddressRange>& dirty) {
    if(program_.referenceGroups().empty())return;
    auto groups=program_.referenceGroups();referenceGroupsUpdated_=0;
    for(auto& group:groups) {
        if(cancel_.load()){program_.invalidateReferences();return;}
        if(group.owner==kNoAddress){group=globalReferences();continue;}
        bool affected=group.conservative;
        for(const auto& dependency:group.dependencies)for(const auto& range:dirty)
            if(dependency.start<range.end && range.start<dependency.end)affected=true;
        if(affected) {
            const auto* function=analyzer_.functionAt(group.owner);
            if(!function){program_.invalidateReferences();return;}
            group=functionReferences(*function);++referenceGroupsUpdated_;
        }
    }
    program_.setReferenceGroups(std::move(groups));
}
std::string Session::referencesText(Address address) {
    buildReferences(); std::string out;
    for (const auto& r:program_.referencesAt(address)) {
        out += hex(r.from) + "\t" + r.kind + " -> 0x" + hex(r.to) + " " + nameAt(r.to) + "\n";
    }
    return out.empty() ? "No indexed references at this address. Indirect/computed references may be unresolved.\n" : out;
}
std::string Session::searchText(const std::string& query, size_t limit) {
    if (!analyzed_ || isDexLike() || query.empty()) return {};
    limit = std::min<size_t>(limit,500); std::string out; size_t count = 0;
    auto hit = [&](Address address,const std::string& text) { if (count++ < limit) out += hex(address)+"\t"+oneLine(text)+"\n"; };
    const auto needle = lower(query);
    if (needle.rfind("bytes:",0) == 0) {
        std::istringstream input(query.substr(6)); std::string token; std::vector<u8> pattern;
        while (input >> token) {
            if (token.size()!=2 || !std::isxdigit(static_cast<unsigned char>(token[0])) || !std::isxdigit(static_cast<unsigned char>(token[1]))) return "Byte pattern: bytes: 7f 45 4c 46\n";
            pattern.push_back(static_cast<u8>(std::stoul(token,nullptr,16)));
            if (pattern.size()>256) return "Byte pattern exceeds 256 bytes\n";
        }
        if (pattern.empty()) return {};
        for (const auto& segment : image_.memory().segments()) {
            for (size_t i=0;i+pattern.size()<=segment.data.size() && count<limit;++i)
                if (std::equal(pattern.begin(),pattern.end(),segment.data.data()+i)) hit(segment.start+i,"byte pattern");
        }
        return out;
    }
    for (const auto& function : analyzer_.functions()) if (lower(displayNameAt(function.entry)).find(needle)!=std::string::npos || lower(nameAt(function.entry)).find(needle)!=std::string::npos) hit(function.entry,"function "+displayNameAt(function.entry));
    for (const auto& symbol : image_.symbols()) if (!symbol.undefined && (lower(symbol.name).find(needle)!=std::string::npos || lower(demangleSymbol(symbol.name)).find(needle)!=std::string::npos)) hit(symbol.value,"symbol "+demangleSymbol(symbol.name));
    for (const auto& entry : program_.annotations()) if (lower(entry.value).find(needle)!=std::string::npos) hit(entry.address,entry.kind+": "+entry.value);
    for (const auto& segment : image_.memory().segments()) {
        size_t i=0;
        while (i<segment.data.size() && count<limit) {
            const size_t start=i;
            while (i<segment.data.size() && segment.data.data()[i]>=32 && segment.data.data()[i]<=126) ++i;
            if (i-start>=4) {
                const auto* first=segment.data.data()+start;const auto* last=segment.data.data()+i;
                const auto match=std::search(first,last,needle.begin(),needle.end(),[](u8 a,char b){return std::tolower(a)==static_cast<unsigned char>(b);});
                if(match!=last)hit(segment.start+start,"string "+std::string(reinterpret_cast<const char*>(first),std::min<size_t>(i-start,512)));
            }
            if (i<segment.data.size()) ++i;
        }
    }
    return out;
}
} // namespace mint
