#include "mint/version/binary_diff.h"

#include <algorithm>
#include <array>
#include <cstdio>
#include <map>
#include <set>
#include <sstream>

#include "mint/session.h"
#include "mint_analysis_engine_id.h"

namespace mint {
namespace {
constexpr size_t kMaxFunctions = 200000;
constexpr size_t kMaxMemberships = 4000000;
constexpr size_t kMaxNormalizedBytes = 64 * 1024 * 1024;
constexpr size_t kMaxFunctionInsns = 200000;
constexpr size_t kMaxInputBytes = 512 * 1024 * 1024;

Status bad(const std::string& message) { return Status::error(ErrorCode::kBadFormat, "binary diff: " + message); }
class Digest {
public:
    void bytes(const u8* data, size_t count) {
        total_ += count;
        for (size_t i=0;i<count;++i) { block_[used_++]=data[i]; if(used_==64){transform();used_=0;} }
    }
    void number(u64 value) { u8 data[8];for(unsigned i=0;i<8;++i)data[i]=static_cast<u8>(value>>(i*8));bytes(data,8); }
    void text(const std::string& value) { number(value.size());bytes(reinterpret_cast<const u8*>(value.data()),value.size()); }
    std::string finish() {
        const u64 bits=total_*8;const u8 one=0x80;bytes(&one,1);const u8 zero=0;
        while(used_!=56)bytes(&zero,1);
        u8 length[8];for(unsigned i=0;i<8;++i)length[7-i]=static_cast<u8>(bits>>(i*8));bytes(length,8);
        char output[65];for(unsigned i=0;i<8;++i)std::snprintf(output+i*8,9,"%08x",state_[i]);
        return std::string(output,64);
    }
private:
    static u32 rotate(u32 x,unsigned n){return (x>>n)|(x<<(32-n));}
    void transform(){
        static constexpr u32 k[64]={
            0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
            0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
            0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
            0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
            0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
            0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
            0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
            0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
        u32 w[64];for(unsigned i=0;i<16;++i)w[i]=u32(block_[i*4])<<24|u32(block_[i*4+1])<<16|u32(block_[i*4+2])<<8|block_[i*4+3];
        for(unsigned i=16;i<64;++i){const u32 a=rotate(w[i-15],7)^rotate(w[i-15],18)^(w[i-15]>>3),b=rotate(w[i-2],17)^rotate(w[i-2],19)^(w[i-2]>>10);w[i]=w[i-16]+a+w[i-7]+b;}
        u32 a=state_[0],b=state_[1],c=state_[2],d=state_[3],e=state_[4],f=state_[5],g=state_[6],h=state_[7];
        for(unsigned i=0;i<64;++i){const u32 first=h+(rotate(e,6)^rotate(e,11)^rotate(e,25))+((e&f)^(~e&g))+k[i]+w[i];const u32 second=(rotate(a,2)^rotate(a,13)^rotate(a,22))+((a&b)^(a&c)^(b&c));h=g;g=f;f=e;e=d+first;d=c;c=b;b=a;a=first+second;}
        state_[0]+=a;state_[1]+=b;state_[2]+=c;state_[3]+=d;state_[4]+=e;state_[5]+=f;state_[6]+=g;state_[7]+=h;
    }
    std::array<u32,8> state_{{0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19}};
    std::array<u8,64> block_{};size_t used_=0;u64 total_=0;
};
std::string digest(const std::string& text) { Digest hash;hash.text(text);return hash.finish(); }
std::string hex(Address value){char out[32];std::snprintf(out,sizeof(out),"0x%llx",static_cast<unsigned long long>(value));return out;}
bool structural(const std::string& kind){return kind=="data"||kind=="function"||kind=="patch"||kind=="type-library"||kind=="signature-library"||kind=="prototype";}
using Symbols=std::map<Address,std::string>;
Symbols symbols(const Session& session){
    Symbols result;
    for(const auto& symbol:session.image().symbols())if(!symbol.undefined&&symbol.isFunction()&&!symbol.name.empty()){
        auto found=result.find(symbol.value);if(found==result.end()||symbol.name<found->second)result[symbol.value]=symbol.name;
    }
    for(const auto& stub:session.image().pltStubs())result[stub.first]=stub.second+"@plt";
    return result;
}
Status fingerprint(const Session& session,const Function& function,const Symbols& linkage,FunctionFingerprint* output){
    if(function.instructions.size()>kMaxFunctionInsns)return Status::error(ErrorCode::kTooLarge,"binary diff per-function instruction limit");
    FunctionFingerprint result;result.entry=function.entry;result.architecture=function.decodeArch==Arch::kUnknown?session.image().arch():function.decodeArch;
    result.name=session.nameAt(function.entry);const auto symbol=linkage.find(function.entry);if(symbol!=linkage.end())result.symbol=symbol->second;
    result.complete=!function.incomplete&&!function.instructions.empty();result.eligible=result.complete;
    Disassembler decoder;Status status=decoder.open(result.architecture);if(!status.ok())return status;
    Digest raw;std::ostringstream normalized,topology;normalized<<static_cast<unsigned>(result.architecture)<<'|';
    std::map<Address,size_t> ordinal;for(size_t i=0;i<function.instructions.size();++i)ordinal[function.instructions[i]]=i;
    for(Address address:function.instructions){
        const InsnRecord* record=session.analyzer().code().find(address);if(!record)return bad("function has missing instruction");
        const ByteView bytes=session.image().memory().viewAt(address,record->size);if(bytes.size()!=record->size)return bad("function instruction is not file-backed");
        DecodedInsn decoded;if(!decoder.decodeVerbose(address,bytes,&decoded)||decoded.record.size!=record->size||decoded.record.id!=record->id){result.eligible=false;decoded.mnemonic="invalid";decoded.operands="";}
        result.instructions.push_back({address,record->size});raw.number(record->size);raw.bytes(bytes.data(),bytes.size());
        std::string operands=decoded.operands,targetName;
        if(record->hasKnownTarget()){
            const auto internal=ordinal.find(record->target);const auto external=linkage.find(record->target);
            if(internal!=ordinal.end())targetName="instruction:"+std::to_string(internal->second);
            else if(external!=linkage.end())targetName="symbol:"+external->second;
            else{targetName="unidentified:"+hex(record->target);result.eligible=false;}
            if(record->flow==FlowKind::kCall||record->flow==FlowKind::kJump||record->flow==FlowKind::kCondJump){const auto comma=operands.find_last_of(',');operands=comma==std::string::npos?std::string():operands.substr(0,comma+1);}
        }
        normalized<<static_cast<unsigned>(record->size)<<':'<<static_cast<unsigned>(record->flow)<<':'<<record->id<<':'<<decoded.mnemonic<<':'<<operands<<':'<<targetName<<'\n';
        if(normalized.tellp()>static_cast<std::streampos>(kMaxNormalizedBytes))return Status::error(ErrorCode::kTooLarge,"binary diff normalized code limit");
    }
    topology<<function.cfg.entry()<<'|';
    for(const auto& block:function.cfg.blocks()){
        const auto start=ordinal.find(block.start);if(start==ordinal.end())return bad("CFG leader is not owned by its function");
        topology<<block.id<<':'<<start->second<<':'<<block.insnCount<<':'<<static_cast<unsigned>(block.terminator)<<'[';
        for(const auto& edge:block.successors)topology<<edge.target<<','<<static_cast<unsigned>(edge.kind)<<';';
        topology<<"]\n";
    }
    result.normalizedCode=normalized.str()+"CFG\n"+topology.str();result.exactHash=raw.finish();result.topologyHash=digest(topology.str());result.normalizedHash=digest(result.normalizedCode);
    *output=std::move(result);return Status::success();
}
}  // namespace

Status binaryIdentity(const Session& session,std::string* result){
    if(!result)return bad("missing identity output");
    if(!session.analyzed()||session.isDexLike())return Status::error(ErrorCode::kUnsupported,"binary diff requires analyzed native sessions");
    if(session.file().size()>kMaxInputBytes)return Status::error(ErrorCode::kTooLarge,"binary identity input exceeds 512 MiB");
    Digest hash;hash.text("mint-version-1");hash.text(MINT_ANALYSIS_ENGINE_ID);hash.text(session.image().formatName());hash.number(static_cast<u8>(session.image().arch()));
    hash.number(session.image().pointerSize());hash.number(session.image().entryPoint());hash.number(session.image().imageBase());hash.number(session.file().size());hash.bytes(session.file().view().data(),session.file().size());
    hash.text(session.program().get(0,"source"));
    size_t mappedBytes=0;
    for(const auto& segment:session.image().memory().segments()){
        if(segment.data.size()>kMaxInputBytes-mappedBytes)return Status::error(ErrorCode::kTooLarge,"binary identity mapped-byte limit");mappedBytes+=segment.data.size();
        hash.number(segment.start);hash.number(segment.size);hash.number(segment.flags);hash.number(segment.data.size());hash.text(segment.name);hash.bytes(segment.data.data(),segment.data.size());
    }
    for(const auto& annotation:session.program().annotations())if(structural(annotation.kind)){hash.number(annotation.address);hash.text(annotation.kind);hash.text(annotation.value);}
    hash.text(session.program().types().serialize());
    const auto& stats=session.analyzer().stats();hash.number(stats.reachedInstructionLimit);hash.number(stats.instructions);hash.number(stats.functions);
    for(const auto& record:session.analyzer().code().instructions()){hash.number(record.address);hash.number(record.id);hash.number(record.size);hash.number(static_cast<u8>(record.flow));hash.number(record.target);}
    for(const auto& function:session.analyzer().functions()){
        hash.number(function.entry);hash.number(static_cast<u8>(function.origin));hash.number(static_cast<u8>(function.decodeArch));hash.number(function.incomplete);hash.number(function.instructions.size());
        for(Address address:function.instructions)hash.number(address);
        hash.number(function.callees.size());for(Address address:function.callees)hash.number(address);
        hash.number(function.cfg.entry());hash.number(function.cfg.size());
        for(const auto& block:function.cfg.blocks()){hash.number(block.start);hash.number(block.end);hash.number(block.insnCount);hash.number(static_cast<u8>(block.terminator));hash.number(block.successors.size());for(const auto& edge:block.successors){hash.number(edge.target);hash.number(static_cast<u8>(edge.kind));}}
    }
    *result="mint-version-1:"+hash.finish();return Status::success();
}
Status fingerprintFunction(const Session& session,Address entry,FunctionFingerprint* result){
    if(!result)return bad("missing function fingerprint output");
    if(!session.analyzed()||session.isDexLike())return Status::error(ErrorCode::kUnsupported,"fingerprints require analyzed native sessions");
    const auto* function=session.analyzer().functionAt(entry);if(!function)return Status::error(ErrorCode::kNotFound,"binary diff function entry not found");
    return fingerprint(session,*function,symbols(session),result);
}
Status correspondInstructions(const Session& source,const Session& target,Address sourceEntry,Address targetEntry,
                              std::vector<InstructionCorrespondence>* output){
    if(!output)return bad("missing correspondence output");
    const auto* left=source.analyzer().functionAt(sourceEntry);const auto* right=target.analyzer().functionAt(targetEntry);
    if(!left||!right)return bad("correspondence requires current function entries");
    const auto arch=[&](const Session& session,const Function& function){return function.decodeArch==Arch::kUnknown?session.image().arch():function.decodeArch;};
    if(arch(source,*left)!=arch(target,*right))return bad("correspondence requires identical instruction modes");
    if(left->instructions.size()>20000||right->instructions.size()>20000)return Status::error(ErrorCode::kTooLarge,"instruction correspondence budget exceeded");
    struct Token {Address address,target;u8 size;FlowKind flow;std::string key;bool nop=false;};
    auto collect=[&](const Session& session,const Function& function,std::vector<Token>* result)->Status{
        Disassembler decoder;auto status=decoder.open(arch(session,function));if(!status.ok())return status;
        const auto linkage=symbols(session);
        for(Address address:function.instructions){
            const auto* record=session.analyzer().code().find(address);if(!record)return bad("correspondence instruction disappeared");
            const auto bytes=session.image().memory().viewAt(address,record->size);DecodedInsn decoded;
            if(!decoder.decodeVerbose(address,bytes,&decoded)||decoded.record.size!=record->size||decoded.record.id!=record->id)return bad("correspondence needs validated decoded instructions");
            std::string operands=decoded.operands,targetKey;
            if(record->hasKnownTarget()){
                // Only the encoded branch address is normalized, never data
                // constants or RIP/PC-relative memory operands.
                const auto comma=operands.find_last_of(',');operands=comma==std::string::npos?std::string():operands.substr(0,comma+1);
                if(std::binary_search(function.instructions.begin(),function.instructions.end(),record->target))targetKey="internal";
                else {const auto external=linkage.find(record->target);targetKey=external!=linkage.end()?"symbol:"+external->second:"address:"+hex(record->target);}
            }
            result->push_back({address,record->target,record->size,record->flow,std::to_string(record->id)+":"+std::to_string(record->size)+":"+std::to_string(static_cast<unsigned>(record->flow))+":"+decoded.mnemonic+":"+operands+":"+targetKey,decoded.mnemonic=="nop"&&record->flow==FlowKind::kNormal});
        }
        // Require an exact owning-block semantic context as well as the anchor.
        // NOP insertion and physical block movement are permitted, arbitrary
        // arithmetic/control changes are not silently declared equivalent.
        std::map<Address,std::string> contexts;
        for(const auto& block:function.cfg.blocks()){
            std::ostringstream code;code<<(block.id==function.cfg.entry())<<':'<<static_cast<unsigned>(block.terminator)<<':'<<block.predecessors.size()<<'|';std::vector<unsigned> kinds;for(const auto& edge:block.successors)kinds.push_back(static_cast<unsigned>(edge.kind));std::sort(kinds.begin(),kinds.end());for(auto kind:kinds)code<<kind<<',';code<<'\n';
            auto start=std::lower_bound(result->begin(),result->end(),block.start,[](const Token& token,Address address){return token.address<address;});for(auto at=start;at!=result->end()&&at->address<block.end;++at)if(!at->nop)code<<at->key<<'\n';const auto context=digest(code.str());for(auto at=start;at!=result->end()&&at->address<block.end;++at)contexts[at->address]=context;
        }for(auto& token:*result){const auto context=contexts.find(token.address);if(context==contexts.end())return bad("instruction has no owning CFG context");token.key+="|block:"+context->second;}return Status::success();
    };
    std::vector<Token> a,b;auto status=collect(source,*left,&a);if(!status.ok())return status;status=collect(target,*right,&b);if(!status.ok())return status;
    std::map<std::string,std::vector<size_t>> ai,bi;
    // A unique instruction is an anchor. Repeated tokens require an exact
    // three-instruction context, avoiding arbitrary LCS tie breaking.
    auto context=[](const std::vector<Token>& tokens,size_t i){std::string key;for(int d=-1;d<=1;++d){const auto at=static_cast<ptrdiff_t>(i)+d;key+=at<0?"<entry>":at>=static_cast<ptrdiff_t>(tokens.size())?"<exit>":tokens[at].key;key+='\n';}return key;};
    for(size_t i=0;i<a.size();++i)ai[a[i].key].push_back(i);for(size_t i=0;i<b.size();++i)bi[b[i].key].push_back(i);
    std::map<Address,Address> mapping;std::map<Address,std::string> evidence;
    for(const auto& item:ai){const auto other=bi.find(item.first);if(item.second.size()==1&&other!=bi.end()&&other->second.size()==1){mapping[a[item.second[0]].address]=b[other->second[0]].address;evidence[a[item.second[0]].address]="unique exact decoded semantics";}}
    std::map<std::string,std::vector<size_t>> ac,bc;for(size_t i=0;i<a.size();++i)if(!mapping.count(a[i].address))ac[context(a,i)].push_back(i);for(size_t i=0;i<b.size();++i)bc[context(b,i)].push_back(i);
    std::set<Address> used;for(const auto& pair:mapping)used.insert(pair.second);
    for(const auto& item:ac){const auto other=bc.find(item.first);if(item.second.size()==1&&other!=bc.end()&&other->second.size()==1&&!used.count(b[other->second[0]].address)){mapping[a[item.second[0]].address]=b[other->second[0]].address;used.insert(b[other->second[0]].address);evidence[a[item.second[0]].address]="unique exact decoded neighbourhood";}}
    // A direct internal transfer cannot be an anchor unless its target also
    // maps exactly. Iterate removal so branch-to-branch chains are validated.
    bool changed=true;while(changed){changed=false;for(const auto& token:a){auto found=mapping.find(token.address);if(found==mapping.end()||token.target==kNoAddress||!std::binary_search(left->instructions.begin(),left->instructions.end(),token.target))continue;const auto destination=std::lower_bound(b.begin(),b.end(),found->second,[](const Token& token,Address address){return token.address<address;});const auto targetMap=mapping.find(token.target);if(destination==b.end()||destination->address!=found->second||targetMap==mapping.end()||targetMap->second!=destination->target){mapping.erase(found);changed=true;}}}
    std::vector<InstructionCorrespondence> prepared;for(const auto& token:a){const auto found=mapping.find(token.address);if(found!=mapping.end())prepared.push_back({token.address,found->second,token.size,evidence[token.address]});}
    *output=std::move(prepared);return Status::success();
}
Status compareBinaries(const Session& source,const Session& target,BinaryDiff* result,size_t maxFunctions){
    if(!result)return bad("missing comparison output");
    if(!maxFunctions||maxFunctions>kMaxFunctions||source.analyzer().functions().size()>maxFunctions||target.analyzer().functions().size()>maxFunctions)return Status::error(ErrorCode::kTooLarge,"binary diff function budget exceeded");
    BinaryDiff prepared;Status status=binaryIdentity(source,&prepared.sourceIdentity);if(!status.ok())return status;status=binaryIdentity(target,&prepared.targetIdentity);if(!status.ok())return status;
    size_t memberships=0,textBytes=0;
    auto collect=[&](const Session& session,std::vector<FunctionFingerprint>* functions)->Status{
        const Symbols linkage=symbols(session);
        for(const auto& function:session.analyzer().functions()){
            if(function.instructions.size()>kMaxMemberships-memberships)return Status::error(ErrorCode::kTooLarge,"binary diff membership budget exceeded");memberships+=function.instructions.size();
            FunctionFingerprint fp;Status current=fingerprint(session,function,linkage,&fp);if(!current.ok())return current;
            if(fp.normalizedCode.size()>kMaxNormalizedBytes-textBytes)return Status::error(ErrorCode::kTooLarge,"binary diff normalized text budget exceeded");textBytes+=fp.normalizedCode.size();functions->push_back(std::move(fp));
        }return Status::success();
    };
    status=collect(source,&prepared.sourceFunctions);if(!status.ok())return status;status=collect(target,&prepared.targetFunctions);if(!status.ok())return status;
    std::vector<u8> usedSource(prepared.sourceFunctions.size(),0),usedTarget(prepared.targetFunctions.size(),0);
    using Index=std::map<std::string,std::vector<size_t>>;
    Index sourceSymbols,targetSymbols;
    for(size_t i=0;i<prepared.sourceFunctions.size();++i)if(!prepared.sourceFunctions[i].symbol.empty())sourceSymbols[prepared.sourceFunctions[i].symbol].push_back(i);
    for(size_t i=0;i<prepared.targetFunctions.size();++i)if(!prepared.targetFunctions[i].symbol.empty())targetSymbols[prepared.targetFunctions[i].symbol].push_back(i);
    auto match=[&](size_t left,size_t right,bool symbol){
        const auto& a=prepared.sourceFunctions[left];const auto& b=prepared.targetFunctions[right];const bool equal=a.eligible&&b.eligible&&a.normalizedCode==b.normalizedCode;
        const FunctionMatchKind kind=equal?(a.exactHash==b.exactHash?FunctionMatchKind::kExactCode:FunctionMatchKind::kNormalizedCode):FunctionMatchKind::kSymbolChanged;
        prepared.matches.push_back({a.entry,b.entry,kind,equal?(symbol?"unique linkage symbol + identical decoded code/CFG":"unique identical decoded code/CFG"):"unique linkage symbol only; code/constants/CFG changed or incompletely understood; manual confirmation required"});
        usedSource[left]=usedTarget[right]=1;
    };
    for(const auto& group:sourceSymbols){const auto other=targetSymbols.find(group.first);if(group.second.size()==1&&other!=targetSymbols.end()&&other->second.size()==1)match(group.second[0],other->second[0],true);}
    Index sourceCode,targetCode;
    for(size_t i=0;i<prepared.sourceFunctions.size();++i)if(!usedSource[i]&&prepared.sourceFunctions[i].eligible)sourceCode[prepared.sourceFunctions[i].normalizedHash].push_back(i);
    for(size_t i=0;i<prepared.targetFunctions.size();++i)if(!usedTarget[i]&&prepared.targetFunctions[i].eligible)targetCode[prepared.targetFunctions[i].normalizedHash].push_back(i);
    for(const auto& group:sourceCode){
        const auto other=targetCode.find(group.first);if(other==targetCode.end())continue;
        if(group.second.size()==1&&other->second.size()==1&&prepared.sourceFunctions[group.second[0]].normalizedCode==prepared.targetFunctions[other->second[0]].normalizedCode)match(group.second[0],other->second[0],false);
        else{
            AmbiguousFunctions ambiguity;ambiguity.reason="duplicate normalized decoded bodies/CFG; no unique one-to-one correspondence";
            for(size_t i:group.second)ambiguity.sources.push_back(prepared.sourceFunctions[i].entry);
            for(size_t i:other->second)ambiguity.targets.push_back(prepared.targetFunctions[i].entry);
            prepared.ambiguous.push_back(std::move(ambiguity));
        }
    }
    for(size_t i=0;i<usedSource.size();++i)if(!usedSource[i])prepared.unmatchedSource.push_back(prepared.sourceFunctions[i].entry);
    for(size_t i=0;i<usedTarget.size();++i)if(!usedTarget[i])prepared.unmatchedTarget.push_back(prepared.targetFunctions[i].entry);
    std::sort(prepared.matches.begin(),prepared.matches.end(),[](const FunctionMatch& a,const FunctionMatch& b){return a.source<b.source;});
    *result=std::move(prepared);return Status::success();
}
std::string binaryDiffText(const BinaryDiff& diff){
    std::ostringstream out;out<<"Native binary diff (decoded scalar code + CFG; constants retained)\nSource: "<<diff.sourceIdentity<<"\nTarget: "<<diff.targetIdentity<<"\nMatches: "<<diff.matches.size()<<"; ambiguity groups: "<<diff.ambiguous.size()<<"; unmatched: "<<diff.unmatchedSource.size()<<" / "<<diff.unmatchedTarget.size()<<"\n";
    for(const auto& match:diff.matches)out<<hex(match.source)<<" -> "<<hex(match.target)<<" ["<<(match.kind==FunctionMatchKind::kExactCode?"exact":match.kind==FunctionMatchKind::kNormalizedCode?"normalized":"symbol-only changed candidate")<<"] "<<match.evidence<<'\n';
    for(const auto& group:diff.ambiguous){out<<"Ambiguous source {";for(Address address:group.sources)out<<hex(address)<<' ';out<<"} target {";for(Address address:group.targets)out<<hex(address)<<' ';out<<"}: "<<group.reason<<'\n';}
    out<<"No annotations are transferred automatically. Confirm function pairs explicitly before transfer.\n";return out.str();
}
}  // namespace mint
