#include "mint/version/version_tracking.h"

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <map>
#include <set>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>

#include "mint/session.h"

namespace mint {
namespace {
constexpr size_t kMaxPairs=20000,kMaxTransfers=100000,kMaxFile=16*1024*1024;
constexpr u8 kMagic[8]={'M','I','N','T','V','T','0','1'};
Status bad(const std::string& message){return Status::error(ErrorCode::kBadFormat,"version tracking: "+message);}
Status io(const std::string& message){return Status::error(ErrorCode::kIoError,"version tracking: "+message+": "+std::strerror(errno));}
std::string hex(Address value){char text[32];std::snprintf(text,sizeof(text),"0x%llx",static_cast<unsigned long long>(value));return text;}
bool digestText(const std::string& value){if(value.size()!=64)return false;for(char c:value)if(!((c>='0'&&c<='9')||(c>='a'&&c<='f')))return false;return true;}
bool identityText(const std::string& value){return value.size()==79&&value.compare(0,15,"mint-version-1:")==0&&digestText(value.substr(15));}
bool transferable(const std::string& kind){return kind=="name"||kind=="comment"||kind=="bookmark"||kind=="prototype";}
u32 checksum(const u8* bytes,size_t size){u32 crc=0xffffffffu;for(size_t i=0;i<size;++i){crc^=bytes[i];for(unsigned bit=0;bit<8;++bit)crc=(crc>>1)^((crc&1)?0xedb88320u:0);}return crc^0xffffffffu;}
void integer(std::vector<u8>* data,u64 value,unsigned width){for(unsigned i=0;i<width;++i)data->push_back(static_cast<u8>(value>>(i*8)));}
void string(std::vector<u8>* data,const std::string& value){integer(data,value.size(),4);data->insert(data->end(),value.begin(),value.end());}
struct Reader{
    const std::vector<u8>& bytes;size_t pos=0;
    bool integer(unsigned width,u64* out){if(width>8||pos>bytes.size()||width>bytes.size()-pos)return false;u64 value=0;for(unsigned i=0;i<width;++i)value|=u64(bytes[pos++])<<(i*8);*out=value;return true;}
    bool string(std::string* out,size_t limit){u64 size=0;if(!integer(4,&size)||size>limit||size>bytes.size()-pos)return false;std::string value(reinterpret_cast<const char*>(bytes.data()+pos),static_cast<size_t>(size));pos+=static_cast<size_t>(size);if(value.find('\0')!=std::string::npos)return false;*out=std::move(value);return true;}
};
Status identities(const Session& source,const Session& target,const std::string& sourceId,const std::string& targetId){
    std::string actual;Status status=binaryIdentity(source,&actual);if(!status.ok())return status;if(actual!=sourceId)return bad("source binary/configuration/analysis changed");
    status=binaryIdentity(target,&actual);if(!status.ok())return status;if(actual!=targetId)return bad("target binary/configuration/analysis changed");return Status::success();
}
Status portable(const TrackingState& state){
    if(!identityText(state.sourceIdentity)||!identityText(state.targetIdentity)||state.confirmed.empty()||state.confirmed.size()>kMaxPairs)return bad("invalid identity or confirmed-pair count");
    std::set<Address> sources,targets;
    for(const auto& pair:state.confirmed){
        if(pair.source==kNoAddress||pair.target==kNoAddress||!sources.insert(pair.source).second||!targets.insert(pair.target).second||
            !digestText(pair.sourceCode)||!digestText(pair.targetCode)||!digestText(pair.sourceTopology)||!digestText(pair.targetTopology))return bad("invalid/non-one-to-one confirmed pair");
    }return Status::success();
}
bool correspondingAddress(const std::vector<InstructionCorrespondence>& correspondence,Address address,Address* mapped){
    auto after=std::upper_bound(correspondence.begin(),correspondence.end(),address,[](Address address,const InstructionCorrespondence& pair){return address<pair.source;});
    if(after==correspondence.begin())return false;const auto& pair=*(after-1);
    if(address-pair.source>=pair.size||pair.target>std::numeric_limits<Address>::max()-(address-pair.source))return false;
    *mapped=pair.target+(address-pair.source);return true;
}
}  // namespace

Status validateTracking(const Session& source,const Session& target,const TrackingState& state){
    Status status=portable(state);if(!status.ok())return status;status=identities(source,target,state.sourceIdentity,state.targetIdentity);if(!status.ok())return status;
    for(const auto& pair:state.confirmed){
        FunctionFingerprint left,right;status=fingerprintFunction(source,pair.source,&left);if(!status.ok())return status;status=fingerprintFunction(target,pair.target,&right);if(!status.ok())return status;
        if(left.architecture!=right.architecture||left.normalizedHash!=pair.sourceCode||right.normalizedHash!=pair.targetCode||left.topologyHash!=pair.sourceTopology||right.topologyHash!=pair.targetTopology)return bad("confirmed function code/topology/mode changed");
    }return Status::success();
}
Status confirmFunctionMatch(const Session& source,const Session& target,Address sourceEntry,Address targetEntry,TrackingState* state){
    if(!state)return bad("missing tracking output");
    TrackingState prepared=*state;
    if(prepared.confirmed.empty()){
        Status status=binaryIdentity(source,&prepared.sourceIdentity);if(!status.ok())return status;status=binaryIdentity(target,&prepared.targetIdentity);if(!status.ok())return status;
    }else{Status status=validateTracking(source,target,prepared);if(!status.ok())return status;}
    for(const auto& pair:prepared.confirmed){
        if(pair.source==sourceEntry&&pair.target==targetEntry)return Status::success();
        if(pair.source==sourceEntry||pair.target==targetEntry)return bad("manual match would not be one-to-one");
    }
    if(prepared.confirmed.size()>=kMaxPairs)return Status::error(ErrorCode::kTooLarge,"version tracking confirmed-pair limit");
    FunctionFingerprint left,right;Status status=fingerprintFunction(source,sourceEntry,&left);if(!status.ok())return status;status=fingerprintFunction(target,targetEntry,&right);if(!status.ok())return status;
    if(left.architecture!=right.architecture)return bad("manual matches require the same instruction architecture/mode");
    prepared.confirmed.push_back({sourceEntry,targetEntry,left.normalizedHash,right.normalizedHash,left.topologyHash,right.topologyHash});
    std::sort(prepared.confirmed.begin(),prepared.confirmed.end(),[](const ConfirmedFunctionMatch& a,const ConfirmedFunctionMatch& b){return a.source<b.source;});
    *state=std::move(prepared);return Status::success();
}
Status saveTracking(const Session& source,const Session& target,const TrackingState& state,const std::string& path){
    Status status=validateTracking(source,target,state);if(!status.ok())return status;
    if(path.empty()||path.size()>4000||path.find('\0')!=std::string::npos)return bad("invalid destination path");
    std::vector<u8> payload;string(&payload,state.sourceIdentity);string(&payload,state.targetIdentity);integer(&payload,state.confirmed.size(),4);
    for(const auto& pair:state.confirmed){integer(&payload,pair.source,8);integer(&payload,pair.target,8);string(&payload,pair.sourceCode);string(&payload,pair.targetCode);string(&payload,pair.sourceTopology);string(&payload,pair.targetTopology);}
    if(payload.size()>kMaxFile-24)return Status::error(ErrorCode::kTooLarge,"version tracking file limit");
    std::vector<u8> bytes(kMagic,kMagic+8);integer(&bytes,1,4);integer(&bytes,payload.size(),8);integer(&bytes,checksum(payload.data(),payload.size()),4);bytes.insert(bytes.end(),payload.begin(),payload.end());
    std::string candidate=path+".candidate-XXXXXX";int fd=::mkstemp(candidate.data());if(fd<0)return io("create candidate");
    bool ok=true;size_t written=0;
    while(written<bytes.size()){const ssize_t count=::write(fd,bytes.data()+written,bytes.size()-written);if(count<0&&errno==EINTR)continue;if(count<=0){ok=false;break;}written+=static_cast<size_t>(count);}
    if(ok&&::fsync(fd)!=0)ok=false;if(::close(fd)!=0)ok=false;
    if(!ok){const auto error=io("write candidate");::unlink(candidate.c_str());return error;}
    // Hard-link publication is atomic and create-only, unlike rename-overwrite.
    if(::link(candidate.c_str(),path.c_str())!=0){const auto error=io("publish new tracking file (destination must not exist)");::unlink(candidate.c_str());return error;}
    ::unlink(candidate.c_str());return Status::success();
}
Status loadTracking(const Session& source,const Session& target,const std::string& path,TrackingState* state){
    if(!state)return bad("missing tracking output");
    if(path.empty()||path.size()>4000||path.find('\0')!=std::string::npos)return bad("invalid source path");
    const int fd=::open(path.c_str(),O_RDONLY|O_CLOEXEC);if(fd<0)return io("open tracking file");
    struct stat metadata{};
    if(::fstat(fd,&metadata)!=0||!S_ISREG(metadata.st_mode)||metadata.st_size<24||static_cast<u64>(metadata.st_size)>kMaxFile){::close(fd);return bad("tracking file size/type limit");}
    std::vector<u8> bytes(static_cast<size_t>(metadata.st_size));size_t read=0;bool ok=true;
    while(read<bytes.size()){const ssize_t count=::read(fd,bytes.data()+read,bytes.size()-read);if(count<0&&errno==EINTR)continue;if(count<=0){ok=false;break;}read+=static_cast<size_t>(count);}
    u8 extra=0;ssize_t count;do{count=::read(fd,&extra,1);}while(count<0&&errno==EINTR);if(count!=0)ok=false;::close(fd);
    if(!ok)return bad("tracking file was truncated/changed while reading");
    if(!std::equal(kMagic,kMagic+8,bytes.begin()))return bad("tracking magic mismatch");
    Reader reader{bytes,8};u64 version=0,size=0,crc=0;
    if(!reader.integer(4,&version)||version!=1||!reader.integer(8,&size)||size!=bytes.size()-24||!reader.integer(4,&crc)||crc!=checksum(bytes.data()+24,bytes.size()-24))return bad("tracking version/length/checksum mismatch");
    TrackingState prepared;u64 pairs=0;
    if(!reader.string(&prepared.sourceIdentity,256)||!reader.string(&prepared.targetIdentity,256)||!reader.integer(4,&pairs)||!pairs||pairs>kMaxPairs)return bad("tracking identity/pair count");
    for(u64 i=0;i<pairs;++i){ConfirmedFunctionMatch pair;if(!reader.integer(8,&pair.source)||!reader.integer(8,&pair.target)||!reader.string(&pair.sourceCode,64)||!reader.string(&pair.targetCode,64)||!reader.string(&pair.sourceTopology,64)||!reader.string(&pair.targetTopology,64))return bad("truncated/invalid confirmed pair");prepared.confirmed.push_back(std::move(pair));}
    if(reader.pos!=bytes.size())return bad("trailing tracking data");
    Status status=validateTracking(source,target,prepared);if(!status.ok())return status;*state=std::move(prepared);return Status::success();
}
Status planAnnotationTransfer(const Session& source,const Session& target,const TrackingState& state,TransferPlan* plan){
    if(!plan)return bad("missing transfer plan output");
    Status status=validateTracking(source,target,state);if(!status.ok())return status;
    TransferPlan prepared;prepared.sourceIdentity=state.sourceIdentity;prepared.targetIdentity=state.targetIdentity;prepared.authorization=state;
    std::set<std::pair<Address,std::string>> scheduled;
    std::vector<std::vector<InstructionCorrespondence>> correspondence(state.confirmed.size());
    size_t totalMappings=0;
    for(size_t i=0;i<state.confirmed.size();++i){const auto& pair=state.confirmed[i];status=correspondInstructions(source,target,pair.source,pair.target,&correspondence[i]);if(!status.ok())return status;totalMappings+=correspondence[i].size();if(totalMappings>1000000)return Status::error(ErrorCode::kTooLarge,"version tracking correspondence budget exceeded");}
    size_t mappingChecks=0;
    for(const auto& annotation:source.program().annotations()){
        if(!transferable(annotation.kind))continue;
        if(prepared.edits.size()+prepared.skipped.size()>=kMaxTransfers)return Status::error(ErrorCode::kTooLarge,"version tracking annotation budget exceeded");
        const Function* from=nullptr;const Function* to=nullptr;Address mapped=kNoAddress;size_t candidates=0;
        for(size_t i=0;i<state.confirmed.size();++i){const auto& pair=state.confirmed[i];
            if(++mappingChecks>8000000)return Status::error(ErrorCode::kTooLarge,"version tracking instruction-offset mapping budget exceeded");
            const Function* candidateSource=source.analyzer().functionAt(pair.source);const Function* candidateTarget=target.analyzer().functionAt(pair.target);Address destination=0;
            const bool prototypeEntry=annotation.kind=="prototype"&&candidateSource&&candidateTarget&&annotation.address==candidateSource->entry;
            if(candidateSource&&candidateTarget&&(prototypeEntry||(correspondingAddress(correspondence[i],annotation.address,&destination)&&target.image().memory().isMapped(destination)))){
                if(prototypeEntry)destination=candidateTarget->entry;
                ++candidates;from=candidateSource;to=candidateTarget;mapped=destination;
            }
        }
        if(candidates!=1){prepared.skipped.push_back({annotation.address,kNoAddress,annotation.kind,candidates?"shared instruction has multiple confirmed mappings":"annotation is not inside an offset-corresponding matched instruction"});continue;}
        if(annotation.kind=="prototype"&&(annotation.address!=from->entry||mapped!=to->entry)){prepared.skipped.push_back({annotation.address,mapped,annotation.kind,"prototype requires corresponding function entries"});continue;}
        if(!target.annotation(mapped,annotation.kind).empty()){prepared.skipped.push_back({annotation.address,mapped,annotation.kind,"existing target edit preserved"});continue;}
        if(!scheduled.insert({mapped,annotation.kind}).second){prepared.skipped.push_back({annotation.address,mapped,annotation.kind,"duplicate destination annotation"});continue;}
        prepared.edits.push_back({annotation.address,mapped,annotation.kind,annotation.value});
    }
    *plan=std::move(prepared);return Status::success();
}
Status applyAnnotationTransfer(const Session& source,Session* target,const TransferPlan& plan,TransferResult* result){
    if(!target||!result)return bad("missing transfer target/result");*result={};result->skipped=plan.skipped.size();
    if(plan.sourceIdentity!=plan.authorization.sourceIdentity||plan.targetIdentity!=plan.authorization.targetIdentity)return bad("transfer plan has no matching manual authorization");
    TransferPlan expected;
    Status status=planAnnotationTransfer(source,*target,plan.authorization,&expected);if(!status.ok())return status;
    if(plan.edits.size()>kMaxTransfers)return Status::error(ErrorCode::kTooLarge,"version tracking annotation budget exceeded");
    std::set<std::pair<Address,std::string>> scheduled;
    std::map<std::pair<Address,std::string>,const AnnotationTransfer*> authorized;
    for(const auto& edit:expected.edits)authorized[{edit.target,edit.kind}]=&edit;
    for(const auto& edit:plan.edits){
        const auto grant=authorized.find({edit.target,edit.kind});
        if(grant==authorized.end()||grant->second->source!=edit.source||grant->second->value!=edit.value)return bad("transfer edit is outside the manually confirmed instruction mapping");
        if(!transferable(edit.kind)||edit.value.empty()||edit.value.size()>4096||!source.image().memory().isMapped(edit.source)||!target->image().memory().isMapped(edit.target)||
            source.annotation(edit.source,edit.kind)!=edit.value||!target->annotation(edit.target,edit.kind).empty()||!scheduled.insert({edit.target,edit.kind}).second)return bad("transfer plan became stale/invalid; no target edits changed");
    }
    for(const auto& edit:plan.edits){
        status=target->editAnnotation(edit.target,edit.kind,edit.value);
        if(!status.ok()){
            const size_t completed=result->applied;
            for(size_t i=0;i<completed;++i){const Status rollback=target->undoEdit(false);if(!rollback.ok())return Status::error(ErrorCode::kIoError,"version tracking edit failed and rollback failed; "+std::to_string(completed-i)+" transferred edits may remain");}
            result->applied=0;result->rolledBack=completed!=0;return status;
        }
        ++result->applied;
    }
    return Status::success();
}
std::string trackingText(const TrackingState& state){std::ostringstream out;out<<"Manually confirmed one-to-one version matches\nSource: "<<state.sourceIdentity<<"\nTarget: "<<state.targetIdentity<<'\n';for(const auto& pair:state.confirmed)out<<hex(pair.source)<<" -> "<<hex(pair.target)<<" [manual; code/CFG fingerprints pinned]\n";return out.str();}
std::string transferPlanText(const TransferPlan& plan){
    std::ostringstream out;out<<"Annotation transfer: "<<plan.edits.size()<<" applicable; "<<plan.skipped.size()<<" skipped. Patches/types/structural decisions excluded.\n";
    auto preview=[](const std::string& value){std::string text;const size_t limit=std::min<size_t>(value.size(),512);for(size_t n=0;n<limit;++n){const unsigned char c=value[n];if(c=='\n')text+="\\n";else if(c=='\r')text+="\\r";else if(c=='\t')text+="\\t";else if(c=='\\')text+="\\\\";else if(c<32 || c==127)text+='?';else text+=static_cast<char>(c);}if(value.size()>limit)text+=" [truncated preview; "+std::to_string(value.size())+" bytes total]";return text;};
    for(const auto& edit:plan.edits){out<<hex(edit.source)<<" -> "<<hex(edit.target)<<" "<<edit.kind<<" = "<<preview(edit.value)<<'\n';if(out.tellp()>1024*1024){out<<"Additional transfer entries omitted by the 1 MiB report limit.\n";return out.str();}}
    for(const auto& issue:plan.skipped){out<<"Skipped "<<hex(issue.source)<<" "<<issue.kind<<": "<<issue.reason<<'\n';if(out.tellp()>1024*1024){out<<"Additional skipped entries omitted by the 1 MiB report limit.\n";break;}}
    return out.str();
}
}  // namespace mint
