#include "mint/session.h"
#include <iomanip>
#include <sstream>
#include <sys/stat.h>
#include <limits>

namespace mint {
void Session::notifyPluginEvent(u32 kind,Address address,const std::string& detail) {
    const MintPluginEventV2 event{sizeof(MintPluginEventV2),kind,address,detail.c_str()};std::string output;
    const auto status=plugins_.dispatchEvent(*this,event,&output);
    if(!status.ok() && pluginEventWarnings_.size()<64)pluginEventWarnings_.push_back("Plugin observer: "+status.toString());
}
Status Session::connectDebugger(const std::string& host,u32 port,bool dap,bool allowRemote) {
    if(port==0 || port>65535)return Status::error(ErrorCode::kBadFormat,"port must be 1..65535");
    DebuggerEndpoint endpoint{host,static_cast<u16>(port),allowRemote};
    return debugger_.connectTcp(endpoint,dap?DebuggerBackend::kLldbDap:DebuggerBackend::kGdbRemote);
}
Status Session::debuggerCommand(const std::string& operation,Address address,u64 value,std::string* output) {
    if(!output)return Status::error(ErrorCode::kInternalError,"missing debugger output");
    Status status=Status::success();std::ostringstream text;
    if(operation=="disconnect")debugger_.disconnect();
    else if(operation=="status"){}
    else if(operation=="attach")status=debugger_.attachProcess(value);
    else if(operation=="step")status=debugger_.step();
    else if(operation=="continue")status=debugger_.resume();
    else if(operation=="interrupt")status=debugger_.interrupt();
    else if(operation=="wait")status=debugger_.waitForStop();
    else if(operation=="threads") {
        std::vector<DebuggerThread> threads;status=debugger_.threads(&threads);
        if(status.ok())for(const auto& thread:threads)text<<thread.id<<'\t'<<(thread.selected?"* ":"")<<thread.name<<'\n';
    } else if(operation=="thread")status=debugger_.selectThread(value);
    else if(operation=="stack") {
        std::vector<DebuggerFrame> frames;status=debugger_.stackFrames(value?static_cast<size_t>(std::min<u64>(value,256)):64,&frames);
        if(status.ok())for(const auto& frame:frames){Address mapped=kNoAddress;const auto mapping=debugger_.runtimeToImage(frame.pc,&mapped);
            text<<frame.id<<"\truntime 0x"<<std::hex<<frame.pc;
            if(mapping.ok())text<<"\timage 0x"<<mapped;else text<<"\tunmapped";
            text<<"\t"<<frame.name<<"\t"<<frame.source<<":"<<std::dec<<frame.line<<'\n';}
    } else if(operation=="modules") {
        std::vector<DebuggerModule> modules;status=debugger_.modules(&modules);
        if(status.ok())for(const auto& module:modules){text<<module.id<<'\t'<<module.name<<'\t'<<module.path;
            if(module.start!=kNoAddress)text<<"\t[0x"<<std::hex<<module.start<<", 0x"<<module.end<<")";text<<'\n';}
    } else if(operation=="layout")status=debugger_.discoverRegisterLayout();
    else if(operation=="map-image") {
        if(!loaded_ || isDexLike())return Status::error(ErrorCode::kUnsupported,"address mapping requires a native Program");
        std::vector<DebuggerImageMapping> mappings;
        for(const auto& segment:image_.memory().segments()) {
            if(segment.start<image_.imageBase())return Status::error(ErrorCode::kBadFormat,"segment precedes image base");
            const auto delta=segment.start-image_.imageBase();
            if(delta>std::numeric_limits<Address>::max()-address || segment.size>std::numeric_limits<Address>::max()-(address+delta))return Status::error(ErrorCode::kBadFormat,"runtime mapping overflows");
            mappings.push_back({segment.start,address+delta,segment.size,"explicit current Program"});
        }
        status=debugger_.setImageMappings(mappings);
        if(status.ok())text<<"Mapped image base 0x"<<std::hex<<image_.imageBase()<<" to explicitly supplied runtime base 0x"<<address<<". Verify the loaded module is this binary.\n";
    } else if(operation=="unmap")status=debugger_.setImageMappings({});
    else if(operation=="pc" || operation=="pc-image") {
        Address runtime=kNoAddress;status=debugger_.programCounter(&runtime);
        if(status.ok()) {Address mapped=runtime;if(operation=="pc-image")status=debugger_.runtimeToImage(runtime,&mapped);
            if(status.ok())text<<"0x"<<std::hex<<mapped<<"\t"<<(operation=="pc-image"?"image":"runtime")<<" PC\n";}
    }
    else if(operation=="registers") {
        std::vector<DebuggerRegister> registers;status=debugger_.readRegisters(&registers);
        if(status.ok())for(const auto& reg:registers)text<<reg.name<<" = "<<(reg.available?reg.value:"<unavailable>")<<'\n';
    } else if(operation=="memory" || operation=="memory-image") {
        if(!value || value>DebuggerClient::kMaxMemoryRead)return Status::error(ErrorCode::kTooLarge,"memory length must be 1..16384");
        if(value-1>std::numeric_limits<Address>::max()-address)return Status::error(ErrorCode::kBadFormat,"memory range overflows");
        Address runtime=address;if(operation=="memory-image"){status=debugger_.imageToRuntime(address,&runtime);if(!status.ok())return status;Address last=0;status=debugger_.imageToRuntime(address+value-1,&last);if(!status.ok() || last-runtime!=value-1)return Status::error(ErrorCode::kBadFormat,"memory read crosses address mappings");}
        std::vector<u8> bytes;status=debugger_.readMemory(runtime,static_cast<size_t>(value),&bytes);
        if(status.ok())for(size_t i=0;i<bytes.size();++i) {
            if(i%16==0)text<<"0x"<<std::hex<<(address+i)<<"  ";
            text<<std::setfill('0')<<std::setw(2)<<static_cast<unsigned>(bytes[i])<<' ';
            if(i%16==15 || i+1==bytes.size())text<<'\n';
        }
    } else if(operation=="break" || operation=="unbreak" || operation=="break-image" || operation=="unbreak-image") {
        const bool imageAddress=operation=="break-image" || operation=="unbreak-image";
        const auto canonical=isDexLike()?address:image_.canonicalAddress(address);Address runtime=address;
        if(imageAddress){status=debugger_.imageToRuntime(canonical,&runtime);if(!status.ok())return status;}
        Address staticAddress=canonical;if(!imageAddress && !debugger_.runtimeToImage(address,&staticAddress).ok())staticAddress=kNoAddress;
        const auto mode=isDexLike()?Arch::kUnknown:image_.architectureAt(staticAddress==kNoAddress?image_.entryPoint():staticAddress);
        u32 width=mode==Arch::kAArch64 || mode==Arch::kArm32?4:mode==Arch::kThumb?2:1;
        if(mode==Arch::kRiscV32 || mode==Arch::kRiscV64){u16 halfword=0;if(staticAddress==kNoAddress || !image_.memory().readInt(staticAddress,&halfword))return Status::error(ErrorCode::kBadFormat,"RISC-V breakpoint requires an explicit image mapping and mapped instruction bytes");width=(halfword&3)==3?4:2;}
        status=debugger_.setBreakpoint(runtime,operation=="break" || operation=="break-image",width);
    } else return Status::error(ErrorCode::kBadFormat,"unknown debugger operation");
    if(!status.ok())return status;
    text<<debuggerSnapshotText(debugger_.snapshot());*output=text.str();return Status::success();
}
Status Session::openComparison(const std::string& path,const std::string& projectPath,Arch rawArch,Address base,Address entry,bool machOSlice) {
    if(!analyzed_ || isDexLike())return Status::error(ErrorCode::kBadFormat,"comparison requires an analyzed native Program");
    if(!projectPath.empty()) {
        struct stat current{},candidate{};
        const bool sameFile=::stat(projectPath.c_str(),&candidate)==0 && ::stat(program_.path().c_str(),&current)==0 && candidate.st_dev==current.st_dev && candidate.st_ino==current.st_ino;
        if(projectPath==program_.path() || sameFile)return Status::error(ErrorCode::kBadFormat,"comparison must use a different project to avoid concurrent edits");
    }
    auto candidate=std::make_unique<Session>();
    auto status=machOSlice?candidate->openMachOPath(path,rawArch):rawArch==Arch::kUnknown?candidate->openPath(path):candidate->openRawPath(path,rawArch,base,entry);
    if(!status.ok())return status;
    if(candidate->isDexLike())return Status::error(ErrorCode::kUnsupported,"comparison supports native binaries, not DEX/APK");
    if(candidate->image().arch()!=image_.arch())return Status::error(ErrorCode::kUnsupported,"comparison requires matching architectures");
    if(!projectPath.empty()){status=candidate->attachProject(projectPath);if(!status.ok())return status;}
    status=candidate->analyze();if(!status.ok())return status;
    comparison_=std::move(candidate);tracking_={};return Status::success();
}
Status Session::comparisonCommand(const std::string& operation,Address source,Address target,const std::string& path,std::string* output) {
    if(!output)return Status::error(ErrorCode::kInternalError,"missing comparison output");
    if(!comparison_)return Status::error(ErrorCode::kBadFormat,"open a comparison Program first");
    Status status=Status::success();std::string text;
    if(operation=="diff") {BinaryDiff diff;status=compareBinaries(*this,*comparison_,&diff);if(status.ok())text=binaryDiffText(diff);}
    else if(operation=="confirm") {status=confirmFunctionMatch(*this,*comparison_,source,target,&tracking_);if(status.ok())text=trackingText(tracking_);}
    else if(operation=="tracking")text=trackingText(tracking_);
    else if(operation=="save") {status=saveTracking(*this,*comparison_,tracking_,path);if(status.ok())text="Saved confirmed matches. Existing files were not overwritten.\n";}
    else if(operation=="load") {status=loadTracking(*this,*comparison_,path,&tracking_);if(status.ok())text=trackingText(tracking_);}
    else if(operation=="preview" || operation=="apply") {
        if(operation=="preview" && tracking_.confirmed.empty()){
            *output="Annotation transfer: 0 applicable; no confirmed function pairs. Diff candidates do not authorize edits. Confirm exact source/target function pairs first.\n";return Status::success();
        }
        TransferPlan plan;status=planAnnotationTransfer(*this,*comparison_,tracking_,&plan);
        if(status.ok()) {
            text=transferPlanText(plan);
            if(operation=="apply") {TransferResult result;status=applyAnnotationTransfer(*this,comparison_.get(),plan,&result);text+="Applied: "+std::to_string(result.applied)+"; skipped: "+std::to_string(result.skipped)+"\n";}
        }
    } else return Status::error(ErrorCode::kBadFormat,"unknown comparison operation");
    if(!status.ok())return status;*output=std::move(text);return Status::success();
}
} // namespace mint
