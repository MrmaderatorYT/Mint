#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "mint/analysis/exception_metadata.h"
#include "mint/analysis/cxx_metadata.h"
#include "mint/analysis/code_analyzer.h"
#include "mint/base/mapped_file.h"

using namespace mint;
namespace {
size_t checks=0;
void require(bool good,const char* message) { ++checks;if(!good){std::fprintf(stderr,"exception metadata: %s\n",message);std::exit(1);} }
void success(const Status& status,const char* message){if(!status.ok())std::fprintf(stderr,"%s\n",status.toString().c_str());require(status.ok(),message);}
void integer(std::vector<u8>* bytes,u64 value,size_t width){for(size_t i=0;i<width;++i)bytes->push_back(static_cast<u8>(value>>(i*8)));}
void set(std::vector<u8>* bytes,size_t at,u64 value,size_t width){require(at+width<=bytes->size(),"fixture integer bounds");for(size_t i=0;i<width;++i)(*bytes)[at+i]=static_cast<u8>(value>>(i*8));}
std::vector<u8> frames(size_t width,bool extended=false,unsigned version=1){
    std::vector<u8> bytes;
    auto begin=[&](){const size_t at=bytes.size();if(extended){integer(&bytes,0xffffffffu,4);integer(&bytes,0,8);}else integer(&bytes,0,4);return at;};
    auto end=[&](size_t at){const size_t header=extended?12:4;set(&bytes,at+(extended?4:0),bytes.size()-at-header,extended?8:4);};
    const size_t cie=begin();integer(&bytes,0,4);bytes.push_back(static_cast<u8>(version));
    bytes.insert(bytes.end(),{'z','L','R',0});if(version==4){bytes.push_back(static_cast<u8>(width));bytes.push_back(0);}
    bytes.insert(bytes.end(),{1,0x78,16,2,0,0x1b});end(cie);
    const size_t fde=begin(),link=bytes.size();integer(&bytes,link-cie,4);
    const Address pcField=0x3000+bytes.size();integer(&bytes,0x1000-pcField,4);integer(&bytes,0x20,4);
    bytes.push_back(static_cast<u8>(width));integer(&bytes,0x5000,width);end(fde);integer(&bytes,0,4);return bytes;
}
std::vector<u8> lsda(size_t width,u8 typeEncoding=0,Address type=0){
    std::vector<u8> bytes{0xff,typeEncoding,0,1,12,
        0,4,16,1, 4,4,20,3, 8,4,0,0, // Ordered ranges, two landing pads and no handler.
        0,0,1,0}; // Cleanup and catch(index1).
    const size_t typeAt=bytes.size();
    if(typeEncoding==0x9b)integer(&bytes,0x7000-(0x5000+typeAt),4);
    else integer(&bytes,type,width);
    bytes[2]=static_cast<u8>(bytes.size()-3);return bytes;
}
struct Fixture {
    size_t width;
    std::vector<u8> code=std::vector<u8>(64,0xc3),eh,exceptions,type=std::vector<u8>(32,0),slot=std::vector<u8>(8,0);
    MemoryMap memory;
    explicit Fixture(size_t pointerWidth,u8 typeEncoding=0,Address typeAddress=0,bool extended=false,unsigned version=1)
        :width(pointerWidth),eh(frames(pointerWidth,extended,version)),exceptions(lsda(pointerWidth,typeEncoding,typeAddress)) {
        memory.addSegment(0x1000,code.size(),{code.data(),code.size()},kMemRead|kMemExec,"code");
        memory.addSegment(0x3000,eh.size(),{eh.data(),eh.size()},kMemRead,".eh_frame");
        memory.addSegment(0x5000,exceptions.size(),{exceptions.data(),exceptions.size()},kMemRead,".gcc_except_table");
        memory.addSegment(0x6000,type.size(),{type.data(),type.size()},kMemRead,"typeinfo");
        memory.addSegment(0x7000,slot.size(),{slot.data(),slot.size()},kMemRead,"unresolved GOT");memory.finalize();
    }
    UnwindFrame frame(){std::vector<UnwindFrame> result;success(parseEhFrameSection({eh.data(),eh.size()},0x3000,memory,width,10,&result),"decode CIE/FDE");require(result.size()==1,"one validated FDE");return result[0];}
};
void synthetic(size_t width,bool extended,unsigned version){
    Fixture f(width,0,0,extended,version);const auto frame=f.frame();
    require(frame.entry==0x1000 && frame.end==0x1020 && frame.cie==0x3000 && frame.lsda==0x5000,"validated entry/extent/LSDA provenance");
    ExceptionFunction result;success(parseExceptionLsda({f.exceptions.data(),f.exceptions.size()},0x5000,f.memory,width,frame,10,&result),"parse cleanup/catch callsites");
    require(result.callSites.size()==3 && result.callSites[0].start==0x1000 && result.callSites[0].end==0x1004 && result.callSites[0].landingPad==0x1010,"callsite offset and landing pad mapping");
    require(result.callSites[0].actions.size()==1 && result.callSites[0].actions[0].filter==0,"cleanup action");
    require(result.callSites[1].actions[0].filter==1 && result.callSites[1].actions[0].catchAll && result.callSites[1].actions[0].typeResolved,"encoded null is catch all");
    require(result.callSites[2].landingPad==kNoAddress && result.callSites[2].actions.empty(),"missing landing pad explicit");
    require(result.landingPads.size()==2 && result.landingPads[0].regions.size()==1 && result.landingPads[0].regions[0].cleanup &&
        result.landingPads[1].regions[0].catchAll && result.callSites[result.landingPads[1].regions[0].callSiteIndex].actions.size()==1,"protected regions grouped by verified landing pad with ordered cleanup/catch dispatch");
    for(size_t size=0;size<f.exceptions.size();++size){result.callSites.push_back({});require(!parseExceptionLsda({f.exceptions.data(),size},0x5000,f.memory,width,frame,10,&result).ok() && result.callSites.empty(),"LSDA truncation fails transactionally");}
    std::vector<UnwindFrame> decoded;
    for(size_t size=0;size<f.eh.size();++size){const auto status=parseEhFrameSection({f.eh.data(),size},0x3000,f.memory,width,10,&decoded);require(status.ok()?decoded.size()<=1:decoded.empty(),"framing truncation never fabricates records");}
    auto corrupt=f.eh;set(&corrupt,0,0xfffffff0u,4);require(!parseEhFrameSection({corrupt.data(),corrupt.size()},0x3000,f.memory,width,10,&decoded).ok() && decoded.empty(),"reserved record size rejected");
    corrupt=f.eh;const size_t cieLength=extended?12+4+1+4+(version==4?2:0)+6:4+4+1+4+(version==4?2:0)+6;
    set(&corrupt,cieLength+(extended?12:4),0xffffffffu,4);std::vector<std::string> notes;
    success(parseEhFrameSection({corrupt.data(),corrupt.size()},0x3000,f.memory,width,10,&decoded,&notes),"invalid backward CIE link excluded");require(decoded.empty()&&!notes.empty(),"invalid FDE has explicit note");
    require(!parseEhFrameSection({f.eh.data(),f.eh.size()},0x3000,f.memory,width,0,&decoded).ok(),"FDE count bounded");
    require(!parseExceptionLsda({f.exceptions.data(),f.exceptions.size()},0x5000,f.memory,width,frame,2,&result).ok(),"callsite count bounded");
    auto bad=f.exceptions;bad[5]=31;require(!parseExceptionLsda({bad.data(),bad.size()},0x5000,f.memory,width,frame,10,&result).ok(),"unsorted/out-of-range callsite rejected");
    bad=f.exceptions;bad[7]=127;require(!parseExceptionLsda({bad.data(),bad.size()},0x5000,f.memory,width,frame,10,&result).ok(),"unmapped landing pad rejected");
    bad=f.exceptions;bad[8]=127;require(!parseExceptionLsda({bad.data(),bad.size()},0x5000,f.memory,width,frame,10,&result).ok(),"action index outside table rejected");
    bad=f.exceptions;bad[18]=0x7f;require(!parseExceptionLsda({bad.data(),bad.size()},0x5000,f.memory,width,frame,10,&result).ok(),"cyclic action chain rejected");
    bad=f.exceptions;bad[3]=0x31;require(!parseExceptionLsda({bad.data(),bad.size()},0x5000,f.memory,width,frame,10,&result).ok(),"unknown data-relative callsite base rejected");
}
void types(){
    Fixture direct(8,0,0x6000);ExceptionFunction result;
    success(parseExceptionLsda({direct.exceptions.data(),direct.exceptions.size()},0x5000,direct.memory,8,direct.frame(),10,&result),"direct catch type");
    require(result.callSites[1].actions[0].typeInfo==0x6000 && !result.callSites[1].actions[0].catchAll,"mapped catch type is not catch all");
    Fixture indirect(8,0x9b);
    success(parseExceptionLsda({indirect.exceptions.data(),indirect.exceptions.size()},0x5000,indirect.memory,8,indirect.frame(),10,&result),"unresolved relocated type pointer");
    require(!result.callSites[1].actions[0].typeResolved && !result.callSites[1].actions[0].catchAll && result.callSites[1].actions[0].indirectSlot==0x7000,"zero unresolved GOT import never becomes catch all");
    auto chain=direct.exceptions;chain[18]=1; // nextField18 +1 -> catch record19.
    success(parseExceptionLsda({chain.data(),chain.size()},0x5000,direct.memory,8,direct.frame(),10,&result),"relative chained action");
    require(result.callSites[0].actions.size()==2 && result.callSites[0].actions[1].filter==1,"action displacement base is next field, not end of field");
    auto negative=direct.exceptions;negative[19]=0x7f;
    success(parseExceptionLsda({negative.data(),negative.size()},0x5000,direct.memory,8,direct.frame(),10,&result),"negative legacy filter inventory");require(!result.notes.empty(),"unsupported exception specification explicitly noted");
}
void real(const char* path){
    MappedFile file;success(file.open(path),"open real clang C++ fixture");ElfImage image;success(image.load(file.view()),"load linked throw/catch ELF");
    std::vector<std::string> warnings;const auto frames=collectUnwindFrames(image,200000,&warnings);
    require(!frames.empty(),"real linked ELF FDE inventory");bool haveLsda=false;for(const auto& frame:frames)haveLsda|=frame.lsda!=0;require(haveLsda,"real C++ FDE LSDA augmentation");
    const auto roots=collectUnwindRoots(image,200000,&warnings);require(!roots.empty(),"headerless function roots consumed");
    const auto report=inspectExceptionMetadata(image,1024);require(!report.functions.empty(),"real clang LSDA decoded");
    size_t landing=0,cleanup=0,catchType=0,catchAll=0;
    for(const auto& function:report.functions)for(const auto& row:function.callSites){landing+=row.landingPad!=kNoAddress;for(const auto& action:row.actions){cleanup+=action.filter==0;catchType+=action.filter>0&&!action.catchAll;catchAll+=action.catchAll;}}
    require(landing&&catchType&&catchAll,"real throw/catch/catchall landing pad inventory");
    require(cxxMetadataText(image).find("Exception metadata")!=std::string::npos,"C++ report includes LSDA inventory");
    CodeAnalyzer analyzer;CodeAnalyzer::Options options;options.linearSweepFallback=false;success(analyzer.analyze(image,options),"analyze with FDE roots");
    bool consumed=false;for(const auto& function:analyzer.functions())consumed|=function.origin==FunctionOrigin::kUnwind;require(consumed,"real FDE roots reach analyzer provenance");
    std::printf("%s: %zu frames, %zu LSDAs, %zu landing pads, %zu cleanup actions\n",path,frames.size(),report.functions.size(),landing,cleanup);
}
} // namespace
int main(int argc,char** argv){for(size_t width:{size_t(4),size_t(8)})for(bool extended:{false,true})for(unsigned version:{1u,3u,4u})synthetic(width,extended,version);types();for(int i=1;i<argc;++i)real(argv[i]);std::printf("exception metadata: %zu checks passed\n",checks);return 0;}
