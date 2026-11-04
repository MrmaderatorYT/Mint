#include "mint/debug/debugger.h"
#include "mint/debug/rsp_modules.h"
#include "mint/debug/rsp_target_description.h"
#include <algorithm>
#include <cstring>
#include <cstdlib>
#include <iostream>
#include <map>
using namespace mint;
namespace {
unsigned checks=0;
void require(bool good,const char* text){++checks;if(!good){std::cerr<<"debug portability: "<<text<<'\n';std::exit(1);}}
std::string packet(const std::string& body){unsigned checksum=0;for(unsigned char c:body)checksum=(checksum+c)&255;const char* digits="0123456789abcdef";return "$"+body+"#"+digits[checksum>>4]+digits[checksum&15];}
struct Trace {std::string incoming,outgoing;size_t position=0,fragment=1;bool closed=false;};
class Wire:public DebuggerTransport {
public:explicit Wire(std::shared_ptr<Trace> trace):trace_(std::move(trace)){}
Status readSome(u8* out,size_t capacity,size_t* count,u64)override{if(trace_->position==trace_->incoming.size())return Status::error(ErrorCode::kIoError,"fixture exhausted");*count=std::min({capacity,trace_->fragment,trace_->incoming.size()-trace_->position});std::memcpy(out,trace_->incoming.data()+trace_->position,*count);trace_->position+=*count;return Status::success();}
Status writeSome(const u8* data,size_t size,size_t* count,u64)override{*count=std::min(size,trace_->fragment);trace_->outgoing.append(reinterpret_cast<const char*>(data),*count);return Status::success();}
void close()override{trace_->closed=true;}
private:std::shared_ptr<Trace> trace_;
};
std::string handshake(const std::string& feature){return "+"+packet("PacketSize=4000;"+feature)+"+"+packet("vCont;c;s")+"+"+packet("T05thread:2;");}
void parser(){
    std::vector<DebuggerModule> modules;
    const std::string xml="<?xml version='1.0'?><!DOCTYPE library-list SYSTEM 'gdb-target.dtd'><library-list version='1.0'><library name='C:\\lib\\a&amp;b.dll'><segment address='0xffffffffffffffff'/><segment address='0x2000'/></library><library name='object.o'><section address='0'/><section address='4096'/></library></library-list>";
    require(parseRspModules(xml,&modules).ok()&&modules.size()==2,"generic module XML");
    require(modules[0].name=="a&b.dll"&&modules[0].segmentBases==std::vector<Address>({~Address{0},0x2000})&&modules[1].sectionBases==std::vector<Address>({0,4096}),"exact Windows path and segment/section base evidence");
    require(modules[0].start==kNoAddress&&modules[0].end==kNoAddress&&!modules[0].hasSvr4,"base addresses do not invent mapped ranges or load bias");
    for(const auto* bad:{"<library-list version='2.0'/>","<library-list><library name='x'/></library-list>","<library-list><library name='x'></library></library-list>","<library-list><library name='x'><segment address='1'/><section address='2'/></library></library-list>",
        "<library-list><library name='x'><segment address='0x10000000000000000'/></library></library-list>","<library-list><library name='&file;'><segment address='1'/></library></library-list>","<library-list><library name='x'><segment address='1' address='2'/></library></library-list>",
        "<library-list><library name='x'><segment address='1'></segment></library></library-list>","<library-list><library name='x'><segment address='1'/></wrong></library-list>","<library-list/><library-list/>","<!DOCTYPE library-list [<!ENTITY file SYSTEM 'file:///private'>]><library-list/>"})
        require(!parseRspModules(bad,&modules).ok()&&modules.size()==2&&modules[0].name=="a&b.dll","malformed library XML leaves old inventory intact");
    std::string excessive="<library-list><library name='x'>";for(unsigned n=0;n<4097;++n)excessive+="<segment address='1'/>";excessive+="</library></library-list>";
    require(!parseRspModules(excessive,&modules).ok(),"per-library base budget");
    require(!parseRspModules(std::string(1024*1024+1,' '),&modules).ok(),"input byte budget");
    require(parseRspModules("<library-list/>",&modules).ok()&&modules.empty(),"default version and empty library inventory");
}
void transport(){
    const std::string xml="<library-list><library name='/lib/a'><segment address='0x1234'/></library><library name='b.o'><section address='0x9876'/></library></library-list>";
    for(size_t fragment:{1u,7u,4096u}){
        auto trace=std::make_shared<Trace>();trace->fragment=fragment;trace->incoming=handshake("qXfer:libraries:read+");
        for(size_t offset=0;offset<xml.size();offset+=53){const auto part=xml.substr(offset,53);trace->incoming+="+"+packet(std::string(offset+part.size()==xml.size()?"l":"m")+part);}
        DebuggerClient client;require(client.connect(std::make_unique<Wire>(trace),DebuggerBackend::kGdbRemote).ok(),"generic RSP capability connect");
        std::vector<DebuggerModule> modules;require(client.modules(&modules).ok()&&modules.size()==2,"fragmented generic library inventory");
        require(trace->outgoing.find("qXfer:libraries:read::35,400")!=std::string::npos&&trace->outgoing.find("libraries-svr4")==std::string::npos,"generic inventory uses byte offsets and advertised packet family");
        Address mapped=123;require(!client.runtimeToImage(0x1234,&mapped).ok()&&mapped==123,"library base never creates an automatic image mapping");
    }
    for(const auto& body:{std::string("<library-list><library name='x'/></library-list>"),std::string("<library-list>\xff</library-list>")}){
        auto trace=std::make_shared<Trace>();trace->incoming=handshake("qXfer:libraries:read+")+"+"+packet("l"+body);DebuggerClient client;
        require(client.connect(std::make_unique<Wire>(trace),DebuggerBackend::kGdbRemote).ok(),"hostile module connect");
        std::vector<DebuggerModule> modules(1);modules[0].name="keep";require(!client.modules(&modules).ok()&&modules[0].name=="keep"&&trace->closed,"hostile/invalid UTF-8 response disconnects without publishing");
    }
    auto trace=std::make_shared<Trace>();trace->incoming=handshake("");DebuggerClient client;require(client.connect(std::make_unique<Wire>(trace),DebuggerBackend::kGdbRemote).ok(),"missing capability connect");
    std::vector<DebuggerModule> modules(1);require(!client.modules(&modules).ok()&&trace->position==trace->incoming.size()&&!trace->closed,"unsupported capability does not send speculative module requests");
}
void endian(){
    for(auto order:{ByteOrder::kLittle,ByteOrder::kBig})for(unsigned width:{4u,8u}){
        auto trace=std::make_shared<Trace>();trace->incoming=handshake("")+"+"+packet("OK")+"+"+packet(width==4?"12345678":"123456789abcdef0");
        DebuggerOptions options;options.registerByteOrder=order;options.registerLayout={{"pc",0,width*8}};DebuggerClient client;
        require(client.connect(std::make_unique<Wire>(trace),DebuggerBackend::kGdbRemote,options).ok(),"explicit byte-order connect");Address pc=0;
        require(client.programCounter(&pc).ok()&&pc==(order==ByteOrder::kBig?(width==4?0x12345678ull:0x123456789abcdef0ull):(width==4?0x78563412ull:0xf0debc9a78563412ull)),"exact PC honors selected target byte order");
    }
    auto trace=std::make_shared<Trace>();DebuggerOptions options;options.registerByteOrder=static_cast<ByteOrder>(255);DebuggerClient client;
    require(!client.connect(std::make_unique<Wire>(trace),DebuggerBackend::kGdbRemote,options).ok()&&trace->closed,"invalid byte order rejected before protocol I/O");
}
void targetDescriptions(){
    using Documents=std::map<std::string,std::string>;
    auto parse=[](const Documents& documents,std::vector<DebuggerRegisterSpec>* out,std::vector<std::string>* requested=nullptr){
        return readRspTargetDescription([&](const std::string& annex,std::string* xml){
            if(requested)requested->push_back(annex);const auto found=documents.find(annex);
            if(found==documents.end())return Status::error(ErrorCode::kNotFound,"fixture annex absent");
            *xml=found->second;return Status::success();
        },out);
    };
    std::vector<DebuggerRegisterSpec> layout;std::vector<std::string> requested;
    const Documents documents={
        {"target.xml","<?xml version='1.0' encoding='UTF-8'?><!DOCTYPE target SYSTEM 'gdb-target.dtd'><target version='1.0' xmlns:xi='http://www.w3.org/2001/XInclude'><!-- <reg name='fake' bitsize='4096'/> <xi:include href='missing.xml'/> --><architecture>i386:x86-64</architecture><xi:include href='core.xml'/><feature name='extra'><flags id='flags' size='4'><field name='mode' start='0' end='1'/></flags><reg name='status' bitsize='32' regnum='2'/></feature></target><!-- tail -->"},
        {"core.xml","<feature name='core'><reg name='pc' bitsize='64' regnum='1'/><reg name='r0' bitsize='32' regnum='0'/></feature>"}};
    require(parse(documents,&layout,&requested).ok()&&layout.size()==3,"structural target XML includes features and ignores commented definitions");
    require(requested==std::vector<std::string>({"target.xml","core.xml"}),"only real XML include nodes are fetched");
    require(layout[0].name=="r0"&&layout[1].name=="pc"&&layout[2].name=="status"&&layout[2].number==2,"g layout sorted by register number across included features");
    // The preceding declaration determines an omitted number before sorting.
    const Documents defaults={{"target.xml","<target><feature><reg name='one' bitsize='32' regnum='1'/><reg name='zero' bitsize='32' regnum='0'/><reg name='two' bitsize='32' regnum='2'/><reg name='three' bitsize='32'/></feature></target>"}};
    require(parse(defaults,&layout).ok()&&layout.size()==4&&layout[3].number==3,"default numbers follow document declaration order before packet sorting");
    std::vector<DebuggerRegisterSpec> included;
    require(parse({{"target.xml","<target><feature><xi:include href='pc.xml'/></feature></target>"},{"pc.xml","<reg name='pc' bitsize='32'/>"}},&included).ok()&&included.size()==1&&included[0].name=="pc","include may replace an individual register element");
    require(parse({{"target.xml","<?xml version='1.0'?><!-- copyright --><!DOCTYPE target SYSTEM 'gdb-target.dtd'><!-- features --><target><feature><reg name='pc' bitsize='32'/></feature></target>"}},&included).ok(),"inert external DTD hints may be preceded by XML comments");
    const auto valid=layout;
    for(const auto& xml:{
        std::string("<target><!-- <reg name='pc' bitsize='32'/> --></target>"),
        std::string("<target><feature><![CDATA[<reg name='pc' bitsize='32'/>]]></feature></target>"),
        std::string("<not-target><feature><reg name='pc' bitsize='32'/></feature></not-target>"),
        std::string("<target><reg name='pc' bitsize='32'/></target>"),
        std::string("<target><feature><struct id='x'><reg name='pc' bitsize='32'/></struct></feature></target>"),
        std::string("<target><feature><reg name='pc' bitsize='32'/></wrong></target>"),
        std::string("<target><feature><reg name='pc' bitsize='32' bitsize='64'/></feature></target>"),
        std::string("<target><feature><reg name='pc' bitsize='32'/></feature></target><target/>"),
        std::string("<target><feature><reg name='pc' bitsize='32'/></feature></target><!-- unterminated"),
        std::string("<target><feature><reg name='pc' bitsize='32'/></feature></target><!-- bad -- comment -->"),
        std::string("<target version='2.0'><feature><reg name='pc' bitsize='32'/></feature></target>"),
        std::string("<?xml version='1.0' encoding='UTF-16'?><target><feature><reg name='pc' bitsize='32'/></feature></target>"),
        std::string("<!DOCTYPE target [<!ENTITY pc 'pc'>]><target><feature><reg name='pc' bitsize='32'/></feature></target>"),
        std::string("<!DOCTYPE feature SYSTEM 'gdb-target.dtd'><target><feature><reg name='pc' bitsize='32'/></feature></target>"),
        std::string("<!DOCTYPE target SYSTEM><target><feature><reg name='pc' bitsize='32'/></feature></target>"),
        std::string("<target><feature><reg name='\xff' bitsize='32'/></feature></target>"),
        std::string("<target><feature><reg name='\xed\xa0\x80' bitsize='32'/></feature></target>"),
        std::string("<target><feature><reg name='pc' bitsize='32'/></feature></target>\xef\xbf\xbe"),
        std::string("<target><xi:include href='../core.xml'/></target>"),
        std::string("<target><xi:include href='http://example/core.xml'/></target>"),
        std::string("<target><xi:include href='target.xml'/></target>"),
        std::string("<target><feature><reg name='pc' bitsize='32' regnum='1'/></feature></target>")}){
        const auto status=parse({{"target.xml",xml}},&layout);
        require(!status.ok()&&layout.size()==valid.size()&&layout[0].name==valid[0].name&&layout.back().number==valid.back().number,"hostile/inexact XML never publishes a partial register layout");
    }
    std::string deep="<target><feature>";for(unsigned n=0;n<40;++n)deep+="<struct>";deep+="<reg name='pc' bitsize='32'/>";
    require(!parse({{"target.xml",deep}},&layout).ok(),"XML nesting bounded");
    require(!parse({{"target.xml",std::string(65537,' ')}},&layout).ok(),"target description total byte budget");
    require(!parse({{"target.xml","<target><xi:include href='missing.xml'/></target>"}},&layout).ok(),"fetch failure preserves old layout");
    const std::string good="<target><!-- <reg name='fake' bitsize='4096'/> --><feature><reg name='pc' bitsize='32' regnum='1'/><reg name='r0' bitsize='32' regnum='0'/></feature></target>";
    for(size_t fragment:{1u,7u,4096u}){
        auto trace=std::make_shared<Trace>();trace->fragment=fragment;trace->incoming=handshake("");
        for(size_t at=0;at<good.size();at+=53){const auto part=good.substr(at,53);trace->incoming+="+"+packet(std::string(at+part.size()==good.size()?"l":"m")+part);}
        trace->incoming+="+"+packet("OK")+"+"+packet("aaaaaaaa78563412");DebuggerClient client;
        require(client.connect(std::make_unique<Wire>(trace),DebuggerBackend::kGdbRemote).ok()&&client.discoverRegisterLayout().ok(),"fragmented target XML discovery");
        Address pc=0;require(client.programCounter(&pc).ok()&&pc==0x12345678,"discovered exact register-number order determines PC");
        require(trace->outgoing.find("qXfer:features:read:target.xml:35,400")!=std::string::npos,"target XML pages use actual byte offsets");
    }
    auto trace=std::make_shared<Trace>();trace->incoming=handshake("")+"+"+packet("l<target><feature><reg name='pc' bitsize='32'/></wrong></target>");DebuggerClient broken;
    require(broken.connect(std::make_unique<Wire>(trace),DebuggerBackend::kGdbRemote).ok()&&!broken.discoverRegisterLayout().ok()&&trace->closed,"malformed target XML closes the stream without accepting a guessed layout");
    for(const auto& page:{std::string("m"),std::string("l")+std::string(1025,' ')}){
        auto hostile=std::make_shared<Trace>();hostile->incoming=handshake("")+"+"+packet(page);DebuggerClient bounded;
        require(bounded.connect(std::make_unique<Wire>(hostile),DebuggerBackend::kGdbRemote).ok()&&!bounded.discoverRegisterLayout().ok()&&hostile->closed,"zero-progress/over-request target XML pages close the stream");
    }
    auto sorted=std::make_shared<Trace>();sorted->incoming=handshake("")+"+"+packet("OK")+"+"+packet("aaaaaaaa78563412");DebuggerOptions options;options.registerLayout={{"pc",1,32},{"r0",0,32}};DebuggerClient exact;
    require(exact.connect(std::make_unique<Wire>(sorted),DebuggerBackend::kGdbRemote,options).ok(),"unordered explicit register metadata connect");Address pc=0;
    require(exact.programCounter(&pc).ok()&&pc==0x12345678,"explicit layouts also use increasing register-number order");
}
}
int main(){parser();transport();endian();targetDescriptions();std::cout<<checks<<" debugger portability checks passed\n";}
