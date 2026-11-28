#include "mint/analysis/x86_switch_recovery.h"
#include "mint/session.h"
#include "program_fresh_oracle.h"
#include "mint/ir/registers.h"
#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <sstream>
#include <unistd.h>

using namespace mint;
namespace {
unsigned checks=0;
void require(bool condition,const std::string& label){++checks;if(!condition){std::cerr<<"x86 switch: "<<label<<'\n';std::exit(1);}}
void okay(const Status& status,const std::string& label){require(status.ok(),label+": "+status.toString());}
template<class T>void put(std::vector<u8>& bytes,size_t offset,T value){require(offset+sizeof(value)<=bytes.size(),"fixture write is bounded");std::memcpy(bytes.data()+offset,&value,sizeof(value));}
ByteView view(const std::vector<u8>& bytes){return ByteView(bytes.data(),bytes.size());}
enum class Variant {kNormal,kNoGuard,kBypass,kChangedIndex,kShortTable,kWritable,kBadTarget,kMiddleTarget,kTooMany,kWideJbe,kLeaFirst,kReenter,
    kCopyElided,kCopyElidedChangedIndex,kCopyElidedUnknownHigh,kCopyElidedClobberedHigh,kCopyElidedBypassedDefinition};
struct Fixture {std::vector<u8> bytes;Address branch=0,guard=0x1000;};
Fixture fixture(Variant variant=Variant::kNormal){
    Fixture result;result.bytes.resize(0x50c);auto& bytes=result.bytes;
    const u8 ident[]={0x7f,'E','L','F',2,1,1};elf::Ehdr header{};std::memcpy(header.ident,ident,sizeof(ident));header.type=elf::kEtDyn;header.machine=62;header.version=1;header.entry=0x1000;header.phoff=sizeof(header);header.ehsize=sizeof(header);header.phentsize=sizeof(elf::Phdr);header.phnum=2;std::memcpy(bytes.data(),&header,sizeof(header));
    elf::Phdr code{};code.type=elf::kPtLoad;code.flags=elf::kPfR|elf::kPfX;code.offset=0x200;code.vaddr=0x1000;code.filesz=code.memsz=0x200;code.align=1;
    elf::Phdr data{};data.type=elf::kPtLoad;data.flags=elf::kPfR|(variant==Variant::kWritable?elf::kPfW:0);data.offset=0x500;data.vaddr=0x2000;data.filesz=variant==Variant::kShortTable?8:12;data.memsz=12;data.align=1;std::memcpy(bytes.data()+sizeof(header),&code,sizeof(code));std::memcpy(bytes.data()+sizeof(header)+sizeof(code),&data,sizeof(data));
    std::fill(bytes.begin()+0x200,bytes.begin()+0x400,0xcc);
    size_t at=0x200;auto emit=[&](std::initializer_list<u8> sequence){for(auto byte:sequence)bytes[at++]=byte;};
    size_t bypass=0;
    if(variant==Variant::kBypass){emit({0x85,0xf6,0x74,0});bypass=at-1;}
    const bool copyElided=variant==Variant::kCopyElided||variant==Variant::kCopyElidedChangedIndex||
        variant==Variant::kCopyElidedUnknownHigh||variant==Variant::kCopyElidedClobberedHigh||variant==Variant::kCopyElidedBypassedDefinition;
    if(variant==Variant::kCopyElidedBypassedDefinition)emit({0x85,0xd2,0x74,0x05}); // test edx,edx; je CMP
    if(copyElided&&variant!=Variant::kCopyElidedUnknownHigh) {
        emit({0x31,0xf7}); // xor edi,esi clears the upper half while computing the index
        emit({0x48,0x89,0xf0}); // mov rax,rsi is independent of the index
    }
    if(variant==Variant::kCopyElidedClobberedHigh)emit({0x48,0x89,0xd7}); // mov rdi,rdx
    result.guard=0x1000+at-0x200;
    size_t guardJump=0;
    if(variant!=Variant::kNoGuard){
        if(variant==Variant::kTooMany){emit({0x81,0xff});put<u32>(bytes,at,256);at+=4;}
        else if(variant==Variant::kWideJbe)emit({0x48,0x83,0xff,0x02}); // cmp rdi,2
        else emit({0x83,0xff,0x02}); // cmp edi,2
        emit({static_cast<u8>(variant==Variant::kWideJbe?0x76:0x77),0});guardJump=at-1;
        if(variant==Variant::kWideJbe){emit({0xe9,0,0,0,0});put<u32>(bytes,at-4,static_cast<u32>(0x280-at));} // default fallthrough
    }
    const auto dispatch=at;
    if(!copyElided&&variant!=Variant::kWideJbe&&variant!=Variant::kLeaFirst)emit({0x89,0xf8}); // explicit zero extension after the guard
    if(variant==Variant::kChangedIndex)emit({0xff,0xc0}); // inc eax
    if(variant==Variant::kCopyElidedChangedIndex)emit({0xff,0xc7}); // inc edi after the guard breaks the range proof
    const auto lea=at;emit({0x48,0x8d,0x0d,0,0,0,0}); // lea rcx,[rip+table]
    put<u32>(bytes,lea+3,static_cast<u32>(0x2000-(0x1000+lea-0x200+7)));
    if(variant==Variant::kLeaFirst)emit({0x89,0xf8});
    emit({0x48,0x63,0x04,static_cast<u8>(copyElided||variant==Variant::kWideJbe?0xb9:0x81),0x48,0x01,0xc8}); // signed rel32 load; add table base
    result.branch=0x1000+at-0x200;emit({0xff,0xe0}); // jmp rax
    if(guardJump)bytes[guardJump]=static_cast<u8>((variant==Variant::kWideJbe?dispatch:0x280)-(guardJump+1));
    if(bypass)bytes[bypass]=static_cast<u8>(dispatch-(bypass+1));
    for(size_t offset:{size_t{0x280},size_t{0x2a0},size_t{0x2b0},size_t{0x2c0}}){bytes[offset]=0xb8;put<u32>(bytes,offset+1,static_cast<u32>(offset));bytes[offset+5]=0xc3;}
    if(variant==Variant::kReenter){ // A newly discovered case invalidates the guard before reentry.
        bytes[0x2a0]=0xbf;put<u32>(bytes,0x2a1,0xffffffffu);
        bytes[0x2a5]=0xe9;put<u32>(bytes,0x2a6,static_cast<u32>(dispatch-(0x2a5+5)));
    }
    for(size_t n=0;n<3;++n){Address target=n==1?0x10b0:0x10a0;if(n==2&&variant==Variant::kBadTarget)target=0x2000;if(n==2&&variant==Variant::kMiddleTarget)target=result.guard+1;put<u32>(bytes,0x500+4*n,static_cast<u32>(target-0x2000));}
    return result;
}
const Function& entryFunction(const CodeAnalyzer& analyzer){const auto* function=analyzer.functionAt(0x1000);require(function!=nullptr,"entry function discovered");return *function;}
const ResolvedIndirectJump* switchAt(const Function& function,Address branch){const auto found=std::find_if(function.resolvedIndirectJumps.begin(),function.resolvedIndirectJumps.end(),[&](const auto& jump){return jump.branch==branch&&!jump.switchCases.empty();});return found==function.resolvedIndirectJumps.end()?nullptr:&*found;}
CodeAnalyzer::Options analysisOptions(){CodeAnalyzer::Options options;options.linearSweepFallback=false;return options;}
void positiveAndBounds(){
    const auto input=fixture();ElfImage image;okay(image.load(view(input.bytes)),"load native ELF64 rel32 fixture");CodeAnalyzer analyzer;okay(analyzer.analyze(image,analysisOptions()),"discover native PIC switch");const auto& function=entryFunction(analyzer);const auto* jump=switchAt(function,input.branch);
    require(!function.incomplete&&jump,"early recovery brings case bodies into a complete function");
    require(jump->targets==std::vector<Address>({0x10a0,0x10b0}),"signed negative table entries produce deduplicated target edges");
    require(jump->switchCases.size()==3&&jump->switchCases[0].value==0&&jump->switchCases[0].target==0x10a0&&jump->switchCases[1].value==1&&jump->switchCases[1].target==0x10b0&&jump->switchCases[2].value==2&&jump->switchCases[2].target==0x10a0,"duplicate destinations retain their distinct source case values");
    require(jump->table==0x2000&&jump->selectorAddress!=kNoAddress&&jump->selectorWidth==4,"switch metadata retains exact table and captured selector width");
    for(Address target:{Address{0x10a0},Address{0x10b0}})require(std::binary_search(function.instructions.begin(),function.instructions.end(),target),"recovered case body belongs to the dispatching function");
    const auto block=std::find_if(function.cfg.blocks().begin(),function.cfg.blocks().end(),[&](const auto& item){return item.contains(input.branch);});require(block!=function.cfg.blocks().end()&&block->successors.size()==2,"switch CFG has one recovered edge per unique destination");
    for(const auto& edge:block->successors)require(edge.kind==EdgeKind::kResolvedIndirect,"switch edges retain recovered provenance");
    bool dependency=false;for(const auto& report:analyzer.indirectFlowReports())for(const auto& site:report.second.sites)if(site.address==input.branch)for(const auto& range:site.dependencies)if(range.start<=0x2000&&range.end>=0x200c)dependency=true;
    require(dependency,"immutable table bytes are recorded as an indirect-flow dependency");
    std::vector<X86SwitchTable> recovered;okay(recoverX86RelativeSwitches(image,analyzer.code(),function,&recovered),"re-prove fully discovered switch");require(recovered.size()==1&&recovered[0].fullyDiscovered,"machine recognizer distinguishes full proof from a discovery proposal");
    for(unsigned cap=0;cap<5;++cap){X86SwitchRecoveryOptions options;if(cap==0)options.maxEntries=2;else if(cap==1)options.maxInstructions=2;else if(cap==2)options.maxSites=0;else if(cap==3)options.maxBlocks=0;else options.maxWork=1;
        recovered.clear();const auto status=recoverX86RelativeSwitches(image,analyzer.code(),function,&recovered,options);
        require(!status.ok()||std::none_of(recovered.begin(),recovered.end(),[](const auto& table){return table.fullyDiscovered;}),"resource cutoff never returns a complete switch proof");
    }
    const auto saved=analyzer.snapshot();const u32 replacement=static_cast<u32>(Address{0x10c0}-0x2000);okay(image.applyPatch(0x2000,ByteView(reinterpret_cast<const u8*>(&replacement),4)),"patch table dependency");CodeAnalyzer stale;require(!stale.restore(image,analysisOptions(),saved).ok(),"cached target edges are re-proved against changed table bytes");
    for(auto variant:{Variant::kWideJbe,Variant::kLeaFirst}){const auto supported=fixture(variant);ElfImage native;okay(native.load(view(supported.bytes)),"load supported guard/dispatcher ordering");CodeAnalyzer analyzed;okay(analyzed.analyze(native,analysisOptions()),"analyze supported guard/dispatcher ordering");const auto& entry=entryFunction(analyzed);const auto* proven=switchAt(entry,supported.branch);require(proven&&!entry.incomplete&&proven->switchCases.size()==3&&proven->targets==std::vector<Address>({0x10a0,0x10b0}),"CMP64/JBE and LEA-before-MOV preserve exact case recovery");require(proven->selectorWidth==(variant==Variant::kWideJbe?8:4),"captured selector width follows the actual native guard");}
}
void rejectedInputs(){
    for(auto variant:{Variant::kNoGuard,Variant::kBypass,Variant::kChangedIndex,Variant::kShortTable,Variant::kWritable,Variant::kBadTarget,Variant::kMiddleTarget,Variant::kTooMany,Variant::kReenter,
        Variant::kCopyElidedChangedIndex,Variant::kCopyElidedUnknownHigh,Variant::kCopyElidedClobberedHigh,Variant::kCopyElidedBypassedDefinition}){
        const auto input=fixture(variant);ElfImage image;okay(image.load(view(input.bytes)),"load negative rel32 fixture");CodeAnalyzer analyzer;okay(analyzer.analyze(image,analysisOptions()),"analyze unsupported switch evidence");const auto& function=entryFunction(analyzer);
        require(function.incomplete&&!switchAt(function,input.branch),"absent/bypassed guard, changed index or invalid/bounded table cannot complete the CFG (variant "+std::to_string(static_cast<unsigned>(variant))+")");
    }
    const auto input=fixture();ElfImage image;okay(image.load(view(input.bytes)),"load instruction-budget fixture");CodeAnalyzer analyzer;auto options=analysisOptions();options.maxInstructions=5;okay(analyzer.analyze(image,options),"analyze under discovery instruction budget");require(entryFunction(analyzer).incomplete,"truncated discovery cannot promote a provisional switch to a complete CFG");
    CodeAnalyzer partiallyDiscovered;options.maxInstructions=11;okay(partiallyDiscovered.analyze(image,options),"bound discovery after the full dispatcher");const auto& partial=entryFunction(partiallyDiscovered);require(partiallyDiscovered.code().find(input.branch)&&(!partiallyDiscovered.code().find(0x10a0)||!partiallyDiscovered.code().find(0x10b0)),"budget fixture reaches the indirect jump but omits at least one case body");require(partial.incomplete&&!switchAt(partial,input.branch),"fully decoded dispatcher cannot export metadata while case discovery is incomplete");
}
class TemporaryDirectory {
    std::string path_;
public:
    TemporaryDirectory(){auto path=(std::filesystem::temp_directory_path()/"mint-x86-switch-XXXXXX").string();if(::mkdtemp(path.data()))path_=path;require(!path_.empty(),"create private fixture directory");}
    ~TemporaryDirectory(){std::error_code error;std::filesystem::remove_all(path_,error);}
    std::string file(const std::string& name)const{return path_+"/"+name;}
};
std::vector<u8> readFile(const std::string& path){std::ifstream input(path,std::ios::binary);return {std::istreambuf_iterator<char>(input),std::istreambuf_iterator<char>()};}
void writeFile(const std::string& path,const std::vector<u8>& bytes){std::ofstream output(path,std::ios::binary|std::ios::trunc);output.write(reinterpret_cast<const char*>(bytes.data()),static_cast<std::streamsize>(bytes.size()));output.close();require(!output.fail(),"write owned fixture file");}
void open(Session& session,const std::string& source,const std::string& project){okay(session.openPath(source),"open ELF switch Session");okay(session.attachProject(project),"attach switch Program");okay(session.analyze(),"analyze or restore switch Program");}
std::string snapshot(Session& session){
    std::ostringstream out;const auto& analyzer=session.analyzer();const auto& stats=analyzer.stats();out<<stats.instructions<<' '<<stats.functions<<' '<<stats.blocks<<' '<<stats.edges<<' '<<stats.incompleteFunctions<<'\n';
    for(const auto& instruction:analyzer.code().instructions())out<<instruction.address<<' '<<instruction.id<<' '<<unsigned(instruction.size)<<' '<<unsigned(instruction.flow)<<' '<<instruction.target<<'\n';
    for(const auto& function:analyzer.functions()){
        out<<"function "<<function.entry<<' '<<function.incomplete<<'\n';for(auto instruction:function.instructions)out<<instruction<<' ';out<<'\n';
        for(const auto& jump:function.resolvedIndirectJumps){out<<"jump "<<jump.branch<<' '<<jump.table<<' '<<jump.selectorAddress<<' '<<jump.selectorRegister<<' '<<unsigned(jump.selectorWidth)<<'\n';for(auto target:jump.targets)out<<target<<' ';out<<'\n';for(const auto& item:jump.switchCases)out<<item.value<<':'<<item.target<<' ';out<<'\n';}
        out<<session.irTextFor(function.entry)<<session.decompiledCFor(function.entry)<<session.cfgTextFor(function.entry);
    }
    for(const auto& row:session.programListing(0x1000,512))out<<row.address<<' '<<row.size<<' '<<unsigned(row.flow)<<' '<<row.target<<' '<<row.text<<' '<<row.comment<<'\n';
    for(Address address:{Address{0x1000},Address{0x10a0},Address{0x10b0},Address{0x10c0},Address{0x2000}})out<<session.referencesText(address);
    return out.str();
}
std::string hex32(u32 value){std::ostringstream out;for(unsigned n=0;n<4;++n){if(n)out<<' ';out<<std::hex<<std::setw(2)<<std::setfill('0')<<((value>>(n*8))&255);}return out.str();}
void captureExample(const std::string& label,Session& session){if(const char* path=std::getenv("MINT_X86_SWITCH_CAPTURE")){std::ofstream output(path,label=="before"?std::ios::trunc:std::ios::app);output<<label<<"\n"<<session.decompiledCFor(0x1000)<<"\nCFG\n"<<session.cfgTextFor(0x1000)<<'\n';require(!output.fail(),"capture actual decompiler/CFG example");}}
void compareToFresh(Session& session, const std::string& source, const std::string& project,
                    const std::string& label) {
    okay(testing::matchesFreshAnalysis(session, project,
        [&](Session& oracle) { return oracle.openPath(source); }, snapshot), label + " vs fresh full analysis");
}

void checkReopen(const std::string& source, const std::string& project, const std::string& expected,
                 const std::string& mode, const std::string& label) {
    const auto authoritative = readFile(project);
    require(!authoritative.empty(), label + " has a persisted Program");
    Session reopened;
    open(reopened, source, project);
    require(testing::hasAnalysisMode(reopened, mode), label + " uses mode=" + mode);
    require(snapshot(reopened) == expected, label + " keeps exact switch semantics and views");
    compareToFresh(reopened, source, project, label);
    require(readFile(project) == authoritative, label + " does not rewrite the authoritative Program");
}

void sessionLifecycle() {
    TemporaryDirectory temporary;
    const auto source = temporary.file("switch.elf"), project = temporary.file("program.mint");
    const auto input = fixture();
    writeFile(source, input.bytes);
    Session session;
    open(session, source, project);
    const auto initial = snapshot(session);
    require(switchAt(entryFunction(session.analyzer()), input.branch), "Session exposes recovered switch semantics");
    auto fresh = [&](const std::string& label) { compareToFresh(session, source, project, label); };
    captureExample("before", session);

    const auto firstIndex = Address{0x2000};
    const auto relative = [&](Address target) { return hex32(static_cast<u32>(target - firstIndex)); };
    okay(session.editAnnotation(firstIndex, "patch", relative(0x10b0) + " " + relative(0x10a0)),
         "permute cases while preserving the set of jump targets");
    const auto permuted = snapshot(session);
    const auto* permutation = switchAt(entryFunction(session.analyzer()), input.branch);
    require(permutation && permutation->targets == std::vector<Address>({0x10a0, 0x10b0}) &&
            permutation->switchCases.size() == 3 && permutation->switchCases[0].target == 0x10b0 &&
            permutation->switchCases[1].target == 0x10a0,
            "equal sets of jump targets still have different case mappings");
    require(permuted != initial, "table permutation changes the exported selector semantics");
    fresh("table permutation");
    captureExample("after case permutation", session);
    checkReopen(source, project, permuted, "restored", "permuted switch reopen");

    okay(session.undoEdit(false), "undo table permutation");
    require(snapshot(session) == initial, "permutation undo restores original case values");
    fresh("permutation undo");
    okay(session.undoEdit(true), "redo table permutation");
    require(snapshot(session) == permuted, "permutation redo restores changed case values");
    fresh("permutation redo");
    okay(session.undoEdit(false), "return to baseline table");

    okay(session.editAnnotation(firstIndex, "patch", relative(0x10c0)), "patch rel32 target");
    require(testing::hasAnalysisMode(session, "full"), "table dependency edit uses safe full rediscovery");
    const auto patched = snapshot(session);
    require(patched != initial, "table patch changes discovered case bodies and exported views");
    fresh("table patch");
    okay(session.undoEdit(false), "undo table patch");
    require(snapshot(session) == initial, "undo exactly restores switch semantics and all views");
    fresh("table undo");
    okay(session.undoEdit(true), "redo table patch");
    require(snapshot(session) == patched, "redo exactly restores patched switch semantics");
    fresh("table redo");
    checkReopen(source, project, patched, "restored", "patched switch reopen");
    okay(testing::corruptDerivedCache(project), "corrupt the patched switch cache");
    checkReopen(source, project, patched, "full", "patched switch recovery");
    const auto olderCache = readFile(project + ".analysis");
    require(!olderCache.empty(), "successful rediscovery replaces the corrupted cache");

    okay(session.editAnnotation(0x1002, "patch", "01"), "reduce unsigned guard bound");
    const auto guard = snapshot(session);
    require(guard != patched, "guard patch changes the proven case range");
    fresh("guard patch");
    okay(session.undoEdit(false), "undo guard patch");
    require(snapshot(session) == patched, "guard undo restores all three table cases");
    fresh("guard undo");
    okay(session.undoEdit(true), "redo guard patch");
    require(snapshot(session) == guard, "guard redo restores the reduced case range");
    fresh("guard redo");
    checkReopen(source, project, guard, "restored", "guard patch reopen");
    okay(session.undoEdit(false), "return to the original guard bound");

    okay(session.editAnnotation(firstIndex, "patch", relative(0x1001)), "patch table to middle of instruction");
    require(entryFunction(session.analyzer()).incomplete && !switchAt(entryFunction(session.analyzer()), input.branch),
            "invalid table overlay cannot reuse previously proved switch semantics");
    const auto invalid = snapshot(session);
    fresh("invalid target patch");
    okay(session.undoEdit(false), "undo invalid target patch");
    require(snapshot(session) == patched, "invalid-target undo re-proves valid cases");
    fresh("invalid target undo");
    okay(session.undoEdit(true), "redo invalid target patch");
    require(snapshot(session) == invalid, "invalid-target redo preserves the incomplete result");
    fresh("invalid target redo");
    writeFile(project + ".analysis", olderCache);
    checkReopen(source, project, invalid, "full", "invalid switch with stale valid cache");
}

void copyElidedLifecycle() {
    TemporaryDirectory temporary;
    const auto source = temporary.file("copy-elided.elf"), project = temporary.file("program.mint");
    const auto input = fixture(Variant::kCopyElided);
    writeFile(source, input.bytes);
    Session session;
    open(session, source, project);
    const auto* jump = switchAt(entryFunction(session.analyzer()), input.branch);
    require(jump && jump->switchCases.size() == 3 && jump->selectorWidth == 4,
            "32-bit index definition before CMP permits the four-instruction dispatcher");
    const auto complete = snapshot(session);
    require(complete.find("proven table indices") != std::string::npos,
            "copy-elided switch reaches the normal Pseudo-C path");
    bool dependency = false;
    for (const auto& item : session.analyzer().indirectFlowReports())
        for (const auto& site : item.second.sites)
            if (site.address == input.branch)
                for (const auto& range : site.dependencies) dependency |= range.start <= 0x1000 && range.end > input.guard;
    require(dependency, "switch proof depends on pre-CMP index definition bytes");

    okay(session.editAnnotation(0x1001, "patch", "fe"), "retarget XOR to esi without changing its length or flow");
    require(entryFunction(session.analyzer()).incomplete && !switchAt(entryFunction(session.analyzer()), input.branch),
            "patching the zero-extension witness invalidates its switch");
    const auto invalidated = snapshot(session);
    compareToFresh(session, source, project, "index definition patch");
    okay(session.undoEdit(false), "restore the zero-extending XOR");
    require(snapshot(session) == complete, "undo re-proves the copy-elided switch");
    compareToFresh(session, source, project, "index definition undo");
    checkReopen(source, project, complete, "restored", "copy-elided switch reopen");
    okay(session.undoEdit(true), "redo patch to index definition");
    require(snapshot(session) == invalidated, "redo invalidates the copy-elided switch again");
    compareToFresh(session, source, project, "index definition redo");
    checkReopen(source, project, invalidated, "restored", "copy-elided switch invalidation reopen");
}
void compilerFixture(const std::string& path,bool copyElided){
    Session session;okay(session.openPath(path),"open compiler-generated PIC switch");
    okay(session.analyze(),"analyze compiler-generated PIC switch");
    const auto* symbol=session.image().findSymbol("pic_switch");
    require(symbol!=nullptr,"compiler fixture preserves named switch symbol");
    const auto* function=session.analyzer().functionAt(symbol->value);
    require(function&&!function->incomplete,"real Clang rel32 switch has complete discovered case coverage");
    require(std::any_of(function->resolvedIndirectJumps.begin(),function->resolvedIndirectJumps.end(),[](const auto& jump){return jump.switchCases.size()>=6;}),"real compiler fixture exposes selector case mapping");
    if(copyElided) {
        const auto resolved=std::find_if(function->resolvedIndirectJumps.begin(),function->resolvedIndirectJumps.end(),
            [](const auto& jump){return jump.switchCases.size()>=6&&jump.selectorWidth==4;});
        require(resolved!=function->resolvedIndirectJumps.end(),"compiler retained the 32-bit guard");
        const auto block=std::find_if(function->cfg.blocks().begin(),function->cfg.blocks().end(),
            [&](const auto& item){return item.contains(resolved->branch);});
        require(block!=function->cfg.blocks().end()&&block->insnCount==4,"compiler dispatch has LEA, MOVSXD, ADD, JMP only");
    }
    const auto c=session.decompiledCFor(symbol->value);
    require(c.find("proven table indices")!=std::string::npos,"ordinary compiler-fixture decompilation emits an indexed switch");
    for(unsigned n=0;n<6;++n)
        require(c.find("case "+std::to_string(n)+"ULL:")!=std::string::npos&&c.find("case_"+std::to_string(n))!=std::string::npos,
            "each compiler-produced case label and body survives ordinary pseudo-C emission");
}
}
int main(int argc,char** argv){
    if(argc==3&&std::string(argv[1])=="--copy-elided")compilerFixture(argv[2],true);
    else {
        positiveAndBounds();rejectedInputs();sessionLifecycle();copyElidedLifecycle();
        for(int n=1;n<argc;++n)compilerFixture(argv[n],false);
    }
    std::cout<<checks<<" x86 PIC switch checks passed\n";
}
