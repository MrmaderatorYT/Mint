// Native CodeBrowser automation, deliberately a bounded command DSL rather
// than arbitrary shell execution. One process owns one serialized Session.
#include "mint/session.h"
#include "mint/analysis/cxx_metadata.h"
#include "mint/script/lua_runtime.h"
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>

using namespace mint;
namespace {
Address address(const std::string& text) {
    if(text.empty() || text[0]=='-')throw std::invalid_argument("address must be unsigned");
    size_t used=0;auto value=std::stoull(text,&used,text.rfind("0x",0)==0 || text.rfind("0X",0)==0?16:10);
    if(used!=text.size())throw std::invalid_argument("address must be decimal or 0x-prefixed hexadecimal");
    return value;
}
void checked(Status status) {if(!status.ok())throw std::runtime_error(status.toString());}
std::string remainder(std::istringstream& input) {std::string value;std::getline(input,value);if(!value.empty() && value[0]==' ')value.erase(0,1);return value;}
std::string joined(const std::string& first,std::istringstream& input) {auto rest=remainder(input);return first+(rest.empty()?"":" "+rest);}
void command(Session& session,const std::string& line,bool allowEdits=false) {
    if(line.size()>65536)throw std::runtime_error("command exceeds 64 KiB");
    std::istringstream input(line);std::string op;input>>op;if(op.empty() || op[0]=='#')return;
    std::string arg;input>>arg;
    if(op=="summary")std::cout<<session.memoryBlocksText();
    else if(op=="functions")for(const auto& fn:session.analyzer().functions())std::cout<<"0x"<<std::hex<<fn.entry<<std::dec<<"\t"<<session.displayNameAt(fn.entry)<<"\t"<<functionOriginName(fn.origin)<<"\n";
    else if(op=="listing")for(const auto& row:session.programListing(address(arg),256))std::cout<<"0x"<<std::hex<<row.address<<std::dec<<"\t"<<row.text<<"\t"<<row.comment<<"\n";
    else if(op=="decompile")std::cout<<session.decompiledCFor(address(arg));
    else if(op=="ir")std::cout<<session.irTextFor(address(arg));
    else if(op=="cfg")std::cout<<session.cfgTextFor(address(arg));
    else if(op=="refs")std::cout<<session.referencesText(address(arg));
    else if(op=="provenance")std::cout<<session.provenanceText(address(arg));
    else if(op=="search") {auto rest=remainder(input);std::cout<<session.searchText(arg+(rest.empty()?"":" "+rest));}
    else if(op=="types")std::cout<<session.typesText();
    else if(op=="types-c")std::cout<<session.typesCHeaderText();
    else if(op=="prototypes")std::cout<<session.interproceduralText();
    else if(op=="abi")std::cout<<session.abiText(address(arg));
    else if(op=="locals")std::cout<<session.localVariablesText(address(arg));
    else if(op=="local") {std::string identity,name;input>>identity>>name;checked(session.editLocalVariable(address(arg),identity,name,remainder(input)));}
    else if(op=="local-clear") {std::string identity;input>>identity;checked(session.editLocalVariable(address(arg),identity,"",""));}
    else if(op=="import-debug") {std::string path=remainder(input);const bool allow=arg=="ack-unverified";checked(session.importExternalDebug(allow?path:arg+(path.empty()?"":" "+path),allow));}
    else if(op=="signatures")std::cout<<session.signatureLibraryText();
    else if(op=="import-library") {
        std::ifstream file(joined(arg,input),std::ios::binary);if(!file)throw std::runtime_error("cannot open library");
        std::string text;char bytes[8192];while(file.read(bytes,sizeof(bytes)) || file.gcount()) {
            text.append(bytes,static_cast<size_t>(file.gcount()));if(text.size()>1024*1024)throw std::runtime_error("library exceeds 1 MiB");
        }
        if(!file.eof())throw std::runtime_error("cannot read complete library");
        checked(session.importLibrary(text,text.rfind("MINTSIG ",0)==0));
    }
    else if(op=="compare-open") {checked(session.openComparison(joined(arg,input),""));std::string text;checked(session.comparisonCommand("diff",0,0,"",&text));std::cout<<text;}
    else if(op=="compare-project") {std::string targetProject;input>>targetProject;checked(session.openComparison(arg,targetProject));}
    else if(op=="compare-confirm") {std::string target;input>>target;std::string text;checked(session.comparisonCommand("confirm",address(arg),address(target),"",&text));std::cout<<text;}
    else if(op=="compare-save" || op=="compare-load") {std::string text;checked(session.comparisonCommand(op=="compare-save"?"save":"load",0,0,joined(arg,input),&text));std::cout<<text;}
    else if(op=="compare-preview" || op=="compare-apply" || op=="compare-diff") {
        if(op=="compare-apply" && !allowEdits)throw std::runtime_error("comparison transfer requires --allow-edits");
        std::string text;checked(session.comparisonCommand(op=="compare-preview"?"preview":op=="compare-apply"?"apply":"diff",0,0,"",&text));std::cout<<text;
    }
    else if(op=="debug-connect") {std::string port,backend,ack;input>>port>>backend>>ack;const auto number=address(port);if(number>65535)throw std::runtime_error("invalid debugger port");if(backend!="rsp" && backend!="dap")throw std::runtime_error("debug backend must be rsp or dap");checked(session.connectDebugger(arg,static_cast<u32>(number),backend=="dap",ack=="ack-plaintext"));}
    else if(op=="debug") {std::string at,value;input>>at>>value;std::string text;checked(session.debuggerCommand(arg,at.empty()?0:address(at),value.empty()?0:address(value),&text));std::cout<<text;}
    else if(op=="type") {auto rest=remainder(input);checked(session.defineType(arg+(rest.empty()?"":" "+rest)));}
    else if(op=="erase-type")checked(session.eraseType(arg));
    else if(op=="cxx")std::cout<<cxxMetadataText(session.image());
    else if(op=="dwarf")std::cout<<session.debugInfoText();
    else if(op=="source")std::cout<<session.sourceLocationText(address(arg))<<'\n';
    else if(op=="plugins")std::cout<<session.pluginCommandsText();
    else if(op=="plugin-run") {
        std::string output;const auto status=session.runPlugin(arg,remainder(input),allowEdits,&output);std::cout<<output;checked(status);
    }
    else if(op=="asm" || op=="asm-preview") {
        std::string bytes;checked(session.assembleAt(address(arg),remainder(input),op=="asm",&bytes));std::cout<<bytes<<'\n';
    }
    else if(op=="edit") {std::string kind;input>>kind;checked(session.editAnnotation(address(arg),kind,remainder(input)));}
    else if(op=="undo")checked(session.undoEdit(false));
    else if(op=="redo")checked(session.undoEdit(true));
    else if(op=="reanalyze")checked(session.reanalyze());
    else if(op=="json")std::cout<<session.exportJsonText();
    else if(op=="export-patched")checked(session.exportPatchedCopy(joined(arg,input)));
    else if(op=="diff") {
        // Byte-level comparison only, not semantic function matching. Compare
        // against the current overlay including BSS zeros; never modify either.
        Session other;checked(other.openPath(joined(arg,input)));
        size_t count=0;u64 compared=0;
        for(const auto& block:session.image().memory().segments())for(u64 i=0;i<block.size;++i) {
            if(++compared>256*1024*1024)throw std::runtime_error("diff exceeds 256 MiB comparison budget");
            u8 a=0,b=0;const auto at=block.start+i;
            bool left=session.image().memory().read(at,&a,1),right=other.image().memory().read(at,&b,1);
            if(left && (!right || a!=b)) {
                if(count++<10000)std::cout<<"0x"<<std::hex<<at<<"\t"<<static_cast<unsigned>(a)<<" -> "<<(right?std::to_string(b):"unmapped")<<std::dec<<"\n";
            }
        }
        std::cout<<count<<" changed bytes in source mapped ranges (first 10000 shown; additions outside source ranges excluded)\n";
    } else throw std::runtime_error("unknown command: "+op);
}
}
int main(int argc,char** argv) {
    if(argc<2){std::cerr<<"mint_headless INPUT [--project PROGRAM] [--raw ARCH BASE ENTRY | --macho ARCH] [--script FILE] [--lua FILE] [--allow-edits] [--plugin PATH --trust-native] [COMMAND...]\n"
        "Read: summary functions listing decompile ir cfg refs provenance search types types-c prototypes abi locals signatures cxx dwarf source json diff\n"
        "Program: type erase-type import-library import-debug local local-clear edit undo redo reanalyze asm-preview asm export-patched\n"
        "Tracking: compare-open compare-project compare-confirm compare-save compare-load compare-diff compare-preview compare-apply\n"
        "Extensions: plugins plugin-run debug-connect debug\n"
        "Lua: text-only, bounded and read-only unless --allow-edits. Native plugins are unrestricted trusted code, not sandboxed. Debugger sockets require explicit numeric endpoints.\n"
        "DSL scripts: one command per line, # comments, fail-fast. Explicit Program-edit commands require a writable project; earlier committed edits remain undoable. Transfer requires --allow-edits.\n";return 2;}
    try {
        std::string project,script,lua,rawName;std::vector<std::string> plugins;bool allowEdits=false,trustNative=false,macho=false;Arch arch=Arch::kUnknown;Address base=0,entry=0;int i=2;
        while(i<argc && std::string(argv[i]).rfind("--",0)==0) {
            std::string option=argv[i++];
            if((option=="--project" || option=="--script") && i<argc){(option=="--project"?project:script)=argv[i++];}
            else if(option=="--lua" && i<argc)lua=argv[i++];
            else if(option=="--allow-edits")allowEdits=true;
            else if(option=="--plugin" && i<argc)plugins.push_back(argv[i++]);
            else if(option=="--trust-native")trustNative=true;
            else if(option=="--macho" && i<argc){rawName=argv[i++];macho=true;}
            else if(option=="--raw" && i+2<argc) {
                rawName=argv[i++];
                base=address(argv[i++]);entry=address(argv[i++]);
            } else throw std::runtime_error("invalid/incomplete option: "+option);
        }
        Session session;
        // Explicit trusted decoder plugins must be registered before resolving
        // a custom raw/ELF architecture, not after the first analysis attempt.
        for(const auto& plugin:plugins)checked(session.loadPlugin(plugin,trustNative));
        if(!rawName.empty()) {
            for(const auto& description:architectureDescriptions())if(description.id==rawName || archName(description.architecture)==rawName)arch=description.architecture;
            if(arch==Arch::kUnknown)throw std::runtime_error("unknown raw architecture (see mint.architectures() in Lua; load its explicitly trusted decoder first)");
        }
        checked(rawName.empty()?session.openPath(argv[1]):macho?session.openMachOPath(argv[1],arch):session.openRawPath(argv[1],arch,base,entry));
        if(!project.empty())checked(session.attachProject(project));checked(session.analyze());
        if(!lua.empty()) {
            std::ifstream file(lua,std::ios::binary);if(!file)throw std::runtime_error("cannot read Lua script");
            std::string source;char bytes[4096];
            while(file.read(bytes,sizeof(bytes)) || file.gcount()) {
                source.append(bytes,static_cast<size_t>(file.gcount()));
                if(source.size()>256*1024)throw std::runtime_error("Lua script exceeds 256 KiB");
            }
            if(!file.eof())throw std::runtime_error("cannot read complete Lua script");
            ScriptOptions options;options.allowEdits=allowEdits;std::string output;
            auto status=runLuaScript(session,source,options,&output);std::cout<<output;checked(status);
        }
        if(!script.empty()) {
            std::ifstream file(script);if(!file)throw std::runtime_error("cannot read script");
            std::string line;size_t number=0;
            while(std::getline(file,line)) {if(++number>10000)throw std::runtime_error("script exceeds 10000 commands");try{command(session,line,allowEdits);}catch(const std::exception& e){throw std::runtime_error("script line "+std::to_string(number)+": "+e.what());}}
        }
        if(i<argc){std::string line;for(;i<argc;++i){if(!line.empty())line+=' ';line+=argv[i];}command(session,line,allowEdits);}
        else if(script.empty() && lua.empty())command(session,"summary");
        return 0;
    }catch(const std::exception& e){std::cerr<<"mint_headless: "<<e.what()<<"\n";return 1;}
}
