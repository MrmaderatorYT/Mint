#include "mint/plugin/plugin_runtime.h"
#include "mint/plugin/architecture_bridge.h"
#include "mint/disasm/disassembler.h"
#include "mint/session.h"
#include "mint/ir/lifter.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <unistd.h>

using namespace mint;
namespace {
size_t checks = 0;
void require(bool condition, const std::string& message) { ++checks; if (!condition) { std::cerr << "FAIL architecture SDK: " << message << '\n'; std::exit(1); } }
struct Context { int mode = 0; size_t calls = 0; } context;
int decode(void* opaque, uint64_t address, const uint8_t* bytes, size_t count, MintArchitectureInstructionV1* out) {
    auto& state = *static_cast<Context*>(opaque); ++state.calls;
    require(bytes && count >= 1 && count <= 4 && out->struct_size == sizeof(*out), "bounded borrowed C ABI input/output");
    out->address = address; out->size = 1; out->flow = MINT_FLOW_NORMAL; std::strcpy(out->mnemonic, "sdk_nop");
    switch (state.mode) {
        case 1: out->size = 5; break;
        case 2: out->flow = 255; break;
        case 3: ++out->address; break;
        case 4: out->struct_size = 0; break;
        case 5: std::memset(out->mnemonic, 'x', sizeof(out->mnemonic)); break;
        case 6: throw std::runtime_error("native C ABI violation");
        case 7: out->flow = MINT_FLOW_JUMP; break;
        case 8: out->target = address; break;
        case 9: out->reserved[0] = 1; break;
        case 10: std::strcpy(out->operands, "injected\nline"); break;
        case 11: return -1;
        case 12: out->flow = MINT_FLOW_CALL; out->target = 0xFEDCBA9876543210ULL; std::strcpy(out->operands, "target64"); break;
    }
    return 0;
}
MintArchitectureDescriptorV1 descriptor(uint8_t id, const char* name) {
    MintArchitectureDescriptorV1 value{}; value.abi_version = MINT_ARCHITECTURE_ABI_V1; value.struct_size = sizeof(value);
    value.architecture = id; value.pointer_size = 8; value.minimum_instruction_size = 1; value.maximum_instruction_size = 4; value.instruction_alignment = 1;
    std::snprintf(value.id, sizeof(value.id), "%s", name); std::strcpy(value.name, "SDK builtin fixture"); value.context = &context; value.decode = decode; return value;
}
MintArchitecturePluginV1 plugin(const MintArchitectureDescriptorV1* descriptions, uint32_t count, const char* id) {
    MintArchitecturePluginV1 value{}; value.abi_version = MINT_ARCHITECTURE_ABI_V1; value.struct_size = sizeof(value);
    std::snprintf(value.id, sizeof(value.id), "%s", id); std::strcpy(value.title, "SDK builtin plugin"); value.architecture_count = count; value.architectures = descriptions; return value;
}
bool exists(uint8_t id) { ArchitectureDescription value; return architectureDescription(static_cast<Arch>(id), &value); }
int semanticMode=0;
int semanticDecode(void*,uint64_t address,const uint8_t* bytes,size_t count,MintArchitectureInstructionV1* out){if(!count||(bytes[0]!=0xff&&count<2))return -1;out->address=address;out->instruction_id=bytes[0]==0xff?2:1;out->size=bytes[0]==0xff?1:2;out->flow=bytes[0]==0xff?MINT_FLOW_RETURN:MINT_FLOW_NORMAL;std::strcpy(out->mnemonic,bytes[0]==0xff?"return":"move");return 0;}
int semanticLift(void*,uint64_t,const uint8_t* bytes,size_t,MintSemanticFragmentV2* out){out->operation_count=1;auto& operation=out->operations[0];if(bytes[0]==0xff){operation.op=MINT_IR_RETURN;operation.a={0,MINT_VALUE_CONSTANT,8,{}};}else{operation.op=MINT_IR_COPY;operation.destination={0,MINT_VALUE_REGISTER,8,{}};operation.a={bytes[1],MINT_VALUE_CONSTANT,8,{}};}
    if(semanticMode==1)operation.destination.width=3;if(semanticMode==2)operation.a={63,MINT_VALUE_TEMP,8,{}};if(semanticMode==3)operation.op=999;if(semanticMode==4)out->operation_count=65;return 0;
}
void semanticLifter(){
    auto desc=descriptor(183,"sdk-semantic");desc.minimum_instruction_size=1;desc.maximum_instruction_size=2;desc.context=nullptr;desc.decode=semanticDecode;auto base=plugin(&desc,1,"sdk-semantic-plugin");
    MintArchitectureRegisterV2 registers[2]{};registers[0].byte_offset=0;registers[0].width=8;std::strcpy(registers[0].name,"r0");registers[1].byte_offset=8;registers[1].width=8;std::strcpy(registers[1].name,"sp");
    MintArchitectureSemanticsV2 semantic{};semantic.abi_version=2;semantic.struct_size=sizeof(semantic);semantic.architecture=183;semantic.pointer_size=8;semantic.register_file_bytes=16;semantic.register_count=2;semantic.registers=registers;semantic.stack_pointer_offset=8;semantic.return_register_offset=0;semantic.argument_count=1;semantic.argument_offsets[0]=0;semantic.lift=semanticLift;
    MintArchitecturePluginV2 item{2,sizeof(MintArchitecturePluginV2),&base,1,&semantic};auto pristine=semantic;semantic.return_register_offset=7;require(!registerArchitecturePluginV2(&item).ok()&&!exists(183),"invalid ABI register slices cannot publish decoder/lifter");semantic=pristine;require(registerArchitecturePluginV2(&item).ok(),"register decoder and semantic ABI2 atomically");
    MintArchitectureSemanticsV2 copied{};require(architecturePluginAbi(static_cast<Arch>(183),&copied)&&copied.argument_offsets[0]==0&&std::strcmp(copied.registers[0].name,"r0")==0,"immutable copied ABI exposes exact argument/return register layout");registers[0].width=1;require(copied.registers[0].width==8,"caller metadata mutations cannot change process register table");
    Lifter lifter;require(lifter.open(static_cast<Arch>(183)).ok()&&lifter.ready(),"custom lifter opens without fake Capstone handle");const u8 code[]={0x10,7};IrFunction ir;ir.arch=static_cast<Arch>(183);IrBuilder builder(&ir);require(lifter.liftInstruction(0x1000,ByteView(code,2),&builder)==2&&ir.insns.size()==1&&ir.insns[0].op==MintOp::kCopy&&ir.insns[0].a.offset==7&&ir.intrinsicCount==0,"custom semantic fragment contributes validated exact IR");
    for(semanticMode=1;semanticMode<=4;++semanticMode){IrFunction failed;IrBuilder output(&failed);require(lifter.liftInstruction(0x1000,ByteView(code,2),&output)==2&&failed.insns.size()==1&&failed.intrinsicCount==1&&failed.insns[0].op==MintOp::kIntrinsic,"malformed fragment becomes one explicit intrinsic without partial semantic writes");}semanticMode=0;
}
void boundedValidation() {
    const auto before = architectureDescriptions().size(); auto description = descriptor(151, "sdk-one"); auto item = plugin(&description, 1, "sdk-builtin");
    auto bad = item; bad.abi_version = 9; require(!registerArchitecturePlugin(&bad).ok(), "plugin version rejected");
    bad = item; --bad.struct_size; require(!registerArchitecturePlugin(&bad).ok(), "plugin exact POD size rejected");
    bad = item; bad.architecture_count = 0; require(!registerArchitecturePlugin(&bad).ok(), "empty architecture table rejected");
    bad = item; bad.architecture_count = 9; require(!registerArchitecturePlugin(&bad).ok(), "architecture table cap");
    bad = item; std::memset(bad.id, 'x', sizeof(bad.id)); require(!registerArchitecturePlugin(&bad).ok(), "unterminated plugin ID rejected");
    const auto pristine = description;
    description.abi_version = 0; require(!registerArchitecturePlugin(&item).ok(), "decoder version rejected"); description = pristine;
    description.struct_size = 0; require(!registerArchitecturePlugin(&item).ok(), "decoder POD size rejected"); description = pristine;
    description.architecture = 1; require(!registerArchitecturePlugin(&item).ok(), "builtins cannot be replaced"); description = pristine;
    description.pointer_size = 16; require(!registerArchitecturePlugin(&item).ok(), "pointer width bounded"); description = pristine;
    description.instruction_alignment = 3; require(!registerArchitecturePlugin(&item).ok(), "non-power-of-two alignment rejected"); description = pristine;
    description.elf_class = 1; description.elf_machine = 999; require(!registerArchitecturePlugin(&item).ok(), "ELF class/pointer-width mismatch rejected"); description = pristine;
    description.reserved[0] = 1; require(!registerArchitecturePlugin(&item).ok(), "reserved flags rejected"); description = pristine;
    description.decode = nullptr; require(!registerArchitecturePlugin(&item).ok(), "no callback rejected"); description = pristine;
    MintArchitectureDescriptorV1 batch[] = {description, descriptor(152, "sdk-two")}; auto table = plugin(batch, 2, "sdk-batch");
    batch[1].minimum_instruction_size = 0; require(!registerArchitecturePlugin(&table).ok() && !exists(151), "invalid second descriptor cannot publish first");
    batch[1] = descriptor(151, "sdk-two"); require(!registerArchitecturePlugin(&table).ok() && !exists(151), "duplicate batch IDs roll back staged callback slots");
    batch[1] = descriptor(152, "aarch64"); require(!registerArchitecturePlugin(&table).ok() && !exists(151), "native registry collision rejects whole staged C table");
    require(architectureDescriptions().size() == before, "failed tables do not change process registry");
    batch[1] = descriptor(152, "sdk-two"); require(registerArchitecturePlugin(&table).ok() && exists(151) && exists(152), "valid table publishes both after rollback failures");
    require(!registerArchitecturePlugin(&table).ok(), "registered IDs never replaced");
    Disassembler decoder; require(decoder.open(static_cast<Arch>(151)).ok(), "open registered builtin C decoder"); const uint8_t bytes[] = {0, 1, 2, 3, 4, 5}; DecodedInsn out;
    require(decoder.decodeVerbose(0xF000000000001000ULL, ByteView(bytes, sizeof(bytes)), &out) && out.record.address == 0xF000000000001000ULL && out.record.size == 1 && out.mnemonic == "sdk_nop" && out.bytes[0] == 0, "exact64-bit decoded record/text/raw bytes");
    for (int mode = 1; mode <= 11; ++mode) { context.mode = mode; require(!decoder.decodeVerbose(0xF000000000001000ULL, ByteView(bytes, sizeof(bytes)), &out) && out.record.flow == FlowKind::kInvalid && out.mnemonic.empty(), "invalid/throwing/undecodable callback never publishes a partial result"); }
    context.mode = 12; require(decoder.decodeVerbose(0xF000000000001000ULL, ByteView(bytes, sizeof(bytes)), &out) && out.record.target == 0xFEDCBA9876543210ULL && out.record.flow == FlowKind::kCall, "C target address retains full64 bits"); context.mode = 0;
}
void dynamicLifetime(const char* architectureLibrary, const char* commandLibrary) {
    const auto custom = static_cast<Arch>(180); const uint8_t bytes[] = {0, 255};
    { PluginManager manager;
        require(!manager.load(architectureLibrary, false).ok() && !exists(180), "native trust required before decoder loading");
        require(manager.load(architectureLibrary, true).ok(), "decoder-only library registers without command export");
        require(manager.commandsText().find("sdk-toy64") != std::string::npos, "decoder metadata visible without lifter claims");
        require(!manager.load(architectureLibrary, true).ok(), "duplicate dynamic decoder registration fails safely");
    }
    Disassembler decoder; DecodedInsn out; require(decoder.open(custom).ok() && decoder.decodeVerbose(0x8000000000001000ULL, ByteView(bytes + 1, 1), &out) && out.record.flow == FlowKind::kReturn, "decoder DSO remains callable after PluginManager destruction");
    uint8_t jump[9] = {16}; const Address target = 0xFEDCBA9876543210ULL; for (unsigned i = 0; i < 8; ++i) jump[i + 1] = static_cast<uint8_t>(target >> (i * 8));
    require(decoder.decodeVerbose(0x8000000000001000ULL, ByteView(jump, sizeof(jump)), &out) && out.record.target == target && out.record.flow == FlowKind::kCondJump, "dynamic C decoder preserves high-bit branch target");
    char input[] = "/private/tmp/mint-architecture-input-XXXXXX"; const int fd = mkstemp(input);
    require(fd >= 0 && write(fd, bytes, sizeof(bytes)) == sizeof(bytes), "create owned raw fixture"); close(fd);
    { Session session;
        require(session.loadPlugin(commandLibrary, true).ok(), "load explicit command plugin before import");
        require(session.openRawPath(input, custom, 0x8000000000001000ULL, 0x8000000000001000ULL).ok() && session.analyze().ok(), "registered decoder participates in actual raw binary analysis");
        std::string output; require(session.runPlugin("sample/inventory", "", false, &output).ok(), "preloaded command registrations survive first beginOpen");
        require(session.openRawPath(input, custom, 0x8000000000001000ULL, 0x8000000000001000ULL).ok() && session.analyze().ok() && session.runPlugin("sample/inventory", "", false, &output).ok(), "same-Session reopen retains explicitly selected commands");
        const auto pseudoC = session.decompiledCFor(0x8000000000001000ULL); require(pseudoC.find("unsupported") != std::string::npos || pseudoC.find("no lifter") != std::string::npos || pseudoC.find("Unsupported") != std::string::npos, "decoder-only extension does not invent a lifter/decompiler");
    }
    Session fresh; require(fresh.pluginCommandsText().find("sample/inventory") == std::string::npos, "new Session never automatically loads command library");
    require(decoder.decodeVerbose(0x8000000000001000ULL, ByteView(bytes, sizeof(bytes)), &out) && out.mnemonic == "nop", "decoder remains callable after Session replacement/destruction");
    char project[] = "/private/tmp/mint-architecture-project-XXXXXX"; const int projectFd = mkstemp(project);
    require(projectFd >= 0, "reserve exact owned project path"); close(projectFd);
    require(unlink(project) == 0, "new project starts at a reserved absent path");
    {
        Session first;
        require(first.openRawPath(input, static_cast<Arch>(151), 0x1000, 0x1000).ok() && first.attachProject(project).ok(), "persist custom decoder identity");
        require(first.memoryBlocksText().find("sdk-one") != std::string::npos, "custom decoder identity appears in memory view");
        Session same;
        require(same.openRawPath(input, static_cast<Arch>(151), 0x1000, 0x1000).ok() && same.attachProject(project).ok(), "same custom decoder can reopen its project");
        Session different;
        require(different.openRawPath(input, static_cast<Arch>(152), 0x1000, 0x1000).ok() && !different.attachProject(project).ok(), "different custom decoder cannot reuse identical bytes/base/entry project");
    }
    require(unlink(project) == 0, "remove exact owned project fixture");
    require(unlink(input) == 0, "remove exact owned raw fixture");
}
} // namespace
int main(int argc, char** argv) {
    require(argc == 3||argc==4, "usage: mint_architecture_sdk_test DECODER_LIBRARY COMMAND_LIBRARY [SEMANTICS_LIBRARY]");
    boundedValidation();semanticLifter(); dynamicLifetime(argv[1], argv[2]);
    if(argc==4){PluginManager manager;require(manager.load(argv[3],true).ok(),"load actual C ABI2 lifter shared library");Lifter lifter;require(lifter.open(static_cast<Arch>(185)).ok(),"open dynamic native custom lifter");const u8 code[]={0x10,42};IrFunction ir;IrBuilder builder(&ir);require(lifter.liftInstruction(0x1000,ByteView(code,2),&builder)==2&&ir.insns.size()==1&&ir.insns[0].a.offset==42&&ir.intrinsicCount==0,"dynamic ABI2 DSO provides validated IR semantics");
        char path[]="/private/tmp/mint-custom-lifter-XXXXXX";const int fd=mkstemp(path);const u8 function[]={0x10,42,0xff};require(fd>=0&&write(fd,function,sizeof(function))==sizeof(function),"create actual custom ISA function fixture");close(fd);
        const std::string projectPath=std::string(path)+".mint";
        {Session program;require(program.openRawPath(path,static_cast<Arch>(185),0x1000,0x1000).ok()&&program.attachProject(projectPath).ok()&&program.analyze().ok(),"custom native ISA analyzes through ordinary persistent Session pipeline");require(program.irTextFor(0x1000).find("0x2a")!=std::string::npos,"custom IR reaches Session listing API");require(program.editAnnotation(0x1000,"prototype","uint64_t(void)").ok()&&program.abiText(0x1000).find("plugin")!=std::string::npos,"custom ABI declaration reaches authoritative Program storage model");const auto c=program.decompiledCFor(0x1000);require(c.find("42")!=std::string::npos||c.find("0x2a")!=std::string::npos,"actual custom lifter semantics reach pseudo-C output");}
        unlink(projectPath.c_str());unlink((projectPath+".analysis").c_str());
        require(unlink(path)==0,"remove exact custom ISA fixture");}
    std::cout << "Architecture C SDK: " << checks << " checks; passed\n";
}
