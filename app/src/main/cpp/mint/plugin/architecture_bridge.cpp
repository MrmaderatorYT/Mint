#include "mint/plugin/architecture_bridge.h"
#include "mint/disasm/disassembler.h"
#include <algorithm>
#include <array>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <sstream>
#include <set>
#include <climits>
#include <utility>

namespace mint {
namespace {
struct Decoder { MintArchitectureDescriptorV1 descriptor{};MintArchitectureSemanticsV2 semantics{};std::vector<MintArchitectureRegisterV2> registers; std::mutex mutex; };
struct Registry {
    std::mutex mutex;
    std::array<std::shared_ptr<Decoder>, 127> decoders;
    std::map<std::string, std::string> plugins;
    std::vector<void*> pinnedLibraries; // Deliberately no dlclose, even at teardown.
};
Registry& state() { static Registry value; return value; }
template<size_t N> bool text(const char (&value)[N], bool identifier = false) {
    const auto* end = static_cast<const char*>(std::memchr(value, 0, N));
    if (!end || end == value) return false;
    for (auto at = value; at != end; ++at) {
        const auto c = static_cast<unsigned char>(*at);
        if (identifier ? !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') : (c < 32 || c == 127)) return false;
    }
    return true;
}
template<size_t N> bool zero(const uint8_t (&value)[N]) { return std::all_of(value, value + N, [](uint8_t c) { return c == 0; }); }
bool adapt(size_t index, Address address, ByteView code, DecodedInsn* output) {
    if (!output || index >= state().decoders.size()) return false;
    std::shared_ptr<Decoder> decoder;
    { std::lock_guard<std::mutex> guard(state().mutex); decoder = state().decoders[index]; }
    if (!decoder) return false;
    const auto& descriptor = decoder->descriptor;
    if (code.size() < descriptor.minimum_instruction_size || address % descriptor.instruction_alignment) return false;
    MintArchitectureInstructionV1 raw{}; raw.struct_size = sizeof(raw); raw.address = address; raw.target = MINT_ARCHITECTURE_NO_TARGET;
    int result = -1;
    try { std::lock_guard<std::mutex> guard(decoder->mutex); result = descriptor.decode(descriptor.context, address, code.data(), std::min<size_t>(code.size(), descriptor.maximum_instruction_size), &raw); }
    catch (...) { return false; }
    if (result || raw.struct_size != sizeof(raw) || raw.address != address || raw.size < descriptor.minimum_instruction_size ||
        raw.size > descriptor.maximum_instruction_size || raw.size > code.size() || raw.flow > MINT_FLOW_TRAP || !zero(raw.reserved) ||
        !text(raw.mnemonic) || !std::memchr(raw.operands, 0, sizeof(raw.operands)) || address > kNoAddress - raw.size) return false;
    const bool direct = raw.flow == MINT_FLOW_JUMP || raw.flow == MINT_FLOW_CONDITIONAL_JUMP || raw.flow == MINT_FLOW_CALL;
    if (direct != (raw.target != MINT_ARCHITECTURE_NO_TARGET)) return false;
    for (const char* at = raw.operands; *at; ++at) if (static_cast<unsigned char>(*at) < 32 || *at == 127) return false;
    DecodedInsn candidate; candidate.record = {address, raw.target, raw.instruction_id, raw.size, static_cast<FlowKind>(raw.flow)};
    candidate.mnemonic = raw.mnemonic; candidate.operands = raw.operands; std::memcpy(candidate.bytes, code.data(), raw.size);
    *output = std::move(candidate); return true;
}
template<size_t I> bool thunk(Address address, ByteView code, DecodedInsn* output) { return adapt(I, address, code, output); }
template<size_t... I> constexpr std::array<ArchitectureDecode, sizeof...(I)> thunks(std::index_sequence<I...>) { return {{&thunk<I>...}}; }
constexpr auto kThunks = thunks(std::make_index_sequence<127>{});
Status bad(const char* message) { return Status::error(ErrorCode::kBadFormat, std::string("architecture plugin: ") + message); }
} // namespace

Status registerArchitecturePluginImpl(const MintArchitecturePluginV1* plugin,const MintArchitecturePluginV2* extensions, void* libraryHandle) {
    if (!plugin || plugin->abi_version != MINT_ARCHITECTURE_ABI_V1 || plugin->struct_size != sizeof(*plugin) ||
        !text(plugin->id, true) || !text(plugin->title) || !plugin->architecture_count || plugin->architecture_count > 8 || !plugin->architectures) return bad("invalid descriptor or ABI");
    std::vector<std::shared_ptr<Decoder>> decoders; std::vector<ArchitectureDescription> descriptions;
    try {
        for (u32 i = 0; i < plugin->architecture_count; ++i) {
            const auto& source = plugin->architectures[i];
            if (source.abi_version != MINT_ARCHITECTURE_ABI_V1 || source.struct_size != sizeof(source) || source.architecture < 128 || source.architecture == 255 ||
                !text(source.id, true) || !text(source.name) || !zero(source.reserved) || !source.decode ||
                (source.pointer_size != 4 && source.pointer_size != 8) || !source.minimum_instruction_size || source.minimum_instruction_size > source.maximum_instruction_size ||
                source.maximum_instruction_size > 16 || !source.instruction_alignment || source.instruction_alignment > source.minimum_instruction_size ||
                (source.instruction_alignment & (source.instruction_alignment - 1)) || source.elf_class > 2 ||
                ((source.elf_class == 0) != (source.elf_machine == 0)) || (source.elf_class && source.pointer_size != (source.elf_class == 1 ? 4 : 8))) return bad("invalid architecture metadata");
            auto decoder = std::make_shared<Decoder>(); decoder->descriptor = source;
            if(extensions)for(u32 j=0;j<extensions->semantics_count;++j)if(extensions->semantics[j].architecture==source.architecture){decoder->semantics=extensions->semantics[j];decoder->registers.assign(decoder->semantics.registers,decoder->semantics.registers+decoder->semantics.register_count);decoder->semantics.registers=decoder->registers.data();}
            decoders.push_back(std::move(decoder));
            descriptions.push_back({static_cast<Arch>(source.architecture), source.id, source.name, source.pointer_size, source.minimum_instruction_size,
                source.maximum_instruction_size, source.instruction_alignment, source.elf_machine, source.elf_class, false, kThunks[source.architecture - 128]});
        }
        std::lock_guard<std::mutex> guard(state().mutex);
        if (state().plugins.size() >= 32 || state().plugins.count(plugin->id)) return bad("duplicate plugin ID or plugin budget exceeded");
        for (const auto& decoder : decoders) if (state().decoders[decoder->descriptor.architecture - 128]) return bad("architecture ID already registered");
        auto nextPlugins = state().plugins; nextPlugins.emplace(plugin->id, plugin->title);
        // Allocate the pin before publication; no allocation/failure can close a
        // DSO after its callback has become observable in the permanent registry.
        if (libraryHandle) state().pinnedLibraries.push_back(libraryHandle);
        for (const auto& decoder : decoders) state().decoders[decoder->descriptor.architecture - 128] = decoder;
        struct Rollback {
            const std::vector<std::shared_ptr<Decoder>>& decoders;
            bool library, armed = true;
            ~Rollback() { if (!armed) return; for (const auto& decoder : decoders) state().decoders[decoder->descriptor.architecture - 128].reset(); if (library) state().pinnedLibraries.pop_back(); }
        } rollback{decoders, libraryHandle != nullptr};
        const auto status = registerArchitectureDescriptions(descriptions);
        if (!status.ok()) return status;
        rollback.armed = false;
        state().plugins.swap(nextPlugins); return Status::success();
    } catch (...) { return Status::error(ErrorCode::kInternalError, "architecture plugin allocation failed before publication"); }
}
Status registerArchitecturePlugin(const MintArchitecturePluginV1* plugin,void* libraryHandle){return registerArchitecturePluginImpl(plugin,nullptr,libraryHandle);}
Status registerArchitecturePluginV2(const MintArchitecturePluginV2* plugin,void* libraryHandle){
    if(!plugin||plugin->abi_version!=MINT_ARCHITECTURE_ABI_V2||plugin->struct_size!=sizeof(*plugin)||!plugin->decoders||!plugin->semantics_count||plugin->semantics_count>8||!plugin->semantics)return bad("invalid semantics ABI2 table");
    if(!plugin->decoders->architectures||plugin->decoders->architecture_count>8)return bad("invalid decoder table for semantics");std::set<u8> architectures;
    for(u32 i=0;i<plugin->semantics_count;++i){const auto& sem=plugin->semantics[i];if(sem.abi_version!=MINT_ARCHITECTURE_ABI_V2||sem.struct_size!=sizeof(sem)||sem.architecture<128||sem.architecture==255||!architectures.insert(sem.architecture).second||!zero(sem.reserved)||!sem.lift||!sem.registers||!sem.register_count||sem.register_count>1024||!sem.register_file_bytes||sem.register_file_bytes>65536||sem.argument_count>16)return bad("invalid semantic architecture");
        const MintArchitectureDescriptorV1* desc=nullptr;for(u32 j=0;j<plugin->decoders->architecture_count;++j)if(plugin->decoders->architectures[j].architecture==sem.architecture)desc=&plugin->decoders->architectures[j];if(!desc||sem.pointer_size!=desc->pointer_size)return bad("semantics must match a decoder and its pointer width");
        std::set<std::string> names;for(u32 j=0;j<sem.register_count;++j){const auto& reg=sem.registers[j];if(!zero(reg.reserved)||!text(reg.name)||!names.insert(reg.name).second||(reg.width!=1&&reg.width!=2&&reg.width!=4&&reg.width!=8&&reg.width!=16)||reg.width>sem.register_file_bytes||reg.byte_offset>sem.register_file_bytes-reg.width)return bad("invalid semantic register layout");}
        const auto exact=[&](u32 offset){return offset==UINT32_MAX||std::any_of(sem.registers,sem.registers+sem.register_count,[&](const MintArchitectureRegisterV2& reg){return reg.byte_offset==offset&&reg.width==sem.pointer_size;});};
        if(!exact(sem.stack_pointer_offset)||!exact(sem.return_register_offset))return bad("ABI special registers need exact pointer-width slices");std::set<u32> args;for(u32 j=0;j<sem.argument_count;++j)if(sem.argument_offsets[j]==UINT32_MAX||!exact(sem.argument_offsets[j])||!args.insert(sem.argument_offsets[j]).second)return bad("invalid ABI argument register");
    }return registerArchitecturePluginImpl(plugin->decoders,plugin,libraryHandle);
}
bool architecturePluginAbi(Arch arch,MintArchitectureSemanticsV2* output){const auto id=static_cast<u8>(arch);if(id<128||id==255)return false;std::lock_guard<std::mutex> guard(state().mutex);const auto& decoder=state().decoders[id-128];if(!decoder||!decoder->semantics.lift)return false;if(output)*output=decoder->semantics;return true;}
bool architecturePluginHasLifter(Arch arch){return architecturePluginAbi(arch,nullptr);}
u32 liftArchitecturePlugin(Arch arch,Address address,ByteView bytes,IrBuilder* builder){
    if(!builder)return 0;const auto id=static_cast<u8>(arch);if(id<128||id==255)return 0;std::shared_ptr<Decoder> decoder;{std::lock_guard<std::mutex> guard(state().mutex);decoder=state().decoders[id-128];}if(!decoder||!decoder->semantics.lift)return 0;
    DecodedInsn decoded;if(!adapt(id-128,address,bytes,&decoded))return 0;
    MintSemanticFragmentV2 raw{};raw.struct_size=sizeof(raw);raw.instruction_size=decoded.record.size;int result=-1;try{std::lock_guard<std::mutex> guard(decoder->mutex);result=decoder->semantics.lift(decoder->semantics.context,address,bytes.data(),decoded.record.size,&raw);}catch(...){result=-1;}
    auto reject=[&](){builder->setAddress(address);builder->emitIntrinsic(decoded.record.id);return static_cast<u32>(decoded.record.size);};
    if(result||raw.struct_size!=sizeof(raw)||raw.instruction_size!=decoded.record.size||raw.operation_count>64||raw.temporary_count>64||!zero(raw.reserved))return reject();
    static const MintOp ops[]={MintOp::kInvalid,MintOp::kCopy,MintOp::kLoad,MintOp::kStore,MintOp::kAdd,MintOp::kSub,MintOp::kMul,MintOp::kAnd,MintOp::kOr,MintOp::kXor,MintOp::kNot,MintOp::kNeg,MintOp::kShl,MintOp::kShrU,MintOp::kShrS,MintOp::kEqual,MintOp::kNotEqual,MintOp::kLessU,MintOp::kLessS,MintOp::kLessEqU,MintOp::kLessEqS,MintOp::kZeroExt,MintOp::kSignExt,MintOp::kTrunc,MintOp::kSelect,MintOp::kBranch,MintOp::kCondBranch,MintOp::kBranchInd,MintOp::kCall,MintOp::kCallInd,MintOp::kReturn,MintOp::kTrap,MintOp::kUndefined};
    std::array<u8,64> temporaryWidths{};std::array<bool,64> defined{};IrFunction fragment;fragment.arch=arch;fragment.tempCount=raw.temporary_count;IrBuilder scratch(&fragment);scratch.setAddress(address);bool invalid=false;
    auto value=[&](const MintSemanticValueV2& source,bool destination)->Varnode{
        if(!zero(source.reserved)||source.space>3){invalid=true;return {};}
        if(source.space==MINT_VALUE_NONE){if(source.width||source.value)invalid=true;return {};}
        if(source.width!=1&&source.width!=2&&source.width!=4&&source.width!=8&&source.width!=16){invalid=true;return {};}
        if(source.space==MINT_VALUE_CONSTANT){if(destination||source.width>8||(source.width<8&&(source.value>>(source.width*8))))invalid=true;return Varnode::constant(source.value,source.width);}
        if(source.space==MINT_VALUE_REGISTER){if(source.width>decoder->semantics.register_file_bytes||source.value>decoder->semantics.register_file_bytes-source.width||std::none_of(decoder->registers.begin(),decoder->registers.end(),[&](const MintArchitectureRegisterV2& reg){return source.value>=reg.byte_offset&&source.value-reg.byte_offset+source.width<=reg.width;}))invalid=true;return Varnode::reg(source.value,source.width);}
        if(source.value>=raw.temporary_count){invalid=true;return {};}
        const auto index=static_cast<size_t>(source.value);if(!destination&&!defined[index])invalid=true;if(temporaryWidths[index]&&temporaryWidths[index]!=source.width)invalid=true;temporaryWidths[index]=source.width;return Varnode::temp(source.value,source.width);
    };
    for(u32 i=0;i<raw.operation_count;++i){const auto& source=raw.operations[i];if(!source.op||source.op>=sizeof(ops)/sizeof(ops[0])||source.reserved)return reject();const auto a=value(source.a,false),b=value(source.b,false),c=value(source.c,false),dest=value(source.destination,true);if(invalid)return reject();scratch.emit(ops[source.op],dest,a,b,c);if(dest.isTemp())defined[dest.offset]=true;}
    IrBlock block;block.start=address;block.end=address+decoded.record.size;block.insnCount=fragment.insns.size();fragment.blocks.push_back(block);if(!fragment.verify().empty())return reject();
    MintOp control=MintOp::kInvalid;Address target=kNoAddress;for(const auto& insn:fragment.insns)if(insn.op==MintOp::kBranch||insn.op==MintOp::kCondBranch||insn.op==MintOp::kBranchInd||insn.op==MintOp::kCall||insn.op==MintOp::kCallInd||insn.op==MintOp::kReturn||insn.op==MintOp::kTrap){if(control!=MintOp::kInvalid)return reject();const auto& destination=insn.op==MintOp::kCondBranch?insn.b:insn.a;if(insn.op!=MintOp::kTrap&&destination.size!=decoder->semantics.pointer_size)return reject();control=insn.op;target=destination.isConstant()?destination.offset:kNoAddress;}
    const MintOp expected[]={MintOp::kInvalid,MintOp::kBranch,MintOp::kCondBranch,MintOp::kCall,MintOp::kBranchInd,MintOp::kCallInd,MintOp::kReturn,MintOp::kTrap,MintOp::kInvalid};
    if(static_cast<unsigned>(decoded.record.flow)>=sizeof(expected)/sizeof(expected[0])||control!=expected[static_cast<unsigned>(decoded.record.flow)]||(decoded.record.hasKnownTarget()&&target!=decoded.record.target))return reject();
    auto* function=builder->function();const u32 offset=function->tempCount;if(offset>UINT32_MAX-raw.temporary_count)return reject();function->insns.reserve(function->insns.size()+fragment.insns.size());function->tempCount+=raw.temporary_count;builder->setAddress(address);
    for(auto insn:fragment.insns){for(auto* node:{&insn.dest,&insn.a,&insn.b,&insn.c})if(node->isTemp())node->offset+=offset;builder->emit(insn.op,insn.dest,insn.a,insn.b,insn.c);}return decoded.record.size;
}
std::string architecturePluginsText() {
    std::lock_guard<std::mutex> guard(state().mutex); std::ostringstream out;
    out << "Architecture SDK ABI1 decoders / ABI2 verified lifters and register ABI; process-lifetime registry.\n";
    for (const auto& plugin : state().plugins) out << plugin.first << "\t" << plugin.second << '\n';
    for (const auto& decoder : state().decoders) if (decoder) out << "  arch=" << unsigned(decoder->descriptor.architecture) << " " << decoder->descriptor.id << " " << decoder->descriptor.name << (decoder->semantics.lift?" [verified IR lifter / ABI]":" [decoder only]") << '\n';
    return out.str();
}
} // namespace mint
