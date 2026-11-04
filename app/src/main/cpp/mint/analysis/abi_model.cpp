#include "mint/analysis/abi_model.h"

#include <algorithm>
#include <sstream>
#include "mint/analysis/local_variables.h"
#include "mint/ir/registers.h"
#include "mint/plugin/architecture_bridge.h"
#include "mint/disasm/disassembler.h"

namespace mint {
namespace {
u64 rounded(u64 value,u64 alignment) {return (value+alignment-1)/alignment*alignment;}
bool aggregate(const DataTypeLayout& t){return t.kind==DataTypeKind::kStruct||t.kind==DataTypeKind::kUnion||t.kind==DataTypeKind::kArray;}
struct Builder {
    Arch arch;const UserPrototype& prototype;AbiTypeResolver resolver;AbiModel model;
    std::vector<u64> gp,fp;u32 nextGp=0,nextFp=0,nextPosition=0;u64 stack=0;u8 word=8,flen=0;
    Builder(Arch architecture,const UserPrototype& declaration,AbiTypeResolver layouts)
        :arch(architecture),prototype(declaration),resolver(std::move(layouts)){}
    bool riscv() const {return arch==Arch::kRiscV32||arch==Arch::kRiscV64;}
    Status layout(const std::string& type,DataTypeLayout* result) {
        const auto expression=localTypeExpression(type);
        if(expression=="void") {*result={};result->expression="void";return Status::success();}
        if(!expression.empty() && expression.back()=='*') {*result={};result->kind=DataTypeKind::kPointer;result->expression=expression;result->size=word;result->alignment=word;return Status::success();}
        auto status=resolver(expression,result);if(!status.ok())return status;
        if(!result->size || result->size>1024*1024 || !result->alignment || result->alignment>16 || (result->alignment&(result->alignment-1)))return Status::error(ErrorCode::kUnsupported,"ABI layout must have known size <=1 MiB and power-of-two alignment <=16");
        return Status::success();
    }
    AbiStoragePiece reg(u64 offset,u8 width,u64 valueOffset=0,bool floating=false) {
        const u8 storageWidth=floating ? (riscv()?8:16) : word;
        return {AbiStorageKind::kRegister,Varnode::reg(offset,storageWidth),0,valueOffset,width,floating,floating&&riscv()&&width<storageWidth};
    }
    struct FlatField {u64 offset;u8 width;bool floating;};
    bool flattenRiscV(const DataTypeLayout& type,u64 offset,std::vector<FlatField>* fields,bool* incomplete,unsigned depth=0) {
        if(depth>32){*incomplete=true;return false;}
        if(fields->size()>2)return false;
        if(type.kind==DataTypeKind::kUnion)return false;
        if(type.kind==DataTypeKind::kArray) {
            if(type.elementType.empty() || !type.elementCount){*incomplete=true;return false;}
            if(type.elementCount>2)return false;
            DataTypeLayout element;if(!layout(type.elementType,&element).ok() || !element.size || type.size/element.size!=type.elementCount || type.size%element.size){*incomplete=true;return false;}
            for(u64 n=0;n<type.elementCount;++n)if(!flattenRiscV(element,offset+n*element.size,fields,incomplete,depth+1))return false;
            return true;
        }
        if(type.kind==DataTypeKind::kStruct) {
            if(type.fields.empty()){*incomplete=true;return false;}
            u64 end=0;
            for(const auto& field:type.fields) {
                DataTypeLayout child;
                if(!layout(field.type,&child).ok() || field.offset<end || field.offset>type.size || child.size>type.size-field.offset){*incomplete=true;return false;}
                end=field.offset+child.size;
                if(!flattenRiscV(child,offset+field.offset,fields,incomplete,depth+1))return false;
            }
            return true;
        }
        if(!type.size || type.size>(type.isFloating?flen:word))return false;
        if(type.isFloating && type.size!=4 && type.size!=8)return false;
        fields->push_back({offset,static_cast<u8>(type.size),type.isFloating});return fields->size()<=2;
    }
    Status assignRiscV(const DataTypeLayout& type,AbiValue* value,bool result) {
        // Hard-float eligibility is independent of aggregate padding/alignment.
        // Both banks must have space before either is consumed; a failed mixed
        // classification falls back as a whole to the integer convention.
        if(flen && (type.isFloating || type.kind==DataTypeKind::kStruct)) {
            std::vector<FlatField> fields;
            bool incomplete=false;
            const bool flattened=flattenRiscV(type,0,&fields,&incomplete);
            if(incomplete)return Status::error(ErrorCode::kUnsupported,"RISC-V aggregate flattening requires complete bounded field/array layouts");
            if(flattened && !fields.empty()) {
                const u32 floats=static_cast<u32>(std::count_if(fields.begin(),fields.end(),[](const auto& f){return f.floating;}));
                const u32 integers=static_cast<u32>(fields.size())-floats;
                u32 fi=result?0:nextFp,gi=result?0:nextGp;
                if(floats && integers<=1 && fi+floats<=fp.size() && gi+integers<=gp.size()) {
                    for(const auto& field:fields)value->pieces.push_back(reg(field.floating?fp[fi++]:gp[gi++],field.width,field.offset,field.floating));
                    if(!result){nextFp=fi;nextGp=gi;}return Status::success();
                }
            }
        }
        const bool indirect=type.size>u64(word)*2;
        if(indirect && result)return hiddenReturn(type);
        value->indirect=indirect;
        auto storageType=type;if(indirect){storageType.size=word;storageType.alignment=word;storageType.isFloating=false;}
        const u64 size=storageType.size;const u32 count=static_cast<u32>((size+word-1)/word);
        if(result) {for(u32 n=0;n<count;++n)value->pieces.push_back(reg(gp[n],static_cast<u8>(std::min<u64>(word,size-n*word)),n*word));return Status::success();}
        const u32 available=static_cast<u32>(gp.size())-nextGp;
        const u32 registers=std::min(count,available);
        // Named arguments need no even-register pairing, even in a variadic
        // declaration. The special aligned-pair rule is for unnamed va_args.
        for(u32 n=0;n<registers;++n){auto piece=reg(gp[nextGp++],static_cast<u8>(std::min<u64>(word,size-n*word)),n*word);
            if(indirect)piece.kind=AbiStorageKind::kIndirect;value->pieces.push_back(piece);}
        if(registers<count) {
            const size_t first=value->pieces.size();const u64 consumed=u64(registers)*word;
            if(consumed){storageType.size-=consumed;storageType.alignment=word;}
            onStack(value,storageType,indirect);
            for(size_t n=first;n<value->pieces.size();++n)value->pieces[n].valueOffset+=consumed;
        }
        return Status::success();
    }
    void onStack(AbiValue* value,const DataTypeLayout& type,bool indirect=false) {
        const u64 skew=model.convention=="sysv64" ? 8 : model.convention=="cdecl32"||model.convention=="stdcall32" ? 4 : 0;
        const u64 alignment=indirect?word:model.convention=="cdecl32"||model.convention=="stdcall32" ? 4 : std::max<u64>(word,std::min<u64>(type.alignment,16));
        stack=rounded(stack-skew,alignment)+skew;
        // Composite bytes are split into bounded pieces, preserving exact offset.
        const u64 size=indirect ? word : type.size;
        for(u64 offset=0;offset<size;offset+=word)value->pieces.push_back({indirect?AbiStorageKind::kIndirect:AbiStorageKind::kStack,{},static_cast<i64>(stack+offset),offset,static_cast<u8>(std::min<u64>(word,size-offset)),type.isFloating});
        if(prototype.byteOrder==ByteOrder::kBig && size<word && !indirect && !aggregate(type))value->pieces.back().stackOffset+=word-size;
        stack+=rounded(size,word);
    }
    bool homogeneous(const DataTypeLayout& type,u8* width,u32* lanes,unsigned depth=0) {
        if(depth>16)return false;
        if(type.kind==DataTypeKind::kPrimitive && type.isFloating){*width=static_cast<u8>(type.size);*lanes=1;return true;}
        if(type.kind==DataTypeKind::kArray) {
            DataTypeLayout element;u8 w=0;u32 n=0;
            if(type.elementType.empty() || !type.elementCount || type.elementCount>4 || !layout(type.elementType,&element).ok() ||
                !homogeneous(element,&w,&n,depth+1) || n*type.elementCount>4 || type.size!=element.size*type.elementCount)return false;
            *width=w;*lanes=static_cast<u32>(n*type.elementCount);return true;
        }
        if((type.kind!=DataTypeKind::kStruct && type.kind!=DataTypeKind::kUnion) || type.fields.empty())return false;
        u8 w=0;u32 count=0;u64 occupied=0;
        for(const auto& field:type.fields) {
            DataTypeLayout child;if(!layout(field.type,&child).ok())return false;
            const bool isUnion=type.kind==DataTypeKind::kUnion;
            u8 cw=0;u32 cc=0;if(!homogeneous(child,&cw,&cc,depth+1) || (w&&cw!=w) || field.offset!=(isUnion?0:occupied))return false;
            w=cw;if(isUnion){count=std::max(count,cc);occupied=std::max(occupied,child.size);}else{count+=cc;occupied+=child.size;}
        }
        if(count>4 || type.size!=occupied)return false;*width=w;*lanes=count;return true;
    }
    bool sysvClasses(const DataTypeLayout& type,u64 base,std::vector<bool>* sse,unsigned depth=0) {
        if(depth>16 || type.size>16 || base+type.size>16)return false;
        if(type.kind==DataTypeKind::kPrimitive || type.kind==DataTypeKind::kPointer || type.kind==DataTypeKind::kEnum) {
            if(base%type.alignment)return false;
            for(u64 byte=base;byte<base+type.size;++byte)if(!type.isFloating)(*sse)[byte/8]=false;
            return true;
        }
        if(type.kind!=DataTypeKind::kStruct && type.kind!=DataTypeKind::kUnion)return false;
        for(const auto& field:type.fields) {
            DataTypeLayout child;if(!layout(field.type,&child).ok() || !sysvClasses(child,base+field.offset,sse,depth+1))return false;
        }
        return !type.fields.empty();
    }
    void integerPieces(AbiValue* value,const DataTypeLayout& type,bool result=false,bool indirect=false) {
        const u64 size=indirect ? word : type.size;const u32 count=static_cast<u32>((size+word-1)/word);
        auto pieceAt=[&](u64 offset,u32 n){auto piece=reg(offset,static_cast<u8>(std::min<u64>(word,size-n*word)),n*word);
            // Composite registers are loaded as memory chunks. A partial BE
            // chunk occupies the high bits, unlike a narrow integral scalar.
            if(prototype.byteOrder==ByteOrder::kBig && aggregate(type) && !indirect)piece.registerShift=static_cast<u8>((word-piece.width)*8);
            if(indirect)piece.kind=AbiStorageKind::kIndirect;return piece;};
        if(result) {
            const auto offsets=arch==Arch::kAArch64 ? std::vector<u64>{arm64::kXn(0),arm64::kXn(1)} :
                (arch==Arch::kX86_64||arch==Arch::kX86_32 ? std::vector<u64>{x86::kRax,x86::kRdx} :
                (arch==Arch::kArm32||arch==Arch::kThumb ? std::vector<u64>{arm32::kRn(0),arm32::kRn(1)} : std::vector<u64>{riscv::kXn(10),riscv::kXn(11)}));
            for(u32 n=0;n<count&&n<offsets.size();++n)value->pieces.push_back(pieceAt(offsets[n],n));
            return;
        }
        if(word==4 && type.alignment>=8)nextGp=(nextGp+1)&~1u;
        if(model.convention=="aapcs64" && type.alignment==16)nextGp=(nextGp+1)&~1u;
        if(nextGp+count<=gp.size()) {
            for(u32 n=0;n<count;++n)value->pieces.push_back(pieceAt(gp[nextGp++],n));
        } else if(model.convention=="aapcs32" && !indirect && nextGp<gp.size() && stack==0) {
            // AAPCS32 C.5: the first overflowing argument splits at the last
            // available core register, only while NSAA is still entry SP.
            const u32 registers=static_cast<u32>(gp.size())-nextGp;
            for(u32 n=0;n<registers;++n)value->pieces.push_back(reg(gp[nextGp++],static_cast<u8>(std::min<u64>(word,size-n*word)),n*word));
            const u64 consumed=registers*word;auto remainder=type;remainder.size=size-consumed;remainder.alignment=word;
            const size_t first=value->pieces.size();onStack(value,remainder);
            for(size_t n=first;n<value->pieces.size();++n)value->pieces[n].valueOffset+=consumed;
        } else {nextGp=static_cast<u32>(gp.size());onStack(value,type,indirect);}
    }
    Status configure() {
        model.convention=prototype.callingConvention;
        if(model.convention.empty()) {
            switch(arch) {
                case Arch::kAArch64:model.convention="aapcs64";break;case Arch::kX86_64:model.convention="sysv64";break;case Arch::kX86_32:model.convention="cdecl32";break;
                case Arch::kArm32:case Arch::kThumb:model.convention="aapcs32";break;case Arch::kRiscV32:model.convention="riscv32";break;case Arch::kRiscV64:model.convention="riscv64";break;
                default: {
                    MintArchitectureSemanticsV2 custom{};if(!architecturePluginAbi(arch,&custom))return Status::error(ErrorCode::kUnsupported,"no custom architecture ABI description");
                    ArchitectureDescription desc;if(!architectureDescription(arch,&desc))return Status::error(ErrorCode::kUnsupported,"missing architecture descriptor");
                    word=desc.pointerSize;for(u32 n=0;n<custom.argument_count;++n)gp.push_back(custom.argument_offsets[n]);model.convention="plugin-register";return Status::success();
                }
            }
        }
        const auto& cc=model.convention;
        if(cc=="aapcs64" && arch==Arch::kAArch64){for(unsigned n=0;n<8;++n){gp.push_back(arm64::kXn(n));fp.push_back(arm64::kVn(n));}}
        else if((cc=="sysv64"||cc=="windows64") && arch==Arch::kX86_64) {
            if(cc=="sysv64"){gp={x86::kRdi,x86::kRsi,x86::kRdx,x86::kRcx,x86::kGpr(8),x86::kGpr(9)};for(unsigned n=0;n<8;++n)fp.push_back(x86::kXmmN(n));stack=8;}
            else {gp={x86::kRcx,x86::kRdx,x86::kGpr(8),x86::kGpr(9)};for(unsigned n=0;n<4;++n)fp.push_back(x86::kXmmN(n));stack=40;model.shadowBytes=32;}
        }
        else if((cc=="cdecl32"||cc=="stdcall32") && arch==Arch::kX86_32){word=4;stack=4;}
        else if((cc=="aapcs32"||cc=="aapcs32-vfp") && (arch==Arch::kArm32||arch==Arch::kThumb)) {
            word=4;for(unsigned n=0;n<4;++n)gp.push_back(arm32::kRn(n));
            if(cc=="aapcs32-vfp")return Status::error(ErrorCode::kUnsupported,"AAPCS32 VFP packing/backfill not modeled; select aapcs32 only for proven soft-float binaries");
        }
        else if(((cc=="riscv32"||cc=="riscv32f"||cc=="riscv32d") && arch==Arch::kRiscV32) || ((cc=="riscv64"||cc=="riscv64f"||cc=="riscv64d") && arch==Arch::kRiscV64)) {
            word=arch==Arch::kRiscV32?4:8;for(unsigned n=10;n<18;++n)gp.push_back(riscv::kXn(n));
            flen=cc.back()=='d'?8:cc.back()=='f'?4:0;
            if(flen)for(unsigned n=10;n<18;++n)fp.push_back(riscv::kF0+n*8);
        } else return Status::error(ErrorCode::kBadFormat,"calling convention is incompatible with target architecture");
        return Status::success();
    }
    Status hiddenReturn(const DataTypeLayout& type) {
        if(model.convention=="aapcs64")model.hiddenResult.push_back(reg(arm64::kXn(8),word));
        else if(model.convention=="cdecl32"||model.convention=="stdcall32") {model.hiddenResult.push_back({AbiStorageKind::kStack,{},4,0,word,false});stack+=word;}
        else if(!gp.empty()){model.hiddenResult.push_back(reg(gp[0],word));nextGp=1;nextPosition=1;}
        else return Status::error(ErrorCode::kUnsupported,"indirect return has no known hidden-pointer storage");
        model.result.indirect=true;model.result.size=type.size;return Status::success();
    }
    Status assign(const std::string& name,AbiValue* value,bool result=false) {
        DataTypeLayout type;auto status=layout(name,&type);if(!status.ok())return status;
        value->type=name;value->size=type.size;if(!type.size)return Status::success();
        const bool composite=aggregate(type);const auto& cc=model.convention;
        if(riscv())return assignRiscV(type,value,result);
        if(cc=="plugin-register") {
            if(composite || type.isFloating || type.size>word)return Status::error(ErrorCode::kUnsupported,"plugin ABI declares integer/pointer register values only");
            MintArchitectureSemanticsV2 custom{};if(!architecturePluginAbi(arch,&custom))return Status::error(ErrorCode::kUnsupported,"plugin ABI unavailable");
            if(result) {if(custom.return_register_offset==UINT32_MAX)return Status::error(ErrorCode::kUnsupported,"plugin ABI has no result register");value->pieces.push_back(reg(custom.return_register_offset,static_cast<u8>(type.size)));}
            else {if(nextGp>=gp.size())return Status::error(ErrorCode::kUnsupported,"plugin ABI has no declared stack argument convention");value->pieces.push_back(reg(gp[nextGp++],static_cast<u8>(type.size)));}
            return Status::success();
        }
        u8 hfaWidth=0;u32 lanes=0;const bool hfa=cc=="aapcs64"&&homogeneous(type,&hfaWidth,&lanes);
        if(result) {
            if(type.isFloating && !fp.empty()){value->pieces.push_back(reg(fp[0],static_cast<u8>(type.size),0,true));return Status::success();}
            if(type.isFloating && (cc=="cdecl32"||cc=="stdcall32"))return Status::error(ErrorCode::kUnsupported,"x87 floating returns are not modeled in IR");
            if(hfa){for(u32 n=0;n<lanes;++n)value->pieces.push_back(reg(fp[n],hfaWidth,n*hfaWidth,true));return Status::success();}
            if(cc=="sysv64"&&composite&&type.size<=16) {
                std::vector<bool> classes((type.size+7)/8,true);
                if(sysvClasses(type,0,&classes)){u32 gi=0,fi=0;for(u32 n=0;n<classes.size();++n)value->pieces.push_back(reg(classes[n]?x86::kXmmN(fi++):(gi++?x86::kRdx:x86::kRax),static_cast<u8>(std::min<u64>(8,type.size-n*8)),n*8,classes[n]));return Status::success();}
                return hiddenReturn(type);
            }
            const u64 directLimit=cc=="windows64" || cc=="aapcs32" ? word : word*2;
            if(composite && (type.size>directLimit || cc=="cdecl32" || cc=="stdcall32" || (cc=="windows64" && type.size!=1&&type.size!=2&&type.size!=4&&type.size!=8)))return hiddenReturn(type);
            if(type.size>word*2)return Status::error(ErrorCode::kUnsupported,"return storage exceeds supported scalar/register pairs");
            integerPieces(value,type,true);return Status::success();
        }
        if(cc=="windows64") {
            const bool indirect=composite && type.size!=1&&type.size!=2&&type.size!=4&&type.size!=8;value->indirect=indirect;
            if(nextPosition<4) {
                auto piece=reg(type.isFloating&&!indirect ? fp[nextPosition] : gp[nextPosition],indirect ? word : static_cast<u8>(type.size),0,type.isFloating&&!indirect);
                if(indirect)piece.kind=AbiStorageKind::kIndirect;value->pieces.push_back(piece);
                if(prototype.variadic&&type.isFloating)value->pieces.push_back(reg(gp[nextPosition],static_cast<u8>(type.size)));
            } else onStack(value,type,indirect);
            ++nextPosition;return Status::success();
        }
        if(cc=="sysv64"&&composite) {
            std::vector<bool> classes((std::min<u64>(type.size,16)+7)/8,true);
            if(type.size<=16&&sysvClasses(type,0,&classes)) {
                u32 sse=static_cast<u32>(std::count(classes.begin(),classes.end(),true)),integer=static_cast<u32>(classes.size())-sse;
                if(nextGp+integer<=gp.size()&&nextFp+sse<=fp.size()) {for(u32 n=0;n<classes.size();++n)value->pieces.push_back(reg(classes[n]?fp[nextFp++]:gp[nextGp++],static_cast<u8>(std::min<u64>(8,type.size-n*8)),n*8,classes[n]));return Status::success();}
            }
            onStack(value,type);return Status::success();
        }
        if(type.isFloating&&!fp.empty()) {
            if(nextFp<fp.size())value->pieces.push_back(reg(fp[nextFp++],static_cast<u8>(type.size),0,true));else onStack(value,type);
            return Status::success();
        }
        if(hfa) {
            if(nextFp+lanes<=fp.size())for(u32 n=0;n<lanes;++n)value->pieces.push_back(reg(fp[nextFp++],hfaWidth,n*hfaWidth,true));
            else {nextFp=static_cast<u32>(fp.size());onStack(value,type);}return Status::success();
        }
        const bool indirect=composite && type.size>(cc=="aapcs64" ? 16 : 1024*1024);
        value->indirect=indirect;integerPieces(value,type,false,indirect);return Status::success();
    }
};
}
Status buildAbiModel(Arch architecture,const UserPrototype& prototype,AbiModel* output,const AbiTypeResolver& types) {
    if(!output)return Status::error(ErrorCode::kInternalError,"null ABI output");*output={};
    if(!prototype.valid() || prototype.parameters.size()>64)return Status::error(ErrorCode::kBadFormat,"invalid/unbounded ABI prototype");
    if(prototype.byteOrder==ByteOrder::kBig && architecture!=Arch::kAArch64)return Status::error(ErrorCode::kUnsupported,"big-endian ABI storage currently requires AArch64");
    u8 pointer=architecture==Arch::kX86_32||architecture==Arch::kArm32||architecture==Arch::kThumb||architecture==Arch::kRiscV32 ? 4 : 8;
    MintArchitectureSemanticsV2 custom{};if(architecturePluginAbi(architecture,&custom))pointer=custom.pointer_size;
    DataTypeManager builtins(pointer);Builder builder(architecture,prototype,types ? types : AbiTypeResolver([&](const auto& t,auto* out){return builtins.resolve(t,out);}));
    auto status=builder.configure();if(!status.ok())return status;builder.model.pointerWidth=builder.word;builder.model.variadic=prototype.variadic;
    status=builder.assign(prototype.returnType,&builder.model.result,true);if(!status.ok())return status;
    for(const auto& argument:prototype.parameters) {AbiValue value;status=builder.assign(argument.type,&value);if(!status.ok())return status;builder.model.parameters.push_back(std::move(value));}
    builder.model.stackBytes=builder.stack;
    if(prototype.variadic)builder.model.diagnostics.push_back("Only named parameters have declared storage; unnamed arguments require call-site type evidence.");
    *output=std::move(builder.model);return Status::success();
}
bool prototypeUsesSimpleIntegerRegisters(const UserPrototype& prototype,Arch architecture) {
    const auto& cc=prototype.callingConvention;
    const bool riscvConvention=(architecture==Arch::kRiscV32 && (cc=="riscv32"||cc=="riscv32f"||cc=="riscv32d")) ||
        (architecture==Arch::kRiscV64 && (cc=="riscv64"||cc=="riscv64f"||cc=="riscv64d"));
    if((!cc.empty()&&!riscvConvention) || prototype.variadic)return false;
    const auto scalar=[](const std::string& type){const auto t=localTypeExpression(type);return t=="void"||t=="char"||t=="bool"||t.find('*')!=std::string::npos||t=="u8"||t=="u16"||t=="u32"||t=="u64"||t=="i8"||t=="i16"||t=="i32"||t=="i64";};
    if(!scalar(prototype.returnType))return false;
    size_t slots=architecture==Arch::kX86_64 ? 6 : architecture==Arch::kArm32||architecture==Arch::kThumb ? 4 : architecture==Arch::kX86_32 ? 0 : 8;
    if(prototype.parameters.size()>slots)return false;
    const u8 word=architecture==Arch::kX86_32||architecture==Arch::kArm32||architecture==Arch::kThumb||architecture==Arch::kRiscV32?4:8;
    DataTypeManager types(word);
    if(prototype.returnType!="void"){DataTypeLayout result;if(!types.resolve(localTypeExpression(prototype.returnType),&result).ok() || result.size>word)return false;}
    for(const auto& parameter:prototype.parameters){if(!scalar(parameter.type))return false;DataTypeLayout layout;if(!types.resolve(localTypeExpression(parameter.type),&layout).ok() || layout.size>word)return false;}
    return true;
}
std::string AbiModel::toText() const {
    std::ostringstream out;out<<"Calling convention: "<<convention<<"; pointer "<<unsigned(pointerWidth)*8<<" bits; stack extent "<<stackBytes<<"; shadow "<<shadowBytes<<"\n";
    auto value=[&](const std::string& label,const AbiValue& value) {
        out<<label<<" "<<value.type<<" ("<<value.size<<" bytes"<<(value.indirect?", indirect copy":"")<<")\n";
        for(const auto& piece:value.pieces)out<<"  +"<<piece.valueOffset<<": "<<(piece.storage.valid()?"register byte "+std::to_string(piece.storage.offset):"entry SP "+std::to_string(piece.stackOffset))<<", "<<unsigned(piece.width)<<" bytes"<<(piece.floating?" FP":"")<<(piece.nanBoxed?" NaN-boxed":"")<<(piece.registerShift?" bit offset "+std::to_string(piece.registerShift):"")<<(piece.kind==AbiStorageKind::kIndirect?" indirect-pointer":"")<<"\n";
    };
    value("return",result);for(size_t i=0;i<parameters.size();++i)value("arg "+std::to_string(i),parameters[i]);
    for(const auto& piece:hiddenResult)out<<"hidden result pointer: "<<(piece.storage.valid()?"register byte "+std::to_string(piece.storage.offset):"entry SP "+std::to_string(piece.stackOffset))<<'\n';
    for(const auto& note:diagnostics)out<<note<<'\n';return out.str();
}
} // namespace mint
