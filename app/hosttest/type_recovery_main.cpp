#include "mint/ir/type_recovery.h"
#include "mint/ir/registers.h"
#include "mint/ssa/ssa_builder.h"
#include <iostream>

using namespace mint;
namespace {
int checks=0,failures=0;
void expect(bool value,const char* label){++checks;if(!value){++failures;std::cerr<<"FAIL "<<label<<'\n';}}
struct Fixture {
    IrFunction ir;IrBuilder b{&ir};SsaFunction ssa;TypeRecovery types;
    Fixture(){ir.arch=Arch::kAArch64;ir.entry=0x1000;ir.name="layout";b.setAddress(ir.entry);}
    void finish(){
        b.emit(MintOp::kReturn,{},Varnode::reg(arm64::kXn(30),8));
        IrBlock block;block.id=0;block.start=0x1000;block.end=0x1100;block.insnCount=ir.insns.size();ir.blocks.push_back(block);
        expect(ir.verify().empty(),"valid fixture IR");expect(buildSsa(ir,&ssa).ok(),"build fixture SSA");
        expect(recoverTypes(ssa,&types).ok(),"recover fixture types");
    }
    RecoveredTypeKind kind(const Varnode& storage){
        for(SsaId id=0;id<ssa.values.size();++id){const auto& value=ssa.values[id];
            if(value.storage.space==storage.space&&value.storage.offset==storage.offset&&value.storage.size==storage.size)return types.values[id].kind;}
        return RecoveredTypeKind::kUnknown;
    }
};
void storesAndAliases(){
    Fixture f;const auto base=Varnode::reg(arm64::kXn(0),8),data=Varnode::reg(arm64::kXn(1),8);
    f.b.emit(MintOp::kStore,{},base,data);
    auto alias=f.b.unary(MintOp::kCopy,base,8);
    for(unsigned n=0;n<32;++n)alias=f.b.binary(MintOp::kAdd,alias,Varnode::constant(0,8));
    const auto middle=f.b.binary(MintOp::kAdd,alias,Varnode::constant(24,8));
    const auto tail=f.b.binary(MintOp::kSub,middle,Varnode::constant(16,8));
    f.b.emit(MintOp::kStore,{},tail,data);f.finish();
    expect(f.types.structs.size()==1,"store-only output parameter has layout");
    if(f.types.structs.size()==1){const auto& fields=f.types.structs[0].fields;
        expect(fields.size()==2&&fields[0].offset==0&&fields[1].offset==8,"nested copy/add/sub addresses share object identity");
        expect(fields.size()==2&&fields[0].width==8&&fields[1].width==8,"store value determines field width");}
    expect(f.kind(alias)==RecoveredTypeKind::kPointer,"pointer evidence crosses more than four arithmetic operations");
    expect(!f.types.parameters.empty()&&f.types.parameters[0].type.kind==RecoveredTypeKind::kPointer,"output argument is a pointer");
}
void rejectedLayouts(){
    Fixture f;const auto base=Varnode::reg(arm64::kXn(0),8),index=Varnode::reg(arm64::kXn(1),8),data=Varnode::constant(7,8);
    for(u64 offset:{8u,16u}){
        f.b.emit(MintOp::kStore,{},f.b.binary(MintOp::kSub,base,Varnode::constant(offset,8)),data);
        auto absolute=f.b.unary(MintOp::kCopy,Varnode::constant(0x3000+offset,8),8);
        f.b.emit(MintOp::kStore,{},absolute,data);
        auto indexed=f.b.binary(MintOp::kAdd,base,index);
        f.b.emit(MintOp::kStore,{},f.b.binary(MintOp::kAdd,indexed,Varnode::constant(offset,8)),data);
        f.b.emit(MintOp::kStore,{},f.b.binary(MintOp::kAdd,base,Varnode::constant(0x8000000000000000ull+offset,8)),data);
    }
    f.finish();expect(f.types.structs.empty(),"negative/indexed/absolute/wrapped addresses do not invent layouts");
}
void pointerArithmetic(){
    Fixture f;const auto left=Varnode::reg(arm64::kXn(0),8),right=Varnode::reg(arm64::kXn(1),8);
    f.b.emit(MintOp::kLoad,f.b.newTemp(8),left);f.b.emit(MintOp::kLoad,f.b.newTemp(8),right);
    auto difference=f.b.binary(MintOp::kSub,left,right),sum=f.b.binary(MintOp::kAdd,left,right);
    auto offset=f.b.binary(MintOp::kAdd,left,Varnode::constant(8,8));f.finish();
    expect(f.kind(difference)!=RecoveredTypeKind::kPointer,"pointer difference is not a pointer");
    expect(f.kind(sum)!=RecoveredTypeKind::kPointer,"sum of pointers has no pointer evidence");
    expect(f.kind(offset)==RecoveredTypeKind::kPointer,"constant offset preserves pointer evidence");
}
}
int main(){storesAndAliases();rejectedLayouts();pointerArithmetic();std::cout<<checks<<" checks, "<<failures<<" failures\n";return failures?1:0;}
