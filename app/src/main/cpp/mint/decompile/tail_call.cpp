#include "mint/decompile/tail_call.h"

#include "mint/analysis/local_variables.h"
#include <algorithm>
#include <deque>
#include <map>

namespace mint {
namespace {
Status unsupported(){return Status::error(ErrorCode::kUnsupported,"tail transfer needs matching authoritative scalar SysV64 ABI and proven inputs");}
bool scalar(const DataTypeLayout& type){return !type.isFloating&&(type.kind==DataTypeKind::kPrimitive||type.kind==DataTypeKind::kPointer)&&(type.size==1||type.size==2||type.size==4||type.size==8);}
bool gp(const AbiValue& value){return !value.indirect&&value.pieces.size()==1&&value.pieces[0].kind==AbiStorageKind::kRegister&&value.pieces[0].storage.isRegister()&&value.pieces[0].storage.size==8&&!value.pieces[0].floating&&value.pieces[0].width==value.size&&!value.pieces[0].registerShift;}
}
Status buildTailCallContract(Arch arch,ByteOrder order,const UserPrototype& caller,const UserPrototype& callee,const AbiTypeResolver& supplied,TailCallContract* out){
    if(!out)return Status::error(ErrorCode::kInternalError,"null tail contract");*out={};
    if(arch!=Arch::kX86_64||order!=ByteOrder::kLittle||!caller.valid()||!callee.valid()||caller.variadic||callee.variadic||caller.parameters.size()>6||callee.parameters.size()>6)return unsupported();
    TailCallContract result;result.caller=caller;result.callee=callee;result.caller.byteOrder=result.callee.byteOrder=order;
    DataTypeManager builtins(8);const AbiTypeResolver layouts=supplied?supplied:AbiTypeResolver([&](const auto& type,auto* output){return builtins.resolve(localTypeExpression(type),output);});
    if(!buildAbiModel(arch,result.caller,&result.callerAbi,layouts).ok()||!buildAbiModel(arch,result.callee,&result.calleeAbi,layouts).ok()||result.callerAbi.convention!="sysv64"||result.calleeAbi.convention!="sysv64"||!result.callerAbi.hiddenResult.empty()||!result.calleeAbi.hiddenResult.empty())return unsupported();
    for(const auto* model:{&result.callerAbi,&result.calleeAbi})for(const auto& value:model->parameters){DataTypeLayout type;if(!layouts(localTypeExpression(value.type),&type).ok()||!scalar(type)||!gp(value))return unsupported();}
    if(localTypeExpression(caller.returnType)!=localTypeExpression(callee.returnType))return unsupported();
    if(localTypeExpression(caller.returnType)!="void"){
        DataTypeLayout type;if(!layouts(localTypeExpression(caller.returnType),&type).ok()||!scalar(type)||!gp(result.callerAbi.result)||!gp(result.calleeAbi.result))return unsupported();
        if(result.callerAbi.result.pieces[0].storage!=result.calleeAbi.result.pieces[0].storage||result.callerAbi.result.size!=result.calleeAbi.result.size)return unsupported();
    }else if(!result.callerAbi.result.pieces.empty()||!result.calleeAbi.result.pieces.empty())return unsupported();
    *out=std::move(result);return Status::success();
}
bool validateTailCallInputs(const SsaFunction& function,const SsaInsn& instruction,const TailCallContract& contract,const MemoryAnalysis* memory){
    if(instruction.op!=MintOp::kTailCall||instruction.tailInputs.size()!=contract.calleeAbi.parameters.size()||instruction.tailInputs.size()>6)return false;
    if(memory&&!memory->matches(function))memory=nullptr;
    // Intrinsics do not expose physical register clobbers in core SSA.
    if(std::any_of(function.insns.begin(),function.insns.end(),[](const auto& insn){return !insn.dead&&insn.op==MintOp::kIntrinsic;}))return false;
    std::map<std::pair<u64,u8>,u8> declared;
    for(const auto& parameter:contract.callerAbi.parameters){const auto& piece=parameter.pieces[0];declared[{piece.storage.offset,piece.storage.size}]=piece.width;}
    size_t work=0;std::map<std::pair<SsaId,u8>,u8> state;
    auto canonical=[&](SsaId id){for(unsigned n=0;n<512&&id<function.values.size();++n){const auto& value=function.values[id];if(value.def!=SsaDef::kInsn||value.defIndex>=function.insns.size())break;const auto& def=function.insns[value.defIndex];if(def.op!=MintOp::kCopy||def.use[0]==id)break;id=def.use[0];}return id;};
    u32 instructionIndex=0;while(instructionIndex<function.insns.size()&&&function.insns[instructionIndex]!=&instruction)++instructionIndex;
    if(instructionIndex==function.insns.size())return false;
    auto physical=[&](const Varnode& storage){
        auto matches=[&](SsaId id){return id<function.values.size()&&function.values[id].storage==storage;};
        auto scan=[&](u32 block,u32 limit,SsaId* found){
            const auto& cfg=function.blocks[block];
            for(u32 n=std::min<u32>(limit,cfg.firstInsn+cfg.insnCount);n>cfg.firstInsn;){
                if(++work>65536){*found=kNoValue;return true;}const auto& insn=function.insns[--n];
                for(auto id:insn.clobbers)if(matches(id)){*found=id;return true;}
                if(matches(insn.dest)){*found=canonical(insn.dest);return true;}
            }
            for(auto pi:cfg.phis)if(pi<function.phis.size()){
                const auto& phi=function.phis[pi];if(!matches(phi.dest))continue;
                if(!phi.dead){*found=phi.dest;return true;}
                *found=kNoValue;for(auto input:phi.args){const auto value=canonical(input);if(*found==kNoValue)*found=value;else if(*found!=value){*found=kNoValue;break;}}return true;
            }
            return false;
        };
        if(instruction.block>=function.blocks.size())return kNoValue;
        SsaId found=kNoValue;if(scan(instruction.block,instructionIndex,&found))return found;
        std::deque<u32> pending;std::vector<u8> visited(function.blocks.size(),0);SsaId agreed=kNoValue;bool any=false;
        auto agree=[&](SsaId value){value=canonical(value);if(value==kNoValue)return false;if(!any){agreed=value;any=true;}return agreed==value;};
        auto entry=[&](){for(SsaId id=0;id<function.values.size();++id)if(function.values[id].def==SsaDef::kEntry&&matches(id))return id;return kNoValue;};
        auto enqueue=[&](u32 block){for(auto pred:function.blocks[block].predecessors)if(pred<visited.size()&&!visited[pred]){visited[pred]=1;pending.push_back(pred);}};
        if(instruction.block==0&&!agree(entry()))return kNoValue;enqueue(instruction.block);
        while(!pending.empty()){
            if(++work>65536)return kNoValue;const auto block=pending.front();pending.pop_front();
            if(scan(block,function.blocks[block].firstInsn+function.blocks[block].insnCount,&found)){if(!agree(found))return kNoValue;continue;}
            if(block==0&&!agree(entry()))return kNoValue;enqueue(block);
        }
        return any?agreed:kNoValue;
    };
    std::function<bool(SsaId,u8,unsigned)> origin=[&](SsaId id,u8 required,unsigned depth){
        if(depth>128||++work>65536||id>=function.values.size()||!required||required>8)return false;
        const auto& value=function.values[id];if(value.storage.size<required||value.storage.size>8)return false;
        auto& mark=state[{id,required}];if(mark)return mark==2;mark=1;
        if(memory&&id<memory->values.size()&&memory->values[id].kind==MemoryBaseKind::kEntryStack)return false;
        bool valid=false;
        if(value.def==SsaDef::kConstant)valid=true;
        else if(value.def==SsaDef::kEntry){const auto found=declared.find({value.storage.offset,value.storage.size});valid=value.storage.isRegister()&&found!=declared.end()&&found->second>=required;}
        else if(value.def==SsaDef::kPhi&&value.defIndex<function.phis.size()){
            const auto& phi=function.phis[value.defIndex];valid=!phi.dead&&!phi.args.empty();for(auto input:phi.args)if(!origin(input,required,depth+1)){valid=false;break;}
        }else if(value.def==SsaDef::kInsn&&value.defIndex<function.insns.size()){
            const auto& insn=function.insns[value.defIndex];valid=!insn.dead&&insn.dest==id&&!hasSideEffect(insn.op)&&insn.op!=MintOp::kUndefined;
            // Exact store/reload evidence can prove a spilled argument's origin.
            // This does not fold the load or change its emitted memory access.
            if(valid&&insn.op==MintOp::kLoad&&memory&&value.defIndex<memory->accessByInstruction.size()){
                const auto access=memory->accessByInstruction[value.defIndex];
                if(access<memory->accesses.size()){
                    const auto& proof=memory->accesses[access];
                    if(!proof.store&&proof.instruction==value.defIndex&&proof.width==value.storage.size&&proof.reachingValue<function.values.size()){
                        valid=origin(proof.reachingValue,required,depth+1);mark=valid?2:3;return valid;
                    }
                }
            }
            if(valid)for(auto input:insn.use)if(input!=kNoValue){
                if(input>=function.values.size()){valid=false;break;}
                const auto width=function.values[input].storage.size;
                const bool low=insn.op==MintOp::kCopy||insn.op==MintOp::kTrunc||insn.op==MintOp::kZeroExt||insn.op==MintOp::kSignExt||insn.op==MintOp::kAdd||insn.op==MintOp::kSub||insn.op==MintOp::kMul||insn.op==MintOp::kAnd||insn.op==MintOp::kOr||insn.op==MintOp::kXor||insn.op==MintOp::kNeg||insn.op==MintOp::kNot;
                if(!origin(input,low?std::min(required,width):width,depth+1)){valid=false;break;}
            }
        }
        mark=valid?2:3;return valid;
    };
    for(size_t i=0;i<instruction.tailInputs.size();++i){const auto input=instruction.tailInputs[i];if(input>=function.values.size()||function.values[input].storage.size!=8||physical(contract.calleeAbi.parameters[i].pieces[0].storage)!=canonical(input)||!origin(input,contract.calleeAbi.parameters[i].pieces[0].width,0))return false;}
    return true;
}
}
