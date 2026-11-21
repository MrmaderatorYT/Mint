#include "mint/analysis/x86_switch_recovery.h"

#include "mint/disasm/disassembler.h"
#include "mint/ir/registers.h"
#include <capstone/capstone.h>
#include <algorithm>
#include <array>
#include <deque>
#include <limits>
#include <map>
#include <set>

namespace mint {
namespace {
bool addSigned(Address base,i64 displacement,Address* result) {
    if(displacement>=0) {
        if(base>std::numeric_limits<Address>::max()-static_cast<u64>(displacement))return false;
        *result=base+static_cast<u64>(displacement);
    } else {
        const u64 magnitude=static_cast<u64>(-(displacement+1))+1;
        if(base<magnitude)return false;
        *result=base-magnitude;
    }
    return true;
}
int family(x86_reg reg,u8 size) {
    static const std::array<x86_reg,16> wide={{X86_REG_RAX,X86_REG_RCX,X86_REG_RDX,X86_REG_RBX,
        X86_REG_RSP,X86_REG_RBP,X86_REG_RSI,X86_REG_RDI,X86_REG_R8,X86_REG_R9,X86_REG_R10,
        X86_REG_R11,X86_REG_R12,X86_REG_R13,X86_REG_R14,X86_REG_R15}};
    static const std::array<x86_reg,16> narrow={{X86_REG_EAX,X86_REG_ECX,X86_REG_EDX,X86_REG_EBX,
        X86_REG_ESP,X86_REG_EBP,X86_REG_ESI,X86_REG_EDI,X86_REG_R8D,X86_REG_R9D,X86_REG_R10D,
        X86_REG_R11D,X86_REG_R12D,X86_REG_R13D,X86_REG_R14D,X86_REG_R15D}};
    if(size!=4&&size!=8)return -1;
    const auto& registers=size==8?wide:narrow;
    const auto found=std::find(registers.begin(),registers.end(),reg);
    return found==registers.end()?-1:static_cast<int>(found-registers.begin());
}
int reg(const cs_x86_op& operand,u8 size) {
    return operand.type==X86_OP_REG&&operand.size==size?family(operand.reg,size):-1;
}
bool plain(const cs_x86& insn) {
    return !insn.prefix[0]&&!insn.prefix[1]&&!insn.prefix[2]&&!insn.prefix[3]&&insn.addr_size==8;
}
struct Detail {unsigned id=0;Address address=0;u8 size=0;cs_x86 operands{};};
class Recovery {
public:
    Recovery(const ElfImage& image,const CodeMap& code,const Function& function,const X86SwitchRecoveryOptions& options)
        :image_(image),code_(code),function_(function),options_(options){}
    ~Recovery(){if(scratch_)cs_free(scratch_,1);if(handle_)cs_close(&handle_);}
    bool limited=false;
    Status initialize() {
        if(!code_.finalized()||function_.cfg.empty()||function_.cfg.entry()>=function_.cfg.size())
            return Status::error(ErrorCode::kBadFormat,"switch recovery requires finalized code and a provisional CFG");
        if(function_.instructions.size()>std::min<size_t>(options_.maxInstructions,4096)||
           function_.cfg.size()>std::min<size_t>(options_.maxBlocks,1024)||
           function_.resolvedIndirectJumps.size()>std::min<size_t>(options_.maxSites,64)||function_.tailCalls.size()>64)
            return Status::error(ErrorCode::kTooLarge,"x86 switch function bounds exceeded");
        std::set<Address> resolvedSites;
        for(const auto& resolved:function_.resolvedIndirectJumps) {
            if(resolved.targets.size()>256||resolved.switchCases.size()>256)
                return Status::error(ErrorCode::kTooLarge,"x86 switch prior target bounds exceeded");
            if(!resolvedSites.insert(resolved.branch).second)return bad();
        }
        if(cs_open(CS_ARCH_X86,CS_MODE_64,&handle_)!=CS_ERR_OK||
           cs_option(handle_,CS_OPT_DETAIL,CS_OPT_ON)!=CS_ERR_OK||!(scratch_=cs_malloc(handle_)))
            return Status::error(ErrorCode::kInternalError,"cannot open x86 switch decoder");
        const auto opened=decoder_.open(Arch::kX86_64);if(!opened.ok())return opened;
        Address previousEnd=0;bool first=true;
        for(auto address:function_.instructions) {
            if(!tick())return budget();
            if(!owned_.insert(address).second)return bad();
            const auto* instruction=code_.find(address);
            if(!instruction||!instruction->size||instruction->size>15||instruction->next()<address||
               (!first&&address<previousEnd)||!exactDecode(*instruction))return bad();
            previousEnd=instruction->next();first=false;
        }
        if(!owned_.count(function_.entry)||function_.cfg.blocks()[function_.cfg.entry()].start!=function_.entry)return bad();
        std::set<Address> tailSites;
        for(const auto& tail:function_.tailCalls) {
            if(!tick())return budget();
            const auto* insn=code_.find(tail.branch);
            if(!tailSites.insert(tail.branch).second || !owned_.count(tail.branch) || owned_.count(tail.target) ||
                !insn || insn->flow!=FlowKind::kJump || insn->target!=tail.target ||
                !std::binary_search(function_.callees.begin(),function_.callees.end(),tail.target))return bad();
        }
        // Rebuild from authoritative instruction membership instead of trusting
        // cached predecessor lists or a caller-supplied subset of the graph.
        expected_=ControlFlowGraph::build(code_,function_.instructions,function_.entry,function_.resolvedIndirectJumps);
        if(expected_.size()!=function_.cfg.size()||expected_.entry()!=function_.cfg.entry())return bad();
        for(size_t i=0;i<expected_.size();++i) {
            if(!tick())return budget();
            const auto& a=expected_.blocks()[i];const auto& b=function_.cfg.blocks()[i];
            if(a.id!=b.id||a.start!=b.start||a.end!=b.end||a.firstInsn!=b.firstInsn||a.insnCount!=b.insnCount||
               a.terminator!=b.terminator||a.successors.size()!=b.successors.size())return bad();
            for(size_t e=0;e<a.successors.size();++e)
                if(a.successors[e].target!=b.successors[e].target||a.successors[e].kind!=b.successors[e].kind)return bad();
            if(a.firstInsn>code_.size()||a.insnCount>code_.size()-a.firstInsn||!a.insnCount)return bad();
            for(size_t n=0;n<a.insnCount;++n) {
                if(!tick())return budget();
                const auto& insn=code_.instructions()[a.firstInsn+n];
                if(!owned_.count(insn.address)||(n&&code_.instructions()[a.firstInsn+n-1].next()!=insn.address))return bad();
            }
        }
        return Status::success();
    }
    bool recover(const BasicBlock& dispatch,X86SwitchTable* result) {
        // The entire dispatcher is whitelisted. No call, flag clobber or index
        // assignment may hide between the guard and the indexed load.
        if(dispatch.insnCount!=4&&dispatch.insnCount!=5)return false;
        const auto& instructions=code_.instructions();
        const size_t begin=dispatch.firstInsn;
        const auto* firstInsn=detail(instructions[begin]);
        if(!firstInsn)return false;
        const bool leaFirst=firstInsn->id==X86_INS_LEA;
        const auto* lea=dispatch.insnCount==4||leaFirst?firstInsn:detail(instructions[begin+1]);
        const auto* load=detail(instructions[begin+dispatch.insnCount-3]);
        const auto* add=detail(instructions[begin+dispatch.insnCount-2]);
        const auto* jump=detail(instructions[begin+dispatch.insnCount-1]);
        if(!lea||!load||!add||!jump||lea->id!=X86_INS_LEA||load->id!=X86_INS_MOVSXD||add->id!=X86_INS_ADD||jump->id!=X86_INS_JMP)return false;
        const auto& l=lea->operands;const auto& m=load->operands;const auto& a=add->operands;const auto& j=jump->operands;
        if(!plain(l)||!plain(m)||!plain(a)||!plain(j)||l.op_count!=2||m.op_count!=2||a.op_count!=2||j.op_count!=1)return false;
        const int base=reg(l.operands[0],8),target=reg(m.operands[0],8);
        if(base<0||target<0||base==target||l.operands[1].type!=X86_OP_MEM||l.operands[1].mem.base!=X86_REG_RIP||
           l.operands[1].mem.index!=X86_REG_INVALID||l.operands[1].mem.segment!=X86_REG_INVALID||
           m.operands[1].type!=X86_OP_MEM||m.operands[1].size!=4||m.operands[1].mem.segment!=X86_REG_INVALID||
           family(m.operands[1].mem.base,8)!=base||m.operands[1].mem.scale!=4||m.operands[1].mem.disp!=0||
           reg(a.operands[0],8)!=target||reg(a.operands[1],8)!=base||reg(j.operands[0],8)!=target)return false;
        const int index=family(m.operands[1].mem.index,8);
        if(index<0||index==base)return false;
        const auto& predecessors=expected_.blocks()[dispatch.id].predecessors;
        if(predecessors.size()!=1)return false;
        const auto& guard=expected_.blocks()[predecessors[0]];
        if(guard.insnCount<2||guard.terminator!=FlowKind::kCondJump)return false;
        const auto* compare=detail(instructions[guard.firstInsn+guard.insnCount-2]);
        const auto* branch=detail(instructions[guard.firstInsn+guard.insnCount-1]);
        if(!compare||!branch||compare->id!=X86_INS_CMP||(branch->id!=X86_INS_JA&&branch->id!=X86_INS_JBE)||
           !plain(compare->operands)||!plain(branch->operands)||compare->operands.op_count!=2||branch->operands.op_count!=1||
           branch->operands.operands[0].type!=X86_OP_IMM)return false;
        const auto& compared=compare->operands.operands[0];const auto& bound=compare->operands.operands[1];
        const int guarded=reg(compared,compared.size);
        if(guarded<0||bound.type!=X86_OP_IMM||bound.imm<1||static_cast<u64>(bound.imm)>=std::min<size_t>(options_.maxEntries,256))return false;
        const Address accepted=branch->id==X86_INS_JA?branch->address+branch->size:static_cast<Address>(branch->operands.operands[0].imm);
        if(accepted!=dispatch.start||guard.successors.size()!=2||!edge(guard.id,dispatch.id,
            branch->id==X86_INS_JA?EdgeKind::kNotTaken:EdgeKind::kTaken)||!guardedEdge(guard.id,dispatch.id))return false;
        Address proofStart=compare->address;
        if(compared.size==4&&dispatch.insnCount==5) {
            const auto* copy=detail(instructions[begin+(leaFirst?1:0)]);
            if(!copy||copy->id!=X86_INS_MOV||!plain(copy->operands)||copy->operands.op_count!=2||
               reg(copy->operands.operands[0],4)!=index||reg(copy->operands.operands[1],4)!=guarded||
               (leaFirst&&base==guarded))return false;
        } else {
            if(dispatch.insnCount!=4||index!=guarded)return false;
            if(compared.size==4) {
                const auto* definition=indexZeroExtension(guard,index);
                if(!definition)return false;
                proofStart=definition->address;
            } else if(compared.size!=8)return false;
        }
        Address table;
        if(!addSigned(lea->address+lea->size,l.operands[1].mem.disp,&table))return false;
        const u32 count=static_cast<u32>(bound.imm)+1;
        const u64 length=u64(count)*4;
        const auto* segment=image_.memory().segmentAt(table);
        if(!segment||!(segment->flags&kMemRead)||segment->writable()||!segment->data.covers(table-segment->start,length)||
           table>std::numeric_limits<Address>::max()-length||table+length>segment->end())return false;
        // Unsupported runtime fixups anywhere in this segment prohibit treating
        // its file bytes as immutable. No guessed relocation width is used.
        for(const auto& relocation:image_.relocations()) {
            if(!tick())return false;
            if(segment->contains(relocation.offset))return false;
        }
        X86SwitchTable prepared;prepared.guard=compare->address;prepared.jump.branch=jump->address;
        prepared.jump.table=table;prepared.jump.selectorAddress=load->address;
        prepared.jump.selectorRegister=x86::kGpr(static_cast<unsigned>(index));prepared.jump.selectorWidth=compared.size;
        std::map<Address,u8> decodedTargets;
        bool owned=true;
        for(u32 value=0;value<count;++value) {
            if(!tick())return false;
            u64 raw=0;
            if(!image_.memory().readUnsigned(table+u64(value)*4,4,&raw))return false;
            const i64 displacement=(raw&0x80000000u)?static_cast<i64>(raw)-0x100000000ll:static_cast<i64>(raw);
            Address destination;
            if(!addSigned(table,displacement,&destination)||
               (destination>=dispatch.start&&destination<dispatch.end)||
               (destination>=compare->address&&destination<branch->address+branch->size))return false;
            InsnRecord preview;
            if(!previewTarget(destination,&preview))return false;
            const auto inserted=decodedTargets.emplace(destination,preview.size);
            if(!inserted.second&&inserted.first->second!=preview.size)return false;
            owned&=owned_.count(destination)!=0&&code_.find(destination)!=nullptr;
            prepared.jump.switchCases.push_back({value,destination});
        }
        Address previous=0;u8 size=0;bool first=true;
        for(const auto& target:decodedTargets) {
            if(!first&&target.first<previous+size)return false;
            first=false;previous=target.first;size=target.second;prepared.jump.targets.push_back(target.first);
        }
        if(prepared.jump.targets.size()<2)return false;
        prepared.fullyDiscovered=owned&&complete(prepared.jump)&&!function_.undecodableSites;
        prepared.dependencies.push_back({proofStart,branch->address+branch->size});
        prepared.dependencies.push_back({dispatch.start,dispatch.end});
        prepared.dependencies.push_back({table,table+length});
        *result=std::move(prepared);return true;
    }
    bool tick(){if(work_>=std::min<size_t>(options_.maxWork,1000000)){limited=true;return false;}++work_;return true;}
    Status budget()const{return Status::error(ErrorCode::kTooLarge,"x86 switch recovery work limit exceeded");}
private:
    const ElfImage& image_;const CodeMap& code_;const Function& function_;const X86SwitchRecoveryOptions& options_;
    csh handle_=0;cs_insn* scratch_=nullptr;Disassembler decoder_;ControlFlowGraph expected_;
    std::set<Address> owned_;std::map<Address,Detail> details_;size_t work_=0;
    Status bad()const{return Status::error(ErrorCode::kBadFormat,"inconsistent x86 switch provisional code/CFG");}
    bool exactDecode(const InsnRecord& insn) {
        const auto bytes=image_.memory().viewAt(insn.address,15);InsnRecord actual;
        return image_.memory().isExecutable(insn.address)&&bytes.size()>=insn.size&&
            decoder_.decode(insn.address,bytes,&actual)&&actual.size==insn.size&&actual.id==insn.id&&actual.flow==insn.flow&&
            ((insn.flow==FlowKind::kIndirectCall||insn.flow==FlowKind::kIndirectJump)||actual.target==insn.target);
    }
    const Detail* detail(const InsnRecord& record) {
        const auto found=details_.find(record.address);if(found!=details_.end())return &found->second;
        if(!tick())return nullptr;
        const auto bytes=image_.memory().viewAt(record.address,15);auto* pointer=bytes.data();size_t length=bytes.size();uint64_t address=record.address;
        if(!cs_disasm_iter(handle_,&pointer,&length,&address,scratch_)||!scratch_->detail||scratch_->id!=record.id||scratch_->size!=record.size)return nullptr;
        Detail value;value.id=scratch_->id;value.address=record.address;value.size=record.size;value.operands=scratch_->detail->x86;
        return &details_.emplace(record.address,value).first->second;
    }
    const Detail* indexZeroExtension(const BasicBlock& guard,int index) {
        // AMD64 CMP r32 examines only the low half. Prove that the same
        // physical index consumed by the 64-bit address has zero upper bits.
        // Scan a suffix of this block only, so every path executing CMP also
        // executes the definition. Each accepted instruction unconditionally
        // writes just its explicit GPR destination (and possibly flags).
        for(size_t n=guard.insnCount-2;n>0;--n) {
            const auto* instruction=detail(code_.instructions()[guard.firstInsn+n-1]);
            if(!instruction||!plain(instruction->operands)||instruction->operands.op_count!=2)return nullptr;
            switch(instruction->id) {
                case X86_INS_MOV:case X86_INS_LEA:case X86_INS_XOR:break;
                default:return nullptr;
            }
            const auto& destination=instruction->operands.operands[0];
            const auto written=reg(destination,destination.size);
            if(written<0)return nullptr;
            if(written==index)return destination.size==4?instruction:nullptr;
        }
        return nullptr;
    }
    bool edge(u32 from,u32 to,EdgeKind kind)const {
        for(const auto& e:expected_.blocks()[from].successors)if(e.target==to&&e.kind==kind)return true;
        return false;
    }
    bool reachable(u32 destination,u32 cutFrom=kNoBlock,u32 cutTo=kNoBlock) {
        std::deque<u32> queue;std::vector<bool> visited(expected_.size());const u32 entry=expected_.entry();
        queue.push_back(entry);visited[entry]=true;
        while(!queue.empty()) {
            if(!tick())return false;
            const auto block=queue.front();queue.pop_front();if(block==destination)return true;
            for(const auto& e:expected_.blocks()[block].successors)if(!(block==cutFrom&&e.target==cutTo)&&!visited[e.target]){visited[e.target]=true;queue.push_back(e.target);}
        }
        return false;
    }
    bool guardedEdge(u32 guard,u32 dispatch) {
        return reachable(guard)&&reachable(dispatch)&&!reachable(dispatch,guard,dispatch)&&!limited;
    }
    bool previewTarget(Address address,InsnRecord* result) {
        if(!image_.memory().isExecutable(address))return false;
        const auto bytes=image_.memory().viewAt(address,15);
        if(!decoder_.decode(address,bytes,result)||result->flow==FlowKind::kInvalid||!result->size||bytes.size()<result->size||result->next()<address)return false;
        // Check all known streams within the maximum x86 instruction span, not
        // merely CodeMap::covering's nearest starting address.
        const Address earliest=address>14?address-14:0;
        for(size_t i=code_.lowerBound(earliest);i<code_.size()&&code_.instructions()[i].address<result->next();++i) {
            if(!tick())return false;
            const auto& known=code_.instructions()[i];
            if(known.address==address) {if(known.size!=result->size||known.id!=result->id||known.flow!=result->flow)return false;}
            else if(known.address<result->next()&&address<known.next())return false;
        }
        return true;
    }
    bool complete(const ResolvedIndirectJump& candidate) {
        for(auto address:function_.instructions) {
            if(!tick())return false;
            const auto& insn=*code_.find(address);
            if(insn.flow==FlowKind::kInvalid)return false;
            if(fallsThrough(insn.flow)&&!owned_.count(insn.next()))return false;
            if((insn.flow==FlowKind::kJump||insn.flow==FlowKind::kCondJump)&&!owned_.count(insn.target)) {
                const bool tail=insn.flow==FlowKind::kJump && std::any_of(function_.tailCalls.begin(),function_.tailCalls.end(),
                    [&](const auto& proof){return proof.branch==address&&proof.target==insn.target;});
                if(!tail)return false;
            }
            if(insn.flow!=FlowKind::kIndirectJump)continue;
            const ResolvedIndirectJump* resolved=nullptr;
            for(const auto& item:function_.resolvedIndirectJumps)if(item.branch==address){if(resolved)return false;resolved=&item;}
            if(!resolved||resolved->targets.empty())return false;
            if(address==candidate.branch) {
                auto actual=resolved->targets;std::sort(actual.begin(),actual.end());actual.erase(std::unique(actual.begin(),actual.end()),actual.end());
                if(actual!=candidate.targets)return false;
            }
            const BasicBlock* owner=nullptr;
            for(const auto& block:expected_.blocks())if(block.contains(address)){owner=&block;break;}
            if(!owner)return false;
            std::set<u32> targets;
            for(auto target:resolved->targets) {
                if(!owned_.count(target))return false;
                const u32 block=expected_.blockAt(target);if(block==kNoBlock||!edge(owner->id,block,EdgeKind::kResolvedIndirect))return false;
                targets.insert(block);
            }
            if(targets.size()!=owner->successors.size())return false;
        }
        return true;
    }
};
}
Status recoverX86RelativeSwitches(const ElfImage& image,const CodeMap& code,const Function& function,
    std::vector<X86SwitchTable>* output,const X86SwitchRecoveryOptions& options) {
    if(!output)return Status::error(ErrorCode::kBadFormat,"missing x86 switch output");
    if(image.format()!=ImageFormat::kElf64||image.arch()!=Arch::kX86_64||image.memory().byteOrder()!=ByteOrder::kLittle||
       (function.decodeArch!=Arch::kUnknown&&function.decodeArch!=Arch::kX86_64))
        return Status::error(ErrorCode::kUnsupported,"relative switch recovery requires little-endian x86 ELF64");
    if(image.memory().hasOverlaps())return Status::error(ErrorCode::kUnsupported,"overlapping x86 switch memory mappings");
    Recovery recovery(image,code,function,options);const auto initialized=recovery.initialize();if(!initialized.ok())return initialized;
    std::vector<X86SwitchTable> prepared;size_t sites=0;
    for(const auto& block:function.cfg.blocks())if(block.terminator==FlowKind::kIndirectJump) {
        if(++sites>std::min<size_t>(options.maxSites,64))return Status::error(ErrorCode::kTooLarge,"x86 switch site count exceeded");
        X86SwitchTable table;if(recovery.recover(block,&table))prepared.push_back(std::move(table));
        if(recovery.limited)return recovery.budget();
    }
    *output=std::move(prepared);return Status::success();
}
}
