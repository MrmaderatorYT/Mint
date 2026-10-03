#include "mint/analysis/reference_analysis.h"
#include <algorithm>
#include <functional>

namespace mint {
namespace {
using Values = std::vector<u64>;
constexpr size_t kMaxValues=16;
u64 mask(unsigned bytes) {return bytes>=8?~u64{0}:(u64{1}<<(bytes*8))-1;}
i64 signedValue(u64 value,unsigned bytes) {
    if(bytes==8)return static_cast<i64>(value);
    const unsigned bits=bytes*8;const u64 sign=u64{1}<<(bits-1);
    return static_cast<i64>((value^sign)-sign);
}
}
void collectSsaReferences(const SsaFunction& ssa,const ElfImage& image,Program::ReferenceGroup* group) {
    std::vector<u8> state(ssa.values.size());std::vector<Values> cache(ssa.values.size());
    size_t budget=1000000;
    std::function<bool(SsaId,Values*,unsigned)> resolve=[&](SsaId id,Values* out,unsigned depth) {
        if(id>=ssa.values.size() || depth>64 || !budget)return false;
        --budget;
        if(state[id]==2){*out=cache[id];return true;}if(state[id])return false;
        state[id]=1;const auto& value=ssa.values[id];Values found;
        const unsigned width=value.storage.size;
        if(!width || width>8){state[id]=3;return false;}
        if(value.def==SsaDef::kConstant)found.push_back(value.storage.offset);
        else if(value.def==SsaDef::kPhi && value.defIndex<ssa.phis.size()) {
            const auto& phi=ssa.phis[value.defIndex];
            for(const auto& arg:phi.args) {
                Values incoming;if(!resolve(arg,&incoming,depth+1)){found.clear();break;}
                found.insert(found.end(),incoming.begin(),incoming.end());
                std::sort(found.begin(),found.end());found.erase(std::unique(found.begin(),found.end()),found.end());
                if(found.size()>kMaxValues){found.clear();break;}
            }
        } else if(value.def==SsaDef::kInsn && value.defIndex<ssa.insns.size()) {
            const auto& insn=ssa.insns[value.defIndex];Values lhs,rhs;
            if(resolve(insn.use[0],&lhs,depth+1)) {
                if(insn.op==MintOp::kCopy || insn.op==MintOp::kTrunc || insn.op==MintOp::kZeroExt)found=lhs;
                else if(insn.op==MintOp::kSignExt) {
                    const auto sourceWidth=ssa.values[insn.use[0]].storage.size;
                    if(sourceWidth && sourceWidth<=8)for(auto a:lhs)found.push_back(static_cast<u64>(signedValue(a,sourceWidth)));
                } else if(insn.op==MintOp::kLoad) {
                    bool complete=true;
                    for(auto address:lhs) {
                        const auto* segment=image.memory().segmentAt(address);u64 loaded=0;
                        if(!segment || !(segment->flags&kMemRead) || (segment->flags&kMemWrite) ||
                           width>segment->end()-address || image.memory().viewAt(address,width).size()!=width ||
                           !image.memory().read(address,&loaded,width)) {complete=false;break;}
                        group->dependencies.push_back({address,address+width});
                        if(width==image.pointerSize()) {
                            Address pointer;if(image.resolvePointer(address,&pointer))loaded=pointer;
                        }
                        found.push_back(loaded);
                    }
                    if(!complete)found.clear();
                } else if(resolve(insn.use[1],&rhs,depth+1) && lhs.size()*rhs.size()<=kMaxValues) {
                    bool supported=true;
                    for(auto a:lhs)for(auto b:rhs) {
                        u64 v=0;
                        switch(insn.op) {
                            case MintOp::kAdd:v=a+b;break;case MintOp::kSub:v=a-b;break;
                            case MintOp::kMul:v=a*b;break;case MintOp::kAnd:v=a&b;break;
                            case MintOp::kOr:v=a|b;break;case MintOp::kXor:v=a^b;break;
                            case MintOp::kShl:if(b>=width*8){supported=false;break;}v=a<<b;break;
                            case MintOp::kShrU:if(b>=width*8){supported=false;break;}v=a>>b;break;
                            case MintOp::kShrS:if(b>=width*8){supported=false;break;}v=static_cast<u64>(signedValue(a,width)>>b);break;
                            default:supported=false;break;
                        }
                        if(supported)found.push_back(v);
                    }
                    if(!supported)found.clear();
                }
            }
        }
        for(auto& v:found)v&=mask(width);
        std::sort(found.begin(),found.end());found.erase(std::unique(found.begin(),found.end()),found.end());
        if(found.empty() || found.size()>kMaxValues){state[id]=3;return false;}
        cache[id]=found;state[id]=2;*out=std::move(found);return true;
    };
    for(const auto& insn:ssa.insns)if(insn.op==MintOp::kLoad || insn.op==MintOp::kStore) {
        Values addresses;
        if(resolve(insn.use[0],&addresses,0))for(auto address:addresses)if(image.memory().isMapped(address))
            group->references.push_back({insn.address,address,insn.op==MintOp::kLoad?"read (SSA address set)":"write (SSA address set)"});
    }
    std::sort(group->dependencies.begin(),group->dependencies.end(),[](const auto& a,const auto& b){return a.start<b.start || (a.start==b.start && a.end<b.end);});
    std::vector<Program::DependencyRange> merged;
    for(const auto& range:group->dependencies) {
        if(!merged.empty() && range.start<=merged.back().end && image.memory().segmentAt(range.start)==image.memory().segmentAt(merged.back().start))merged.back().end=std::max(merged.back().end,range.end);
        else merged.push_back(range);
    }
    group->dependencies=std::move(merged);
}
} // namespace mint
