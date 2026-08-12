#include "mint/ir/type_recovery.h"

#include "mint/ir/registers.h"

#include <algorithm>
#include <unordered_map>

namespace mint {
namespace {

constexpr u32 kNotAnArgument = ~0u;

/// Where a register sits in the calling convention's argument sequence, or
/// kNotAnArgument.
///
/// Integer and floating-point arguments occupy separate register sequences, so the
/// floating ones are numbered after the integer ones rather than interleaved. That
/// ordering is a guess at the source-level order and is only used for display; what
/// matters for correctness is which registers count at all.
u32 argumentPosition(Arch arch, const Varnode& storage) {
    if (arch == Arch::kAArch64) {
        if (storage.size == 8 && storage.offset <= arm64::kXn(7) &&
            storage.offset % 8 == 0) {
            return static_cast<u32>(storage.offset / 8);
        }
        if (storage.size == 16 && storage.offset >= arm64::kV0 &&
            storage.offset <= arm64::kVn(7) &&
            (storage.offset - arm64::kV0) % 16 == 0) {
            return 8 + static_cast<u32>((storage.offset - arm64::kV0) / 16);
        }
        return kNotAnArgument;
    }
    if (arch == Arch::kX86_64) {
        // The System V order, which is not the encoding order.
        static const u64 kSequence[] = {x86::kRdi, x86::kRsi, x86::kRdx,
                                        x86::kRcx, x86::kGpr(8), x86::kGpr(9)};
        if (storage.size == 8) {
            for (u32 i = 0; i < 6; ++i) {
                if (storage.offset == kSequence[i]) return i;
            }
        }
        if (storage.size == 16 && storage.offset >= x86::kXmm0 &&
            storage.offset <= x86::kXmmN(7) &&
            (storage.offset - x86::kXmm0) % 16 == 0) {
            return 6 + static_cast<u32>((storage.offset - x86::kXmm0) / 16);
        }
        return kNotAnArgument;
    }
    return kNotAnArgument;
}


bool valid(const SsaFunction& function, SsaId id) {
    return id != kNoValue && id < function.values.size();
}

bool isComparison(MintOp op) {
    switch (op) {
        case MintOp::kEqual:
        case MintOp::kNotEqual:
        case MintOp::kLessU:
        case MintOp::kLessS:
        case MintOp::kLessEqU:
        case MintOp::kLessEqS:
        case MintOp::kCarryAdd:
        case MintOp::kBorrowSub:
        case MintOp::kOverflowAdd:
        case MintOp::kOverflowSub:
            return true;
        default:
            return false;
    }
}

void markKind(RecoveredType* type, RecoveredTypeKind kind) {
    if (type->kind == RecoveredTypeKind::kUnknown ||
        type->kind == RecoveredTypeKind::kUnsignedInteger ||
        type->kind == RecoveredTypeKind::kSignedInteger) {
        type->kind = kind;
    }
}

}  // namespace

Status recoverTypes(const SsaFunction& function, TypeRecovery* out) {
    if (out == nullptr) {
        return Status::error(ErrorCode::kInternalError, "no type recovery output");
    }
    const std::vector<std::string> problems = function.verify();
    if (!problems.empty()) {
        return Status::error(ErrorCode::kBadFormat,
                             "cannot recover types from invalid SSA: " + problems.front());
    }
    *out = TypeRecovery();
    out->values.resize(function.values.size());
    for (size_t i = 0; i < function.values.size(); ++i) {
        out->values[i].width = function.values[i].storage.size;
    }

    std::unordered_map<SsaId, std::vector<std::pair<u64, SsaId>>> structAccesses;
    for (u32 index = 0; index < function.insns.size(); ++index) {
        const SsaInsn& insn = function.insns[index];
        if (insn.dest == kNoValue || insn.dest >= out->values.size()) continue;
        RecoveredType& dest = out->values[insn.dest];
        switch (insn.op) {
            case MintOp::kEqual:
            case MintOp::kNotEqual:
            case MintOp::kLessU:
            case MintOp::kLessS:
            case MintOp::kLessEqU:
            case MintOp::kLessEqS:
            case MintOp::kCarryAdd:
            case MintOp::kBorrowSub:
            case MintOp::kOverflowAdd:
            case MintOp::kOverflowSub:
                dest.kind = RecoveredTypeKind::kBoolean;
                dest.width = 1;
                break;
            case MintOp::kLoad:
                if (valid(function, insn.use[0])) {
                    markKind(&out->values[insn.use[0]], RecoveredTypeKind::kPointer);
                }
                break;
            case MintOp::kFloatAdd:
            case MintOp::kFloatSub:
            case MintOp::kFloatMul:
            case MintOp::kFloatDiv:
            case MintOp::kFloatSqrt:
            case MintOp::kFloatAbs:
            case MintOp::kFloatNeg:
                dest.kind = RecoveredTypeKind::kFloat;
                break;
            case MintOp::kIntToFloat:
                dest.kind = RecoveredTypeKind::kFloat;
                break;
            case MintOp::kFloatToInt:
                dest.kind = RecoveredTypeKind::kUnsignedInteger;
                break;
            case MintOp::kVectorAdd:
            case MintOp::kVectorSub:
            case MintOp::kVectorMul:
            case MintOp::kVectorMulWideU:
            case MintOp::kVectorMulWideS:
            case MintOp::kVectorCmpEq:
            case MintOp::kVectorCmpGtS:
            case MintOp::kVectorMinU:
            case MintOp::kVectorMinS:
            case MintOp::kVectorMaxU:
            case MintOp::kVectorMaxS:
            case MintOp::kVectorShl:
            case MintOp::kVectorShrU:
            case MintOp::kVectorShrS:
            case MintOp::kVectorPackS:
            case MintOp::kVectorPackU:
            case MintOp::kVectorExtendS:
            case MintOp::kVectorExtendU:
            case MintOp::kVectorInsert:
            case MintOp::kVectorSelect:
            case MintOp::kVectorShuffle:
            case MintOp::kVectorPermute:
            case MintOp::kVectorSplat:
            case MintOp::kVectorLoad:
                // The aggregate is 16 bytes; how it divides into lanes now lives on
                // the instruction as laneWidth rather than only in the machine
                // instruction's arrangement operand.
                dest.width = 16;
                break;
            case MintOp::kStore:
                if (valid(function, insn.use[0])) {
                    markKind(&out->values[insn.use[0]], RecoveredTypeKind::kPointer);
                }
                break;
            case MintOp::kDivS:
            case MintOp::kRemS:
                markKind(&dest, RecoveredTypeKind::kSignedInteger);
                break;
            default:
                if (insn.op == MintOp::kAdd || insn.op == MintOp::kSub) {
                    for (unsigned slot = 0; slot < 2; ++slot) {
                        const SsaId use = insn.use[slot];
                        if (!valid(function, use)) continue;
                        if (out->values[use].kind == RecoveredTypeKind::kPointer) {
                            dest.kind = RecoveredTypeKind::kPointer;
                        }
                    }
                }
                break;
        }

        if (isComparison(insn.op)) {
            for (unsigned slot = 0; slot < 2; ++slot) {
                if (valid(function, insn.use[slot]) && insn.op == MintOp::kLessS) {
                    markKind(&out->values[insn.use[slot]],
                             RecoveredTypeKind::kSignedInteger);
                }
            }
        }

        // Every access through a pointer is a field observation, whichever way the
        // data moves. Collecting only loads, as this used to, means a structure
        // written but never read looks like it has no fields at all — and an output
        // parameter is exactly that shape.
        if (insn.op == MintOp::kLoad || insn.op == MintOp::kStore) {
            // For a load the field's width is the loaded value's; for a store it is
            // the stored value's, since the destination is memory.
            const SsaId accessed = insn.op == MintOp::kLoad ? insn.dest : insn.use[1];
            if (valid(function, insn.use[0]) && valid(function, accessed)) {
                const SsaId address = insn.use[0];
                const SsaValue& addressValue = function.values[address];
                SsaId base = address;
                u64 offset = 0;
                bool usable = true;
                if (addressValue.def == SsaDef::kInsn &&
                    addressValue.defIndex < function.insns.size()) {
                    const SsaInsn& addressInsn = function.insns[addressValue.defIndex];
                    // kAdd only. A subtraction from a base is a frame slot below a
                    // pointer, not a field above one, and folding the two together
                    // produced offsets with the wrong sign.
                    if (addressInsn.op == MintOp::kAdd &&
                        valid(function, addressInsn.use[0]) &&
                        valid(function, addressInsn.use[1])) {
                        SsaId candidate = addressInsn.use[0];
                        SsaId constant = addressInsn.use[1];
                        if (function.values[candidate].storage.space == Space::kConstant) {
                            std::swap(candidate, constant);
                        }
                        if (function.values[constant].storage.space == Space::kConstant) {
                            base = candidate;
                            offset = function.values[constant].storage.offset;
                        } else {
                            // An index computed at run time: still a pointer, but
                            // not a fixed field.
                            usable = false;
                            markKind(&out->values[address], RecoveredTypeKind::kPointer);
                        }
                    } else if (addressInsn.op == MintOp::kSub) {
                        usable = false;
                    }
                }
                // A constant base is an absolute address — a global, or a literal
                // pool entry. Those are not one object with members, and grouping
                // them would invent a structure spanning unrelated globals whose
                // "fields" are whatever the linker happened to place nearby.
                if (usable && function.values[base].storage.space == Space::kConstant) {
                    usable = false;
                }
                if (usable) {
                    // A bare dereference is the field at offset zero. Leaving it out
                    // lost the first member of every structure whose head is read
                    // without arithmetic, which is the common case.
                    structAccesses[base].push_back({offset, accessed});
                    markKind(&out->values[base], RecoveredTypeKind::kPointer);
                }
            }
        }
    }

    // Pointer facts can be one add away from the load that exposed them. A small
    // fixed point is enough for the local arithmetic chains emitted by the lifter.
    for (unsigned pass = 0; pass < 4; ++pass) {
        bool changed = false;
        for (const SsaInsn& insn : function.insns) {
            if (insn.op != MintOp::kAdd && insn.op != MintOp::kSub) continue;
            if (!valid(function, insn.dest)) continue;
            for (unsigned slot = 0; slot < 2; ++slot) {
                if (!valid(function, insn.use[slot])) continue;
                if (out->values[insn.use[slot]].kind == RecoveredTypeKind::kPointer &&
                    out->values[insn.dest].kind != RecoveredTypeKind::kPointer) {
                    out->values[insn.dest].kind = RecoveredTypeKind::kPointer;
                    changed = true;
                }
            }
        }
        if (!changed) break;
    }

    for (auto& access : structAccesses) {
        if (access.second.size() < 2) continue;
        std::sort(access.second.begin(), access.second.end(),
                  [](const auto& a, const auto& b) { return a.first < b.first; });

        // One field per offset. The same member is normally touched many times, and
        // each access used to become its own field, so a structure read in a loop
        // came out with the same offset repeated a dozen times. Where accesses at
        // one offset disagree about width the widest wins: a four-byte read of a
        // member is consistent with an eight-byte member, not the other way round.
        std::vector<std::pair<u64, SsaId>> merged;
        for (const auto& entry : access.second) {
            if (!valid(function, entry.second)) continue;
            if (!merged.empty() && merged.back().first == entry.first) {
                if (out->values[entry.second].width >
                    out->values[merged.back().second].width) {
                    merged.back().second = entry.second;
                }
                continue;
            }
            merged.push_back(entry);
        }
        // A single field is just a dereference; it takes two to be a layout.
        if (merged.size() < 2) continue;
        access.second = merged;

        RecoveredStruct structure;
        structure.base = access.first;
        const u32 structId = static_cast<u32>(out->structs.size());
        for (const auto& field : access.second) {
            RecoveredField recovered;
            recovered.offset = field.first;
            recovered.width = out->values[field.second].width;
            recovered.base = access.first;
            recovered.type = out->values[field.second];
            structure.fields.push_back(recovered);
        }
        if (structure.fields.empty()) continue;
        out->structs.push_back(std::move(structure));
        out->values[access.first].kind = RecoveredTypeKind::kPointer;
        out->values[access.first].structId = structId;
        for (const auto& field : out->structs.back().fields) {
            // The load result is the value recovered at this offset. Look it up
            // again rather than retaining a parallel index in the public result.
            for (const auto& original : access.second) {
                if (original.first == field.offset && valid(function, original.second)) {
                    out->values[original.second].structId = structId;
                }
            }
        }
    }

    // A parameter is an incoming value in a register the convention uses to pass
    // arguments. Not every incoming value qualifies: the stack pointer and the link
    // register are live on entry to every function, and callee-saved registers are
    // read on entry by any function that saves them in its prologue. Counting those
    // reported over five parameters for the average function in a real library,
    // where the true average is closer to two.
    std::vector<std::pair<u32, SsaId>> ordered;
    for (SsaId id = 0; id < function.values.size(); ++id) {
        const SsaValue& value = function.values[id];
        if (value.def != SsaDef::kEntry || value.uses == 0) continue;
        if (value.storage.space != Space::kRegister) continue;
        const u32 position = argumentPosition(function.arch, value.storage);
        if (position == kNotAnArgument) continue;
        ordered.push_back({position, id});
    }
    // Argument order, not value order: a signature is only useful in the order the
    // convention passes things.
    std::sort(ordered.begin(), ordered.end());
    for (const auto& entry : ordered) {
        out->parameters.push_back({entry.second, out->values[entry.second]});
    }
    return Status::success();
}

}  // namespace mint
