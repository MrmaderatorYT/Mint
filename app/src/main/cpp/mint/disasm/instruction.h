#pragma once

#include <string>

#include "mint/base/types.h"

namespace mint {

/// What an instruction does to control flow. Everything above the disassembler —
/// basic-block splitting, function discovery, the CFG, the OLLVM dispatcher
/// detector — keys off this and nothing else, so it is deliberately small and
/// architecture-independent.
enum class FlowKind : u8 {
    /// Falls through to the next instruction and nothing more.
    kNormal = 0,
    /// Unconditional branch to a known address.
    kJump,
    /// Conditional branch: both the target and the fall-through are live.
    kCondJump,
    /// Direct call. Falls through on return, and the target seeds a new function.
    kCall,
    /// Branch through a register or memory. The target is unknown until either
    /// the jump table is recovered or the IR is emulated — this is the case
    /// OLLVM's dispatcher relies on, so it is never silently treated as a dead
    /// end.
    kIndirectJump,
    kIndirectCall,
    /// Returns from the function; flow stops.
    kReturn,
    /// Traps or halts: brk, hlt, ud2. Flow stops, and compilers emit these after
    /// a noreturn call, which makes them a useful function-boundary signal.
    kTrap,
    /// Bytes that do not decode. Kept in the map rather than skipped, because a
    /// run of undecodable bytes in the middle of .text usually means data was
    /// inlined into code, which the listing should show as data.
    kInvalid,
};

const char* flowKindName(FlowKind kind);

/// True when flow does not continue past this instruction.
inline bool terminatesBlock(FlowKind kind) {
    switch (kind) {
        case FlowKind::kJump:
        case FlowKind::kCondJump:
        case FlowKind::kIndirectJump:
        case FlowKind::kReturn:
        case FlowKind::kTrap:
        case FlowKind::kInvalid:
            return true;
        case FlowKind::kNormal:
        case FlowKind::kCall:
        case FlowKind::kIndirectCall:
            return false;
    }
    return false;
}

/// True when execution can continue at address + size.
inline bool fallsThrough(FlowKind kind) {
    switch (kind) {
        case FlowKind::kNormal:
        case FlowKind::kCondJump:
        case FlowKind::kCall:
        case FlowKind::kIndirectCall:
            return true;
        case FlowKind::kJump:
        case FlowKind::kIndirectJump:
        case FlowKind::kReturn:
        case FlowKind::kTrap:
        case FlowKind::kInvalid:
            return false;
    }
    return false;
}

/// The persistent record of one decoded instruction.
///
/// Deliberately 24 bytes and free of any text. A large obfuscated library
/// disassembles to several hundred thousand instructions, and storing the
/// mnemonic and operand strings alongside each one would cost tens of megabytes
/// of a phone's heap to hold data that is only ever needed for the handful of
/// lines currently on screen. Text is re-derived on demand instead; decoding a
/// single instruction is far cheaper than keeping every one of them formatted.
struct InsnRecord {
    Address address = 0;
    /// Branch or call target, or kNoAddress when there is none or it is indirect.
    Address target = kNoAddress;
    /// Capstone's instruction id, kept so later passes can recognise specific
    /// instructions without re-decoding.
    u16 id = 0;
    u8 size = 0;
    FlowKind flow = FlowKind::kInvalid;

    Address next() const { return address + size; }
    bool hasKnownTarget() const { return target != kNoAddress; }
};
static_assert(sizeof(InsnRecord) <= 24, "InsnRecord must stay small; we hold many");

/// A freshly decoded instruction including its text, for display and for the
/// lifter. Not stored in bulk.
struct DecodedInsn {
    InsnRecord record;
    std::string mnemonic;
    std::string operands;

    /// Raw bytes, for the listing's byte column.
    u8 bytes[24] = {};

    std::string text() const {
        if (operands.empty()) return mnemonic;
        return mnemonic + " " + operands;
    }
};

}  // namespace mint
