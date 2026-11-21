#include "mint/decompile/decompiler.h"

#include "mint/decompile/c_emitter.h"
#include "mint/decompile/cfg_structurer.h"
#include "mint/ir/ir_simplify.h"
#include "mint/decompile/tail_call.h"

#include <algorithm>
#include <sstream>

namespace mint {

namespace {
const char* statusName(DecompileStatus status) {
    switch (status) {
        case DecompileStatus::kComplete: return "complete";
        case DecompileStatus::kPartial: return "partial";
        case DecompileStatus::kUnsupported: return "unsupported";
        case DecompileStatus::kBudgetExhausted: return "budget-exhausted";
        case DecompileStatus::kError: return "error";
    }
    return "error";
}

std::string commentText(std::string reason) {
    for (char& ch : reason) if (ch == '\r' || ch == '\n') ch = ' ';
    for (size_t at = reason.find("*/"); at != std::string::npos; at = reason.find("*/", at + 3))
        reason.replace(at, 2, "* /");
    return reason;
}
}

void DecompileReport::note(DecompileStatus next, std::string reason, Address address) {
    status = std::max(status, next);
    // Retain the first site of each distinct limitation. Bound the report
    // independently of the size of the function.
    if (diagnostics.size() == 32 || std::any_of(diagnostics.begin(), diagnostics.end(),
            [&](const auto& diagnostic) { return diagnostic.status == next && diagnostic.reason == reason; })) return;
    diagnostics.push_back({next, std::move(reason), address});
}

void DecompileReport::noteFailure(const Status& failure, const char* stage) {
    if (failure.ok()) return;
    const auto kind = failure.code() == ErrorCode::kTooLarge ? DecompileStatus::kBudgetExhausted
        : failure.code() == ErrorCode::kUnsupported ? DecompileStatus::kUnsupported
        : DecompileStatus::kError;
    note(kind, std::string(stage) + ": " + failure.toString());
}

std::string DecompileReport::text(std::string* listingAnchors) const {
    std::ostringstream out;
    out << "/* Decompilation status: " << statusName(status) << " */\n";
    for (const auto& item : diagnostics) {
        out << "/* " << statusName(item.status) << ": " << commentText(item.reason);
        if (item.address != kNoAddress) out << " (0x" << std::hex << item.address << std::dec << ')';
        out << " */\n";
    }
    if (listingAnchors) {
        std::ostringstream anchors;
        size_t line = static_cast<size_t>(diagnostics.size()) + 1;
        size_t cursor = 0;
        const auto advance = [&](size_t offset) {
            while (cursor < offset) if (cSource[cursor++] == '\n') ++line;
        };
        for (const auto& range : sourceRanges) {
            const size_t first = sourcePrefixBytes + range.firstByte;
            const size_t end = sourcePrefixBytes + range.endByte;
            if (first >= cSource.size() || end > cSource.size() || first < cursor) continue;
            advance(first);
            const size_t firstLine = line;
            // The stream position of a control expression is a point on the line.
            if (end > first) advance(end - 1);
            anchors << firstLine << ' ' << line << ' ' << std::hex << range.start << ' '
                    << range.end << std::dec << '\n';
        }
        *listingAnchors = anchors.str();
    }
    out << cSource;
    return out.str();
}

Status decompileSsa(const SsaFunction& function, DecompileResult* result,
                    const SymbolNamer& names, const StringResolver& strings,
                    const StringResolver& offsetTable, const PrototypeResolver& prototypes,
                    const TypeLayoutResolver& typeLayouts, const LocalResolver& locals,
                    const MemoryFunctionResolver& memoryFunctions) {
    if (!result) return Status::error(ErrorCode::kInternalError, "null decompile output");
    const auto problems=function.verify();
    if(!problems.empty())return Status::error(ErrorCode::kBadFormat,"cannot decompile invalid SSA: "+problems.front());
    result->ssa = function;
    result->structure = structureControlFlow(result->ssa);
    CEmitterOptions options;
    options.names = names;
    options.strings = strings;
    options.offsetTable = offsetTable;
    options.prototypes = prototypes;
    options.typeLayouts = typeLayouts;
    options.locals = locals;
    options.memoryFunctions = memoryFunctions;
    result->report = {};
    result->cSource = emitC(result->ssa, result->structure, options, &result->report);
    return Status::success();
}

Status decompileIr(const IrFunction& input, DecompileResult* result,
                   const SymbolNamer& names, const StringResolver& strings,
                   const StringResolver& offsetTable, const PrototypeResolver& prototypes,
                   const TypeLayoutResolver& typeLayouts, const LocalResolver& locals,
                   const MemoryFunctionResolver& memoryFunctions) {
    if (!result) return Status::error(ErrorCode::kInternalError, "null decompile output");
    IrFunction normalized = input;
    // Physical tail inputs become real IR uses before SSA liveness/phi placement.
    // Unknown declarations retain only the low-level terminal transfer.
    const auto caller=prototypes?prototypes(input.entry):UserPrototype{};
    for(auto& insn:normalized.insns)if(insn.op==MintOp::kTailCall){
        insn.tailInputs.clear();TailCallContract contract;
        if(insn.a.isConstant()&&prototypes&&buildTailCallContract(input.arch,input.byteOrder,caller,prototypes(insn.a.offset),typeLayouts,&contract).ok())
            for(const auto& parameter:contract.calleeAbi.parameters)insn.tailInputs.push_back(parameter.pieces[0].storage);
    }
    result->normalize = normalizeRegisterAccesses(&normalized);
    IrSimplifyStats simplifyStats;
    Status status = simplifyIr(&normalized, &simplifyStats);
    if (!status.ok()) return status;
    result->ssaStats = {};
    status = buildSsa(normalized, &result->ssa, &result->ssaStats);
    if (!status.ok()) return status;
    return decompileSsa(result->ssa, result, names, strings, offsetTable, prototypes, typeLayouts, locals, memoryFunctions);
}

}  // namespace mint
