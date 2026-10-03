#include "mint/decompile/decompiler.h"

#include "mint/decompile/c_emitter.h"
#include "mint/decompile/cfg_structurer.h"
#include "mint/ir/ir_simplify.h"

namespace mint {

Status decompileSsa(const SsaFunction& function, DecompileResult* result,
                    const SymbolNamer& names, const StringResolver& strings,
                    const StringResolver& offsetTable, const PrototypeResolver& prototypes,
                    const TypeLayoutResolver& typeLayouts, const LocalResolver& locals) {
    if (!result) return Status::error(ErrorCode::kInternalError, "null decompile output");
    result->ssa = function;
    result->structure = structureControlFlow(result->ssa);
    CEmitterOptions options;
    options.names = names;
    options.strings = strings;
    options.offsetTable = offsetTable;
    options.prototypes = prototypes;
    options.typeLayouts = typeLayouts;
    options.locals = locals;
    result->cSource = emitC(result->ssa, result->structure, options);
    return Status::success();
}

Status decompileIr(const IrFunction& input, DecompileResult* result,
                   const SymbolNamer& names, const StringResolver& strings,
                   const StringResolver& offsetTable, const PrototypeResolver& prototypes,
                   const TypeLayoutResolver& typeLayouts, const LocalResolver& locals) {
    if (!result) return Status::error(ErrorCode::kInternalError, "null decompile output");
    IrFunction normalized = input;
    result->normalize = normalizeRegisterAccesses(&normalized);
    IrSimplifyStats simplifyStats;
    Status status = simplifyIr(&normalized, &simplifyStats);
    if (!status.ok()) return status;
    result->ssaStats = {};
    status = buildSsa(normalized, &result->ssa, &result->ssaStats);
    if (!status.ok()) return status;
    return decompileSsa(result->ssa, result, names, strings, offsetTable, prototypes, typeLayouts, locals);
}

}  // namespace mint
