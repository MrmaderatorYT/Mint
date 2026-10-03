#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include "mint/decompile/control_flow_ast.h"
#include "mint/decompile/decompiler.h"
#include "mint/ir/normalize.h"
#include "mint/ir/registers.h"
#include "mint/ssa/ssa_builder.h"

using namespace mint;
namespace {
using Graph = std::vector<std::vector<u32>>;
size_t checks = 0;
std::ostringstream cFixtures;
void require(bool condition, const std::string& message) { ++checks; if (!condition) { std::cerr << "FAIL: " << message << '\n'; std::exit(1); } }
SsaFunction fixture(const Graph& graph, const std::set<u32>& switches = {}) {
    SsaFunction f; f.entry = 0x1000; f.arch = Arch::kAArch64; f.name = "ast_fixture";
    f.blocks.resize(graph.size());
    for (u32 id = 0; id < graph.size(); ++id) {
        auto& block = f.blocks[id]; block.id = id; block.start = 0x1000 + id * 0x20; block.end = block.start + 0x20; block.successors = graph[id]; block.firstInsn = f.insns.size();
        SsaValue marker; marker.storage = Varnode::constant(id + 1, 8); f.values.push_back(marker);
        SsaValue address; address.storage = Varnode::constant(0x5000, 8); f.values.push_back(address);
        SsaInsn store; store.op = MintOp::kStore; store.use[0] = f.values.size() - 1; store.use[1] = f.values.size() - 2; store.block = id; f.insns.push_back(store);
        SsaInsn term; term.block = id; term.address = block.start + 4;
        if (graph[id].empty()) term.op = MintOp::kReturn;
        else if (switches.count(id)) term.op = MintOp::kBranchInd;
        else if (graph[id].size() == 2) term.op = MintOp::kCondBranch;
        else term.op = MintOp::kBranch;
        if (term.op == MintOp::kCondBranch || term.op == MintOp::kBranchInd) { SsaValue condition; condition.def = SsaDef::kEntry; condition.storage = Varnode::temp(id, 8); condition.uses = 1; f.values.push_back(condition); term.use[0] = f.values.size() - 1; }
        f.insns.push_back(term); block.insnCount = 2;
    }
    for (auto& block : f.blocks) for (auto next : block.successors) f.blocks[next].predecessors.push_back(block.id);
    return f;
}
struct Trace { std::vector<u32> blocks; std::vector<std::pair<u32, u32>> edges; bool returned = false; };
struct Runtime {
    const SsaFunction& function;
    std::map<u32, unsigned> visits;
    Trace trace;
    std::function<bool(u32, unsigned)> predicate;
    std::function<unsigned(u32, unsigned)> selector;
    void block(u32 id) { require(trace.blocks.size() < 1000, "execution trace budget"); trace.blocks.push_back(id); ++visits[id]; }
    bool condition(u32 id) { return predicate ? predicate(id, visits[id]) : false; }
    unsigned target(u32 id) { return selector ? selector(id, visits[id]) : 0; }
};
Trace original(const SsaFunction& f, const std::function<bool(u32, unsigned)>& predicate, const std::function<unsigned(u32, unsigned)>& selector) {
    Runtime runtime{f, {}, {}, predicate, selector}; u32 current = 0;
    for (unsigned step = 0; step < 1000; ++step) {
        runtime.block(current); const auto& block = f.blocks[current]; const auto op = f.insns[block.firstInsn + block.insnCount - 1].op;
        if (op == MintOp::kReturn) { runtime.trace.returned = true; return runtime.trace; }
        u32 next = kNoBlock;
        if (op == MintOp::kCondBranch) next = block.successors[runtime.condition(current) ? 0 : 1];
        else if (op == MintOp::kBranchInd) { const auto index = runtime.target(current); if (index >= block.successors.size()) return runtime.trace; next = block.successors[index]; }
        else if (!block.successors.empty()) next = block.successors.front();
        if (next == kNoBlock) return runtime.trace; runtime.trace.edges.emplace_back(current, next); current = next;
    }
    require(false, "original test CFG must terminate"); return {};
}
struct Flow { enum Kind { None, Go, Continue, Break, Return } kind = None; u32 target = kNoBlock; };
Flow execute(u32 id, const ControlFlowAst& ast, Runtime& runtime, unsigned depth = 0) {
    require(depth < 256, "AST interpreter depth"); const auto& node = ast.nodes[id];
    switch (node.kind) {
        case ControlFlowAstKind::kBlock: runtime.block(node.block); if (runtime.function.insns[runtime.function.blocks[node.block].firstInsn + runtime.function.blocks[node.block].insnCount - 1].op == MintOp::kReturn) { runtime.trace.returned = true; return {Flow::Return, kNoBlock}; } return {};
        case ControlFlowAstKind::kEdge: runtime.trace.edges.emplace_back(node.from, node.target); return {};
        case ControlFlowAstKind::kIf: return execute(node.children[runtime.condition(node.condition.block) != node.condition.negated ? 0 : 1], ast, runtime, depth + 1);
        case ControlFlowAstKind::kSwitch: { const auto index = runtime.target(node.condition.block); if (index >= node.arms.size()) return {Flow::Go, kNoBlock}; return execute(node.arms[index].body, ast, runtime, depth + 1); }
        case ControlFlowAstKind::kGoto: return {Flow::Go, node.target};
        case ControlFlowAstKind::kBreak: return {Flow::Break, node.target};
        case ControlFlowAstKind::kContinue: return {Flow::Continue, node.target};
        case ControlFlowAstKind::kLoop:
            for (unsigned iteration = 0; iteration < 1000; ++iteration) { const auto flow = execute(node.children[0], ast, runtime, depth + 1); if (flow.kind == Flow::Break && flow.target == node.target) return {}; if (flow.kind != Flow::None && !(flow.kind == Flow::Continue && flow.target == node.block)) return flow; }
            require(false, "test loop must terminate"); return {};
        case ControlFlowAstKind::kSequence: for (auto child : node.children) { const auto flow = execute(child, ast, runtime, depth + 1); if (flow.kind != Flow::None) return flow; } return {};
        case ControlFlowAstKind::kFallback:
            for (size_t position = 0, steps = 0; position < node.children.size() && steps < 10000; ++steps) {
                const auto flow = execute(node.children[position++], ast, runtime, depth + 1);
                if (flow.kind == Flow::Go && flow.target != kNoBlock) { auto owner = ast.blockOwner[flow.target]; auto target = std::find(node.children.begin(), node.children.end(), owner); require(target != node.children.end(), "fallback target original block label"); position = target - node.children.begin(); }
                else if (flow.kind != Flow::None) return flow;
            }
            return {};
    }
    return {};
}
void equivalent(const SsaFunction& f, const ControlFlowAst& ast, std::function<bool(u32, unsigned)> predicate = {}, std::function<unsigned(u32, unsigned)> selector = {}) {
    const auto expected = original(f, predicate, selector); Runtime runtime{f, {}, {}, predicate, selector}; execute(ast.root, ast, runtime);
    require(expected.blocks == runtime.trace.blocks, "original block statement/side-effect order preserved");
    require(expected.edges == runtime.trace.edges, "exact executed phi-copy edge order preserved");
    require(expected.returned == runtime.trace.returned, "return/unresolved termination preserved");
}
ControlFlowAst build(const SsaFunction& f) {
    ControlFlowAst ast; const auto status = buildControlFlowAst(f, &ast); require(status.ok(), "AST build: " + status.message());
    require(ast.blockOwner.size() == f.blocks.size(), "one ownership slot per block");
    std::set<std::pair<u32, u32>> actual, emitted;
    for (const auto& block : f.blocks) for (auto next : block.successors) actual.emplace(block.id, next);
    size_t blocks = 0; for (const auto& node : ast.nodes) { if (node.kind == ControlFlowAstKind::kBlock) ++blocks; if (node.kind == ControlFlowAstKind::kEdge) require(emitted.emplace(node.from, node.target).second, "no duplicate original edge"); }
    require(actual == emitted && blocks == f.blocks.size(), "every original block and edge exactly once"); return ast;
}
std::string render(const ControlFlowAst& ast) {
    std::ostringstream out; ControlFlowAstCallbacks cb;
    cb.block = [&](u32 id) { out << "    side_effect(" << id << ");\n"; };
    cb.edge = [&](u32 from, u32 target) { out << "    edge_copies(" << from << ',' << target << ");\n"; };
    cb.condition = [](u32 id) { return "condition_" + std::to_string(id); };
    cb.indirectTarget = [](u32 id) { return "target_" + std::to_string(id); };
    cb.label = [](u32 id) { return "L" + std::to_string(id); };
    const auto status = emitControlFlowAst(ast, out, cb); require(status.ok(), "AST rendering: " + status.message()); return out.str();
}
void structured() {
    const auto nested = fixture({{4, 1}, {6}, {5}, {5}, {3, 2}, {6}, {}}); const auto nestedAst = build(nested);
    require(nestedAst.structured && nestedAst.ifCount == 2 && !nestedAst.loopCount, "non-contiguous nested if regions");
    for (unsigned choice = 0; choice < 4; ++choice) equivalent(nested, nestedAst, [=](u32 block, unsigned) { return block == 0 ? choice & 1 : choice & 2; });
    const auto nestedText = render(nestedAst); require(nestedText.find("goto L") == std::string::npos && nestedText.find("condition_4") != std::string::npos, "nested if has no unnecessary gotos/merged conditions");

    const auto whileLoop = fixture({{1}, {2, 5}, {3, 4}, {1}, {1}, {}}); const auto whileAst = build(whileLoop);
    require(whileAst.structured && whileAst.loopCount == 1 && whileAst.ifCount == 2, "multi-latch natural loop contains nested if");
    equivalent(whileLoop, whileAst, [](u32 block, unsigned visit) { return block == 1 ? visit <= 3 : visit % 2; });
    const auto loopText = render(whileAst); require(loopText.find("while (true)") < loopText.find("side_effect(1)"), "header side effects inside every loop iteration");
    require(loopText.find("continue;") != std::string::npos && loopText.find("goto L5;") != std::string::npos, "loop backedge and exact exit remain explicit");

    const auto nestedLoop = fixture({{1}, {2, 6}, {3, 4}, {2}, {5}, {1}, {}}); const auto nestedLoopAst = build(nestedLoop);
    require(nestedLoopAst.structured && nestedLoopAst.loopCount == 2, "nested natural loop regions");
    equivalent(nestedLoop, nestedLoopAst, [](u32 block, unsigned visit) { return block == 1 ? visit <= 2 : visit % 3 != 0; });

    const auto postLoop = fixture({{1}, {2}, {1, 3}, {}}); const auto postAst = build(postLoop); require(postAst.structured && postAst.loopCount == 1, "post-tested loop preserved as explicit loop AST");
    equivalent(postLoop, postAst, [](u32, unsigned visit) { return visit < 4; });

    const auto self = fixture({{0, 1}, {}}); const auto selfAst = build(self); require(selfAst.structured && selfAst.loopCount == 1, "single-block loop"); equivalent(self, selfAst, [](u32, unsigned visit) { return visit < 4; });

    const auto dispatch = fixture({{3, 1, 2}, {4}, {4}, {4}, {}}, {0}); const auto dispatchAst = build(dispatch);
    require(dispatchAst.structured && dispatchAst.switchCount == 1, "computed-target switch AST"); for (unsigned choice = 0; choice < 4; ++choice) equivalent(dispatch, dispatchAst, {}, [=](u32, unsigned) { return choice; });
    const auto switchText = render(dispatchAst); require(switchText.find("switch ((uintptr_t)(target_0))") != std::string::npos && switchText.find("case 0x1060ULL") != std::string::npos && switchText.find("default: goto unresolved_indirect") != std::string::npos, "switch cases use actual target addresses and preserve unknown flow");

    const auto switchLoop = fixture({{1}, {2, 5}, {3, 5, 4}, {1}, {1}, {}}, {2}); const auto switchLoopAst = build(switchLoop);
    require(switchLoopAst.structured && switchLoopAst.loopCount == 1 && switchLoopAst.switchCount == 1, "switch nested in loop");
    for (unsigned choice = 0; choice < 3; ++choice) equivalent(switchLoop, switchLoopAst, [](u32, unsigned visit) { return visit < 4; }, [=](u32, unsigned) { return choice; });
    require(render(switchLoopAst).find("goto L5;") != std::string::npos, "loop exit nested in switch does not become wrong switch break");
    const auto indirectExit = fixture({{1}, {2, 6}, {3, 4, 5}, {1}, {6}, {1}, {}}, {2});
    const auto indirectExitAst = build(indirectExit); require(!indirectExitAst.structured, "switch with distinct loop-exit bridge remains conservative labelled fallback");
    for (unsigned choice = 0; choice < 3; ++choice) equivalent(indirectExit, indirectExitAst, [](u32, unsigned visit) { return visit < 4; }, [=](u32, unsigned) { return choice; });
}
void fallbacks() {
    const auto irreducible = fixture({{1, 2}, {2, 3}, {1, 3}, {}}); const auto ast = build(irreducible);
    require(!ast.structured && !ast.diagnostics.empty(), "two-entry cycle is explicitly irreducible fallback");
    equivalent(irreducible, ast, [](u32 block, unsigned visit) { return block == 0 || visit < 3; }); require(render(ast).find("AST fallback") != std::string::npos, "fallback shown to user");
    const auto exits = fixture({{1}, {2, 4}, {1, 3}, {}, {}}); const auto exitsAst = build(exits); require(!exitsAst.structured, "multi-exit loop conservatively labelled");
    equivalent(exits, exitsAst, [](u32 block, unsigned visit) { return block == 1 || visit < 2; });
    const auto unreachable = fixture({{}, {}}); const auto unreachableAst = build(unreachable); require(!unreachableAst.structured && unreachableAst.blockOwner.size() == 2, "unreachable original blocks retained"); equivalent(unreachable, unreachableAst);
    auto malformed = fixture({{1}, {}}); malformed.blocks[0].successors = {17}; ControlFlowAst sentinel; sentinel.ifCount = 99;
    require(!buildControlFlowAst(malformed, &sentinel).ok() && sentinel.ifCount == 99, "invalid CFG leaves output untouched");
    malformed = fixture({{1}, {}}); malformed.blocks[1].firstInsn = malformed.blocks[0].firstInsn; require(!buildControlFlowAst(malformed, &sentinel).ok(), "overlapping instruction ownership rejected");
    malformed = fixture({{1, 2}, {}, {}}); malformed.insns[1].use[0] = kNoValue; require(!buildControlFlowAst(malformed, &sentinel).ok(), "missing condition is never guessed");
    auto corrupt = ast; corrupt.nodes[corrupt.root].children.push_back(corrupt.root); std::ostringstream unchanged; unchanged << "sentinel"; ControlFlowAstCallbacks callbacks;
    callbacks.block = [](u32) {}; callbacks.edge = [](u32, u32) {}; callbacks.condition = callbacks.indirectTarget = callbacks.label = [](u32) { return "x"; };
    require(!emitControlFlowAst(corrupt, unchanged, callbacks).ok() && unchanged.str() == "sentinel", "cyclic AST rejected before any output/callback");
    const auto text = controlFlowAstText(ast); require(text.find("fallback") != std::string::npos && text.find("from=") != std::string::npos, "AST diagnostic rendering");
    SsaFunction enormous; enormous.blocks.resize(4097); require(buildControlFlowAst(enormous, &sentinel).code() == ErrorCode::kTooLarge, "block resource cap");
}
void native(Arch arch) {
    const Graph graphs[] = {{{4, 1}, {6}, {5}, {5}, {3, 2}, {6}, {}}, {{1}, {2, 5}, {3, 4}, {1}, {1}, {}}, {{3, 1, 2}, {4}, {4}, {4}, {}}};
    for (unsigned shape = 0; shape < 3; ++shape) {
        IrFunction ir; ir.arch = arch; ir.entry = 0x1000; ir.name = "native_ast_" + std::to_string(static_cast<unsigned>(arch)) + "_" + std::to_string(shape); ir.blocks.resize(graphs[shape].size()); u64 temporary = 0;
        const auto result = Varnode::reg(arch == Arch::kAArch64 ? arm64::kXn(0) : x86::kRax, 8);
        for (u32 id = 0; id < ir.blocks.size(); ++id) {
            auto& block = ir.blocks[id]; block.id = id; block.start = 0x1000 + id * 0x20; block.end = block.start + 0x20; block.successors = graphs[shape][id]; block.firstInsn = ir.insns.size();
            auto add = [&](MintOp op, Varnode dest = Varnode::invalid(), Varnode a = Varnode::invalid(), Varnode b = Varnode::invalid()) { IrInsn value; value.op = op; value.dest = dest; value.a = a; value.b = b; value.address = block.start + block.insnCount * 4; ir.insns.push_back(value); ++block.insnCount; };
            if (!id) add(MintOp::kCopy, result, Varnode::constant(1, 8));
            else if (block.successors.size() == 1) add(MintOp::kAdd, result, result, Varnode::constant(id + 1, 8));
            add(MintOp::kStore, Varnode::invalid(), Varnode::constant(0x5000, 8), Varnode::constant(id + 1, 8));
            if (block.successors.empty()) { add(MintOp::kStore, Varnode::invalid(), Varnode::constant(0x7000, 8), result); add(MintOp::kReturn, Varnode::invalid(), arch == Arch::kAArch64 ? Varnode::reg(arm64::kXn(30), 8) : Varnode::constant(0x4000, 8)); }
            else if (shape == 2 && id == 0) { auto target = Varnode::temp(temporary++, 8); add(MintOp::kLoad, target, Varnode::constant(0x6000, 8)); add(MintOp::kBranchInd, Varnode::invalid(), target); }
            else if (block.successors.size() == 2) { auto condition = Varnode::temp(temporary++, 1); add(MintOp::kLoad, condition, Varnode::constant(0x6000 + id, 8)); add(MintOp::kCondBranch, Varnode::invalid(), condition, Varnode::constant(0x1000 + block.successors[0] * 0x20, 8)); }
            else add(MintOp::kBranch, Varnode::invalid(), Varnode::constant(0x1000 + block.successors[0] * 0x20, 8));
        }
        ir.tempCount = temporary; for (const auto& block : ir.blocks) for (auto next : block.successors) ir.blocks[next].predecessors.push_back(block.id);
        require(ir.verify().empty(), "native IR fixture verifies"); normalizeRegisterAccesses(&ir); SsaFunction ssa; SsaBuildStats stats; const auto status = buildSsa(ir, &ssa, &stats);
        require(status.ok() && ssa.verify().empty(), "native SSA fixture verifies: " + status.message()); const auto ast = build(ssa); require(ast.structured, "native SSA nested if/loop/switch structured");
        require(std::any_of(ssa.phis.begin(), ssa.phis.end(), [](const SsaPhi& phi) { return !phi.dead; }), "native fixture retains live loop/join phi values");
        DecompileResult decompiled; require(decompileSsa(ssa, &decompiled).ok() && !decompiled.cSource.empty(), "native SSA goes through decompiler");
        cFixtures << decompiled.cSource << '\n';
    }
}
IrFunction singleBlock(Arch arch, const std::string& name) {
    IrFunction ir; ir.arch = arch; ir.entry = 0x1000; ir.name = name;
    IrBlock block; block.id = 0; block.start = 0x1000; block.end = 0x2000; ir.blocks.push_back(block); return ir;
}
void instruction(IrFunction& ir, MintOp op, Varnode dest = Varnode::invalid(), Varnode a = Varnode::invalid(), Varnode b = Varnode::invalid()) {
    IrInsn insn; insn.op = op; insn.dest = dest; insn.a = a; insn.b = b; insn.address = 0x1000 + ir.insns.size() * 4; ir.insns.push_back(insn); ++ir.blocks[0].insnCount;
}
void identity(Arch arch) {
    auto ir = singleBlock(arch, "identity_" + std::to_string(static_cast<unsigned>(arch)));
    const auto incoming = Varnode::reg(arch == Arch::kAArch64 ? arm64::kXn(0) : x86::kRdi, 8);
    const auto result = Varnode::reg(arch == Arch::kAArch64 ? arm64::kXn(0) : x86::kRax, 8);
    instruction(ir, MintOp::kCopy, result, incoming);
    instruction(ir, MintOp::kReturn, Varnode::invalid(), arch == Arch::kAArch64 ? Varnode::reg(arm64::kXn(30), 8) : Varnode::constant(0x4000, 8));
    UserPrototype prototype; require(parseUserPrototype("uint64_t(uint64_t input)", &prototype).ok(), "identity prototype");
    DecompileResult declared, heuristic;
    require(decompileIr(ir, &declared, {}, {}, {}, [&](Address) { return prototype; }).ok(), "declared identity decompilation");
    require(declared.ssa.verify().empty(), "identity canonical return SSA verifies");
    require(declared.cSource.find("return (uint64_t)(input);") != std::string::npos, "authoritative identity returns the entry parameter, not zero");
    require(decompileIr(ir, &heuristic).ok() && heuristic.cSource.find("void identity_") != std::string::npos, "unknown entry return does not invent a nonvoid heuristic prototype");
    cFixtures << declared.cSource << '\n';
}
void narrowReturn(Arch arch) {
    auto ir = singleBlock(arch, "narrow_return_" + std::to_string(static_cast<unsigned>(arch)));
    const auto result = Varnode::reg(arch == Arch::kArm32 ? arm32::kRn(0) : riscv::kXn(10), 4);
    const auto link = Varnode::reg(arch == Arch::kArm32 ? arm32::kLr : riscv::kXn(1), 4);
    instruction(ir, MintOp::kCopy, result, Varnode::constant(123, 4)); instruction(ir, MintOp::kReturn, Varnode::invalid(), link);
    DecompileResult out; require(decompileIr(ir, &out).ok() && out.ssa.verify().empty(), "32-bit return SSA verifies");
    require(out.cSource.find("uint32_t narrow_return_") != std::string::npos, "inferred return width respects native32-bit ABI"); cFixtures << out.cSource << '\n';
}
void declaredFields() {
    DataTypeManager types;
    require(types.define("Record=struct{tag:u8;payload:u64@8}").ok(), "declared exact field layout");
    require(types.define("Wire=packed{tag:u8;payload:u64@8}").ok(), "packed layout fixture");
    require(types.define("FloatRecord=struct{tag:u8;payload:f64@8}").ok(), "float layout fixture");
    require(types.define("PointerRecord=struct{tag:u8;payload:u64*@8}").ok(), "pointer layout fixture");
    auto ir = singleBlock(Arch::kAArch64, "typed_fields"); ir.tempCount = 6;
    const auto base = Varnode::reg(arm64::kXn(0), 8), address = Varnode::temp(0, 8), first = Varnode::temp(1, 8), second = Varnode::temp(2, 8);
    instruction(ir, MintOp::kAdd, address, base, Varnode::constant(8, 8));
    instruction(ir, MintOp::kLoad, first, address);
    instruction(ir, MintOp::kStore, Varnode::invalid(), address, Varnode::constant(42, 8));
    instruction(ir, MintOp::kLoad, second, address);
    instruction(ir, MintOp::kAdd, base, first, second);
    instruction(ir, MintOp::kReturn, Varnode::invalid(), Varnode::reg(arm64::kXn(30), 8));
    auto decompile = [&](const IrFunction& input, const std::string& name, bool resolver = true) {
        UserPrototype prototype; require(parseUserPrototype("uint64_t(" + name + "* object)", &prototype).ok(), "named pointer prototype");
        DecompileResult out; const auto status = decompileIr(input, &out, {}, {}, {}, [&](Address) { return prototype; },
            resolver ? TypeLayoutResolver([&](const std::string& expression, DataTypeLayout* layout) { return types.resolve(expression, layout); }) : TypeLayoutResolver{});
        require(status.ok() && out.ssa.verify().empty(), "declared field SSA/decompilation: " + status.message()); return out.cSource;
    };
    const auto typed = decompile(ir, "Record"); const auto field = "((Record*)(uintptr_t)object)->payload";
    auto firstLoad = typed.find(field), store = typed.find(field, firstLoad + 1), secondLoad = typed.find(field, store + 1);
    require(firstLoad != std::string::npos && store != std::string::npos && secondLoad != std::string::npos && typed.find(field, secondLoad + 1) == std::string::npos,
            "two materialized exact field loads retain original intervening store order");
    require(decompile(ir, "Record", false).find("->payload") == std::string::npos, "no resolver means no authoritative field binding");
    require(decompile(ir, "Wire").find("->payload") == std::string::npos, "packed fields remain raw rather than guessing alignment");
    require(decompile(ir, "FloatRecord").find("->payload") == std::string::npos, "floating representation fields remain raw");
    require(decompile(ir, "PointerRecord").find("->payload") == std::string::npos, "pointer representation fields remain raw");
    auto mixed = singleBlock(Arch::kAArch64, "mixed_field_widths"); mixed.tempCount = 4;
    instruction(mixed, MintOp::kAdd, address, base, Varnode::constant(8, 8));
    instruction(mixed, MintOp::kLoad, first, address);
    instruction(mixed, MintOp::kLoad, Varnode::temp(2, 4), address);
    instruction(mixed, MintOp::kZeroExt, Varnode::temp(3, 8), Varnode::temp(2, 4));
    instruction(mixed, MintOp::kAdd, base, first, Varnode::temp(3, 8));
    instruction(mixed, MintOp::kReturn, Varnode::invalid(), Varnode::reg(arm64::kXn(30), 8));
    require(decompile(mixed, "Record").find("->payload") == std::string::npos, "all accesses of a shared SSA address must have exact declared width");
    std::string header; require(types.cHeader(&header).ok(), "exact declared C header fixture"); cFixtures << header << typed << '\n';
}
void executableLoop() {
    // The body changes the next header's limit. Hoisting that load would execute
    // three iterations rather than two; live loop and nested-join phis also
    // determine the result and observable payload store.
    const Graph graph = {{1}, {2, 6}, {3, 4}, {5}, {5}, {1}, {}};
    IrFunction ir; ir.arch = Arch::kAArch64; ir.entry = 0x1000; ir.name = "generated_loop_semantics"; ir.blocks.resize(graph.size()); ir.tempCount = 8;
    const auto parameter = Varnode::reg(arm64::kXn(0), 8), count = Varnode::reg(arm64::kXn(1), 8), selected = Varnode::reg(arm64::kXn(2), 8);
    const auto base = Varnode::temp(0, 8), limit = Varnode::temp(1, 8), condition = Varnode::temp(2, 1);
    const auto selectorAddress = Varnode::temp(3, 8), selector = Varnode::temp(4, 8), selectorCondition = Varnode::temp(5, 1), payload = Varnode::temp(6, 8), nextLimit = Varnode::temp(7, 8);
    for (u32 id = 0; id < graph.size(); ++id) {
        auto& block = ir.blocks[id]; block.id = id; block.start = 0x1000 + id * 0x40; block.end = block.start + 0x40; block.firstInsn = ir.insns.size(); block.successors = graph[id];
        auto add = [&](MintOp op, Varnode dest = Varnode::invalid(), Varnode a = Varnode::invalid(), Varnode b = Varnode::invalid()) { IrInsn insn; insn.op = op; insn.dest = dest; insn.a = a; insn.b = b; insn.address = block.start + block.insnCount * 4; ir.insns.push_back(insn); ++block.insnCount; };
        if (!id) { add(MintOp::kCopy, base, parameter); add(MintOp::kCopy, count, Varnode::constant(0, 8)); }
        if (id == 1) { add(MintOp::kLoad, limit, base); add(MintOp::kLessU, condition, count, limit); }
        if (id == 2) { add(MintOp::kAdd, selectorAddress, base, Varnode::constant(8, 8)); add(MintOp::kLoad, selector, selectorAddress); add(MintOp::kNotEqual, selectorCondition, selector, Varnode::constant(0, 8)); }
        if (id == 3 || id == 4) add(MintOp::kAdd, selected, count, Varnode::constant(id == 3 ? 10 : 20, 8));
        if (id == 5) { add(MintOp::kAdd, payload, base, Varnode::constant(16, 8)); add(MintOp::kStore, Varnode::invalid(), payload, selected); add(MintOp::kAdd, count, count, Varnode::constant(1, 8)); add(MintOp::kSub, nextLimit, limit, Varnode::constant(1, 8)); add(MintOp::kStore, Varnode::invalid(), base, nextLimit); }
        if (id == 6) { add(MintOp::kCopy, parameter, count); add(MintOp::kReturn, Varnode::invalid(), Varnode::reg(arm64::kXn(30), 8)); }
        else if (block.successors.size() == 2) add(MintOp::kCondBranch, Varnode::invalid(), id == 1 ? condition : selectorCondition, Varnode::constant(0x1000 + block.successors[0] * 0x40, 8));
        else add(MintOp::kBranch, Varnode::invalid(), Varnode::constant(0x1000 + block.successors[0] * 0x40, 8));
    }
    for (const auto& block : ir.blocks) for (auto next : block.successors) ir.blocks[next].predecessors.push_back(block.id);
    require(ir.verify().empty(), "executable phi/header-load IR verifies");
    UserPrototype prototype; require(parseUserPrototype("uint64_t(uint64_t* memory)", &prototype).ok(), "executable fixture prototype");
    DecompileResult out; require(decompileIr(ir, &out, {}, {}, {}, [&](Address) { return prototype; }).ok() && out.ssa.verify().empty(), "executable phi/header-load SSA verifies");
    require(build(out.ssa).structured && std::count_if(out.ssa.phis.begin(), out.ssa.phis.end(), [](const SsaPhi& phi) { return !phi.dead; }) >= 2, "executable fixture has structured loop and live loop/join phis");
    cFixtures << out.cSource << '\n';
}
}  // namespace
int main(int argc, char** argv) {
    cFixtures << "#include <stdint.h>\n#include <stdbool.h>\n";
    structured(); fallbacks(); native(Arch::kAArch64); native(Arch::kX86_64); identity(Arch::kAArch64); identity(Arch::kX86_64); narrowReturn(Arch::kArm32); narrowReturn(Arch::kRiscV32); declaredFields(); executableLoop();
    cFixtures << "\n#ifdef MINT_AST_GENERATED_MAIN\nint main(void) {\n"
        "    uint64_t memory[3] = {3, 1, 0};\n"
        "    if (generated_loop_semantics(memory) != 2 || memory[0] != 1 || memory[2] != 11) return 1;\n"
        "    memory[0] = 3; memory[1] = 0; memory[2] = 0;\n"
        "    if (generated_loop_semantics(memory) != 2 || memory[0] != 1 || memory[2] != 21) return 2;\n"
        "    Record object = {0}; object.payload = 7;\n"
        "    if (typed_fields(&object) != 49 || object.payload != 42) return 3;\n"
        "    if (identity_1(123) != 123 || identity_2(456) != 456) return 4;\n"
        "    return 0;\n}\n#endif\n";
    if (argc == 3 && std::string(argv[1]) == "--emit-c") { std::ofstream output(argv[2], std::ios::binary); output << cFixtures.str(); require(output.good(), "write owned C syntax-verification fixture"); }
    else require(argc == 1, "usage: mint_control_flow_ast_test [--emit-c output.c]");
    std::cout << "Control-flow AST: " << checks << " checks; passed\n";
}
