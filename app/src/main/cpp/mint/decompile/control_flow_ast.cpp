#include "mint/decompile/control_flow_ast.h"

#include <algorithm>
#include <iomanip>
#include <limits>
#include <map>
#include <set>
#include <sstream>
#include <utility>

namespace mint {
namespace {
constexpr size_t kMaxBlocks = 4096, kMaxEdges = 32768, kMaxNodes = 65536;
constexpr u64 kMaxWork = 32000000;
Status bad(const std::string& text) { return Status::error(ErrorCode::kBadFormat, "control-flow AST: " + text); }
Status large() { return Status::error(ErrorCode::kTooLarge, "control-flow AST resource budget exceeded"); }
using Graph = std::vector<std::vector<u32>>;
using Region = std::set<u32>;
struct Dom {
    std::vector<std::vector<u64>> bits;
    std::vector<bool> reachable;
    std::vector<u32> immediate;
    bool dominates(u32 a, u32 b) const { return a < bits.size() && b < bits.size() && reachable[a] && reachable[b] && (bits[b][a / 64] & (u64(1) << (a % 64))); }
};
bool dominance(const Graph& graph, Dom* out, u64* work) {
    const size_t n = graph.size(), words = (n + 63) / 64;
    Graph preds(n); for (u32 i = 0; i < n; ++i) for (auto next : graph[i]) preds[next].push_back(i);
    std::vector<u8> state(n, 0); std::vector<u32> order;
    std::vector<std::pair<u32, size_t>> stack{{0, 0}}; state[0] = 1;
    while (!stack.empty()) { auto& item = stack.back(); if (item.second < graph[item.first].size()) { auto next = graph[item.first][item.second++]; if (!state[next]) { state[next] = 1; stack.emplace_back(next, 0); } } else { order.push_back(item.first); state[item.first] = 2; stack.pop_back(); } }
    std::reverse(order.begin(), order.end()); out->reachable.resize(n); out->bits.assign(n, std::vector<u64>(words)); out->immediate.assign(n, kNoBlock);
    std::vector<u64> all(words, 0); for (auto node : order) { out->reachable[node] = true; all[node / 64] |= u64(1) << (node % 64); }
    for (auto node : order) out->bits[node] = node ? all : std::vector<u64>(words, 0);
    out->bits[0][0] = 1; out->immediate[0] = 0;
    for (bool changed = true; changed;) {
        changed = false;
        for (auto node : order) if (node) {
            auto value = all;
            for (auto pred : preds[node]) if (out->reachable[pred]) {
                if ((*work += words) > kMaxWork) return false;
                for (size_t word = 0; word < words; ++word) value[word] &= out->bits[pred][word];
            }
            value[node / 64] |= u64(1) << (node % 64);
            if (value != out->bits[node]) { out->bits[node] = std::move(value); changed = true; }
        }
    }
    std::vector<unsigned> depths(n);
    for (auto node : order) for (auto word : out->bits[node]) depths[node] += static_cast<unsigned>(__builtin_popcountll(word));
    for (auto node : order) if (node) {
        unsigned best = 0;
        for (auto candidate : order) { if (++*work > kMaxWork) return false; if (candidate != node && out->dominates(candidate, node) && depths[candidate] > best) { best = depths[candidate]; out->immediate[node] = candidate; } }
    }
    return true;
}
struct Loop { u32 header = kNoBlock, exit = kNoBlock; Region body; std::vector<u32> latches; };
class Builder {
public:
    Builder(const SsaFunction& function, ControlFlowAst* out) : f_(function), out_(*out) {}
    Status run();
private:
    u32 node(ControlFlowAstKind kind) { if (out_.nodes.size() >= kMaxNodes) { okay_ = false; return kNoAstNode; } ControlFlowAstNode value; value.kind = kind; out_.nodes.push_back(std::move(value)); return static_cast<u32>(out_.nodes.size() - 1); }
    u32 sequence() { return node(ControlFlowAstKind::kSequence); }
    void child(u32 parent, u32 value) { if (parent >= out_.nodes.size() || value >= out_.nodes.size()) { okay_ = false; return; } out_.nodes[parent].children.push_back(value); }
    u32 transfer(u32 from, u32 target, ControlFlowAstKind kind) { auto id = node(kind); if (id != kNoAstNode) { out_.nodes[id].from = from; out_.nodes[id].target = target; } return id; }
    bool validate();
    bool loops();
    Region collect(u32 start, u32 join, const Region& allowed, u32 activeLoop);
    bool singleEntry(const Region& region, u32 branch);
    u32 join(u32 block) const { if (block + 1 >= post_.immediate.size()) return kNoBlock; const auto value = post_.immediate[block + 1]; return value == 0 || value == kNoBlock ? kNoBlock : value - 1; }
    u32 region(u32 start, u32 stop, const Region& allowed, u32 activeLoop, unsigned depth);
    u32 arm(u32 from, u32 target, u32 stop, const Region& body, const Region& allowed, u32 activeLoop, unsigned depth);
    void fallback(const std::string& reason);
    void block(u32 parent, u32 index);
    const SsaInsn* terminator(u32 id) const { const auto& b = f_.blocks[id]; return b.insnCount ? &f_.insns[b.firstInsn + b.insnCount - 1] : nullptr; }
    const SsaFunction& f_; ControlFlowAst& out_; Graph graph_, preds_; Dom dom_, post_;
    std::map<u32, Loop> loops_; u64 work_ = 0; bool okay_ = true;
};
bool Builder::validate() {
    graph_.resize(f_.blocks.size()); preds_.resize(f_.blocks.size());
    size_t edges = 0; std::vector<bool> owned(f_.insns.size(), false);
    for (u32 i = 0; i < f_.blocks.size(); ++i) {
        const auto& b = f_.blocks[i];
        if (b.id != i || b.firstInsn > f_.insns.size() || b.insnCount > f_.insns.size() - b.firstInsn) return false;
        std::set<u32> seen;
        for (auto next : b.successors) { if (next >= f_.blocks.size() || !seen.insert(next).second || ++edges > kMaxEdges) return false; graph_[i].push_back(next); preds_[next].push_back(i); }
        for (u32 at = b.firstInsn; at < b.firstInsn + b.insnCount; ++at) { if (owned[at] || (at + 1 < b.firstInsn + b.insnCount && isTerminator(f_.insns[at].op))) return false; owned[at] = true; }
        const auto* term = terminator(i);
        if (term && (term->op == MintOp::kCondBranch || term->op == MintOp::kBranchInd) && (term->use[0] == kNoValue || term->use[0] >= f_.values.size())) return false;
        if (term && term->op == MintOp::kReturn && !b.successors.empty()) return false;
    }
    return std::find(owned.begin(), owned.end(), false) == owned.end();
}
bool Builder::loops() {
    Graph forward = graph_; std::vector<u32> indegree(graph_.size()); size_t reachable = 0;
    for (u32 from = 0; from < graph_.size(); ++from) if (dom_.reachable[from]) {
        ++reachable; forward[from].clear();
        for (auto target : graph_[from]) {
            if (!dom_.dominates(target, from)) { forward[from].push_back(target); ++indegree[target]; continue; }
            auto& loop = loops_[target]; loop.header = target; loop.body.insert(target); loop.latches.push_back(from);
            std::vector<u32> pending{from}; loop.body.insert(from);
            while (!pending.empty()) { auto current = pending.back(); pending.pop_back(); if (current == target) continue; for (auto pred : preds_[current]) { if (++work_ > kMaxWork || !dom_.dominates(target, pred)) return false; if (loop.body.insert(pred).second) pending.push_back(pred); } }
        }
    }
    std::vector<u32> ready; for (u32 i = 0; i < graph_.size(); ++i) if (dom_.reachable[i] && !indegree[i]) ready.push_back(i);
    size_t count = 0; while (!ready.empty()) { auto current = ready.back(); ready.pop_back(); ++count; for (auto next : forward[current]) if (!--indegree[next]) ready.push_back(next); }
    if (count != reachable) return false; // Remaining cycle has no dominating header.
    size_t members = 0;
    for (auto& pair : loops_) {
        auto& loop = pair.second; Region exits; members += loop.body.size(); if (members > 1000000) return false;
        for (auto member : loop.body) {
            for (auto pred : preds_[member]) if (dom_.reachable[pred] && member != loop.header && !loop.body.count(pred)) return false;
            for (auto next : graph_[member]) if (!loop.body.count(next)) exits.insert(next);
        }
        if (exits.size() > 1) return false; if (!exits.empty()) loop.exit = *exits.begin();
    }
    for (auto left = loops_.begin(); left != loops_.end(); ++left) for (auto right = std::next(left); right != loops_.end(); ++right) {
        bool overlap = false; for (auto member : left->second.body) { if (++work_ > kMaxWork) return false; if (right->second.body.count(member)) { overlap = true; break; } }
        if (overlap && !std::includes(left->second.body.begin(), left->second.body.end(), right->second.body.begin(), right->second.body.end()) &&
            !std::includes(right->second.body.begin(), right->second.body.end(), left->second.body.begin(), left->second.body.end())) return false;
    }
    return true;
}
Region Builder::collect(u32 start, u32 stop, const Region& allowed, u32 activeLoop) {
    Region result; std::vector<u32> pending{start};
    while (!pending.empty() && okay_) {
        auto current = pending.back(); pending.pop_back(); if (++work_ > kMaxWork) { okay_ = false; break; }
        if (current == stop || current == activeLoop) continue;
        if (!allowed.count(current)) { if (activeLoop == kNoBlock || current != loops_.at(activeLoop).exit) okay_ = false; continue; }
        if (!result.insert(current).second) continue;
        for (auto next : graph_[current]) pending.push_back(next);
    }
    return result;
}
bool Builder::singleEntry(const Region& body, u32 branch) {
    for (auto block : body) {
        if (!dom_.dominates(branch, block)) return false;
        for (auto pred : preds_[block]) { if (++work_ > kMaxWork) return false; if (dom_.reachable[pred] && pred != branch && !body.count(pred)) return false; }
    }
    return true;
}
void Builder::block(u32 parent, u32 index) {
    if (out_.blockOwner[index] != kNoAstNode) { okay_ = false; return; }
    auto id = node(ControlFlowAstKind::kBlock); if (id == kNoAstNode) return; out_.nodes[id].block = index; out_.blockOwner[index] = id; child(parent, id);
}
u32 Builder::arm(u32 from, u32 target, u32 stop, const Region& body, const Region& allowed, u32 activeLoop, unsigned depth) {
    const auto result = sequence(); child(result, transfer(from, target, ControlFlowAstKind::kEdge));
    if (target == activeLoop) child(result, transfer(from, target, ControlFlowAstKind::kContinue));
    else if (!allowed.count(target)) {
        if (activeLoop != kNoBlock && target == loops_.at(activeLoop).exit) child(result, transfer(from, target, ControlFlowAstKind::kBreak)); else okay_ = false;
    } else if (target != stop) child(result, region(target, stop, body, activeLoop, depth + 1));
    return result;
}
u32 Builder::region(u32 start, u32 stop, const Region& allowed, u32 activeLoop, unsigned depth) {
    const auto result = sequence(); if (depth > 64) { okay_ = false; return result; }
    for (u32 current = start; current != stop && current != kNoBlock && okay_;) {
        if (++work_ > kMaxWork || !allowed.count(current)) { okay_ = false; break; }
        auto natural = loops_.find(current);
        if (natural != loops_.end() && current != activeLoop) {
            const auto& loop = natural->second;
            if (!std::includes(allowed.begin(), allowed.end(), loop.body.begin(), loop.body.end())) { okay_ = false; break; }
            auto id = node(ControlFlowAstKind::kLoop); if (id == kNoAstNode) break; out_.nodes[id].block = current; out_.nodes[id].target = loop.exit; out_.nodes[id].loopBlocks.assign(loop.body.begin(), loop.body.end()); out_.nodes[id].latches = loop.latches;
            const auto* header = terminator(current);
            if (loop.latches.size() == 1 && loop.latches.front() != current && (!header || header->op != MintOp::kCondBranch)) { const auto* latch = terminator(loop.latches.front()); out_.nodes[id].postTest = latch && latch->op == MintOp::kCondBranch; }
            const auto inner = region(current, kNoBlock, loop.body, current, depth + 1); child(id, inner); child(result, id); ++out_.loopCount;
            current = loop.exit; continue;
        }
        block(result, current); if (!okay_) break;
        const auto& next = graph_[current]; const auto* term = terminator(current);
        const bool conditional = term && term->op == MintOp::kCondBranch;
        const bool indirect = term && term->op == MintOp::kBranchInd;
        if (conditional || (indirect && !next.empty())) {
            if ((conditional && next.size() != 2) || (indirect && next.size() > 256)) { okay_ = false; break; }
            const auto finish = join(current); std::vector<Region> arms;
            Region combined; bool valid = true;
            for (auto target : next) { auto body = collect(target, finish, allowed, activeLoop); if (!singleEntry(body, current)) valid = false; for (auto member : body) if (!combined.insert(member).second) valid = false; arms.push_back(std::move(body)); }
            if (!valid || !okay_) { okay_ = false; break; }
            const auto id = node(conditional ? ControlFlowAstKind::kIf : ControlFlowAstKind::kSwitch); if (id == kNoAstNode) break;
            out_.nodes[id].block = current; out_.nodes[id].condition = {current, term->use[0], false};
            for (size_t i = 0; i < next.size(); ++i) {
                const auto body = arm(current, next[i], finish, arms[i], allowed, activeLoop, depth);
                if (conditional) child(id, body);
                else { const auto address = f_.blocks[next[i]].start; for (const auto& existing : out_.nodes[id].arms) if (existing.targetAddress == address) okay_ = false; out_.nodes[id].arms.push_back({address, next[i], body}); }
            }
            child(result, id); if (conditional) ++out_.ifCount; else ++out_.switchCount;
            if (finish == activeLoop || finish == kNoBlock || !allowed.count(finish)) current = kNoBlock; else current = finish;
            continue;
        }
        if (next.empty()) { if (!term || term->op != MintOp::kReturn) child(result, transfer(current, kNoBlock, ControlFlowAstKind::kGoto)); break; }
        if (next.size() != 1 || (term && term->op == MintOp::kReturn)) { okay_ = false; break; }
        const auto target = next.front(); child(result, transfer(current, target, ControlFlowAstKind::kEdge));
        if (target == activeLoop) { child(result, transfer(current, target, ControlFlowAstKind::kContinue)); break; }
        if (target == stop) break;
        if (!allowed.count(target)) { if (activeLoop != kNoBlock && target == loops_.at(activeLoop).exit) child(result, transfer(current, target, ControlFlowAstKind::kBreak)); else okay_ = false; break; }
        current = target;
    }
    return result;
}
void Builder::fallback(const std::string& reason) {
    out_ = {}; out_.diagnostics.push_back(reason); out_.blockOwner.assign(f_.blocks.size(), kNoAstNode); okay_ = true;
    out_.root = node(ControlFlowAstKind::kFallback);
    for (u32 index = 0; index < f_.blocks.size(); ++index) {
        block(out_.root, index); const auto& next = graph_[index]; const auto* term = terminator(index);
        if (term && term->op == MintOp::kReturn) continue;
        if (term && term->op == MintOp::kCondBranch) {
            const auto branch = node(ControlFlowAstKind::kIf); if (branch == kNoAstNode) break; out_.nodes[branch].block = index; out_.nodes[branch].condition = {index, term->use[0], false};
            for (size_t arm = 0; arm < 2; ++arm) { const auto body = sequence(); const auto target = arm < next.size() ? next[arm] : kNoBlock; if (target != kNoBlock) child(body, transfer(index, target, ControlFlowAstKind::kEdge)); child(body, transfer(index, target, ControlFlowAstKind::kGoto)); child(branch, body); }
            child(out_.root, branch);
        } else if (term && term->op == MintOp::kBranchInd && !next.empty()) {
            const auto branch = node(ControlFlowAstKind::kSwitch); if (branch == kNoAstNode) break; out_.nodes[branch].block = index; out_.nodes[branch].condition = {index, term->use[0], false};
            for (auto target : next) { const auto body = sequence(); child(body, transfer(index, target, ControlFlowAstKind::kEdge)); child(body, transfer(index, target, ControlFlowAstKind::kGoto)); out_.nodes[branch].arms.push_back({f_.blocks[target].start, target, body}); }
            child(out_.root, branch);
        } else { const auto target = next.empty() ? kNoBlock : next.front(); if (target != kNoBlock) child(out_.root, transfer(index, target, ControlFlowAstKind::kEdge)); child(out_.root, transfer(index, target, ControlFlowAstKind::kGoto)); }
    }
}
Status Builder::run() {
    if (f_.blocks.empty()) return bad("empty function"); if (f_.blocks.size() > kMaxBlocks || f_.insns.size() > 1000000) return large();
    if (!validate()) return bad("invalid block/instruction/edge ownership or control operand");
    if (!dominance(graph_, &dom_, &work_)) { fallback("Dominance work budget exceeded; original labelled control flow retained."); return okay_ ? Status::success() : large(); }
    Graph reverse(graph_.size() + 1);
    for (u32 from = 0; from < graph_.size(); ++from) { if (graph_[from].empty()) reverse[0].push_back(from + 1); for (auto target : graph_[from]) reverse[target + 1].push_back(from + 1); }
    if (!dominance(reverse, &post_, &work_) || !loops()) { fallback("Irreducible, overlapping, multi-exit or unproven loop region; original labelled control flow retained."); return okay_ ? Status::success() : large(); }
    Region allowed; for (u32 index = 0; index < graph_.size(); ++index) if (dom_.reachable[index]) allowed.insert(index);
    if (allowed.size() != graph_.size()) { fallback("Unreachable blocks retained in original labelled order; no speculative region ownership."); return okay_ ? Status::success() : large(); }
    out_.blockOwner.assign(f_.blocks.size(), kNoAstNode); out_.root = region(0, kNoBlock, allowed, kNoBlock, 0);
    if (!okay_ || std::find(out_.blockOwner.begin(), out_.blockOwner.end(), kNoAstNode) != out_.blockOwner.end()) fallback("Cross-region edges, shared arms, cyclic ownership or depth budget prevent safe AST structuring; original labelled control flow retained.");
    else out_.structured = true;
    return okay_ ? Status::success() : large();
}
bool validateAst(const ControlFlowAst& ast) {
    if (ast.root >= ast.nodes.size() || ast.nodes.size() > kMaxNodes || ast.blockOwner.size() > kMaxBlocks) return false;
    std::vector<u8> state(ast.nodes.size(), 0); std::vector<bool> blocks(ast.blockOwner.size(), false);
    std::vector<std::pair<u32, unsigned>> pending{{ast.root, 0}};
    while (!pending.empty()) {
        auto [id, depth] = pending.back(); pending.pop_back(); if (id >= ast.nodes.size() || depth > 256 || state[id]) return false; state[id] = 1;
        const auto& node = ast.nodes[id]; if (static_cast<unsigned>(node.kind) > static_cast<unsigned>(ControlFlowAstKind::kFallback)) return false;
        if (node.kind == ControlFlowAstKind::kBlock) { if (node.block >= blocks.size() || blocks[node.block] || ast.blockOwner[node.block] != id) return false; blocks[node.block] = true; }
        if (node.kind == ControlFlowAstKind::kIf && (node.children.size() != 2 || node.condition.block >= blocks.size())) return false;
        if (node.kind == ControlFlowAstKind::kLoop && (node.children.size() != 1 || node.block >= blocks.size())) return false;
        if (node.kind == ControlFlowAstKind::kEdge && (node.from >= blocks.size() || node.target >= blocks.size())) return false;
        if ((node.kind == ControlFlowAstKind::kGoto || node.kind == ControlFlowAstKind::kBreak || node.kind == ControlFlowAstKind::kContinue) && node.target != kNoBlock && node.target >= blocks.size()) return false;
        if (node.kind == ControlFlowAstKind::kSwitch) { if (node.condition.block >= blocks.size() || node.arms.size() > 256) return false; std::set<Address> targets; for (const auto& arm : node.arms) { if (arm.target >= blocks.size() || !targets.insert(arm.targetAddress).second) return false; pending.emplace_back(arm.body, depth + 1); } }
        for (auto child : node.children) pending.emplace_back(child, depth + 1);
    }
    return std::find(state.begin(), state.end(), 0) == state.end() && std::find(blocks.begin(), blocks.end(), false) == blocks.end();
}
}  // namespace
Status buildControlFlowAst(const SsaFunction& function, ControlFlowAst* out) {
    if (!out) return bad("null AST output"); ControlFlowAst candidate; auto status = Builder(function, &candidate).run();
    if (status.ok() && !validateAst(candidate)) return bad("internal AST ownership validation failed");
    if (status.ok()) {
        std::set<std::pair<u32, u32>> actual, emitted;
        for (const auto& block : function.blocks) for (auto target : block.successors) actual.emplace(block.id, target);
        for (const auto& node : candidate.nodes) if (node.kind == ControlFlowAstKind::kEdge && !emitted.emplace(node.from, node.target).second) return bad("AST duplicates an original edge");
        if (actual != emitted) return bad("AST does not preserve every original edge exactly once");
        *out = std::move(candidate);
    }
    return status;
}
Status emitControlFlowAst(const ControlFlowAst& ast, std::ostream& out, const ControlFlowAstCallbacks& cb) {
    if (!validateAst(ast) || !cb.block || !cb.edge || !cb.condition || !cb.indirectTarget || !cb.label) return bad("invalid AST/callbacks");
    std::function<void(u32, unsigned)> emit = [&](u32 id, unsigned depth) {
        const auto& node = ast.nodes[id]; const auto indent = std::string(depth * 4, ' ');
        const auto target = [&](u32 block) { return block == kNoBlock ? std::string("unresolved_indirect") : cb.label(block); };
        switch (node.kind) {
            case ControlFlowAstKind::kSequence: case ControlFlowAstKind::kFallback: for (auto child : node.children) emit(child, depth); break;
            case ControlFlowAstKind::kBlock: out << '\n' << cb.label(node.block) << ":;\n"; cb.block(node.block); break;
            case ControlFlowAstKind::kEdge: cb.edge(node.from, node.target); break;
            case ControlFlowAstKind::kIf: out << indent << "if (" << (node.condition.negated ? "!(" : "") << cb.condition(node.condition.block) << (node.condition.negated ? ")" : "") << ") {\n"; emit(node.children[0], depth + 1); out << indent << "} else {\n"; emit(node.children[1], depth + 1); out << indent << "}\n"; break;
            case ControlFlowAstKind::kLoop: out << indent << (node.postTest ? "do {\n" : "while (true) {\n"); emit(node.children[0], depth + 1); out << indent << (node.postTest ? "} while (true);\n" : "}\n"); break;
            case ControlFlowAstKind::kSwitch:
                out << indent << "switch ((uintptr_t)(" << cb.indirectTarget(node.condition.block) << ")) { /* computed target addresses */\n";
                for (const auto& arm : node.arms) { out << indent << "case 0x" << std::hex << arm.targetAddress << std::dec << "ULL: {\n"; emit(arm.body, depth + 1); out << indent << "    break;\n" << indent << "}\n"; }
                out << indent << "default: goto unresolved_indirect;\n" << indent << "}\n"; break;
            case ControlFlowAstKind::kContinue: out << indent << "continue;\n"; break;
            case ControlFlowAstKind::kBreak: case ControlFlowAstKind::kGoto: out << indent << "goto " << target(node.target) << ";\n"; break;
        }
    };
    if (!ast.structured) out << "    /* AST fallback: original labelled CFG; no unproven nesting. */\n";
    emit(ast.root, 1); return Status::success();
}
std::string controlFlowAstText(const ControlFlowAst& ast) {
    const char* names[] = {"sequence", "block", "if", "loop", "switch-target", "edge", "break", "continue", "goto", "fallback"};
    std::ostringstream out; out << "control-flow AST " << (ast.structured ? "structured" : "fallback") << ": " << ast.ifCount << " if, " << ast.loopCount << " loop, " << ast.switchCount << " switch\n";
    for (size_t id = 0; id < ast.nodes.size(); ++id) { const auto& node = ast.nodes[id]; const auto kind = static_cast<unsigned>(node.kind); out << id << ' ' << (kind < 10 ? names[kind] : "invalid"); if (node.block != kNoBlock) out << " block=" << node.block; if (node.from != kNoBlock) out << " from=" << node.from; if (node.target != kNoBlock) out << " target=" << node.target; for (auto child : node.children) out << " child=" << child; for (const auto& arm : node.arms) out << " case=0x" << std::hex << arm.targetAddress << std::dec << "->" << arm.body; out << '\n'; }
    for (const auto& diagnostic : ast.diagnostics) out << "note: " << diagnostic << '\n'; return out.str();
}
}  // namespace mint
