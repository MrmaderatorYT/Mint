#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>
#include <unistd.h>

#include "mint/session.h"
#include "mint/version/version_tracking.h"

using namespace mint;
namespace {
size_t checks = 0;
void require(bool good, const char* message) {
    ++checks;
    if (!good) { std::fprintf(stderr, "version tracking: %s\n", message); std::exit(1); }
}
void success(const Status& status, const char* message) {
    if (!status.ok()) std::fprintf(stderr, "%s\n", status.toString().c_str());
    require(status.ok(), message);
}
struct Files {
    std::vector<std::string> paths;
    ~Files() { for (const auto& path : paths) { ::unlink(path.c_str()); ::unlink((path + ".analysis").c_str()); } }
    std::string make(const std::vector<u8>& bytes, bool absent = false) {
        std::string path = "/private/tmp/mint-version-test-XXXXXX";
        const int fd = ::mkstemp(path.data()); require(fd >= 0, "create unique temporary file"); paths.push_back(path);
        size_t at = 0;
        while (at < bytes.size()) {
            const ssize_t count = ::write(fd, bytes.data() + at, bytes.size() - at);
            if (count < 0 && errno == EINTR) continue;
            require(count > 0, "write fixture"); at += static_cast<size_t>(count);
        }
        require(::close(fd) == 0, "close fixture");
        if (absent) require(::unlink(path.c_str()) == 0, "reserve fresh destination");
        return path;
    }
};
std::vector<u8> contents(const std::string& path) {
    std::ifstream input(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}
std::vector<u8> fixture(Arch arch, unsigned first, unsigned second) {
    std::vector<u8> bytes(40, 0);
    for (unsigned index = 0; index < 2; ++index) {
        const unsigned value = index ? second : first, at = index * 16;
        if (arch == Arch::kAArch64) {
            const u32 mov = 0xd2800000u | (value << 5), ret = 0xd65f03c0;
            for (unsigned i = 0; i < 4; ++i) { bytes[at+i] = static_cast<u8>(mov >> (i*8)); bytes[at+4+i] = static_cast<u8>(ret >> (i*8)); }
        } else { bytes[at] = 0xb8; bytes[at+1] = static_cast<u8>(value); bytes[at+5] = 0xc3; }
    }
    return bytes;
}
void open(Session* session, Files* files, Arch arch, Address base, unsigned first, unsigned second) {
    success(session->openRawPath(files->make(fixture(arch, first, second)), arch, base, base), "open native fixture");
    success(session->attachProject(files->make({}, true)), "attach new project");
    success(session->analyze(), "analyze fixture");
    success(session->editAnnotation(base+16, "function", "code"), "create authoritative second function");
    require(session->analyzer().functions().size() == 2, "two function roots");
}
void tests(Arch arch) {
    Files files; Session source, target, changed, duplicatesLeft, duplicatesRight;
    open(&source, &files, arch, 0x1000, 7, 11); open(&target, &files, arch, 0x2000, 7, 11);
    open(&changed, &files, arch, 0x3000, 9, 11);
    success(source.editAnnotation(0x1000,"name","original_name"), "source user name");
    success(target.editAnnotation(0x2000,"name","target_keeps_name"), "target name has precedence");
    BinaryDiff diff;
    success(compareBinaries(source,target,&diff), "compare shifted functions");
    require(diff.matches.size()==2 && diff.ambiguous.empty(), "shifted and renamed functions match by code");
    for(const auto& pair:diff.matches) require(pair.target-pair.source==0x1000 && pair.kind!=FunctionMatchKind::kSymbolChanged, "content match preserves identity despite user rename");
    success(compareBinaries(source,changed,&diff), "compare differing constants");
    require(diff.matches.size()==1 && diff.matches[0].source==0x1010 && diff.unmatchedSource.size()==1, "different scalar constants are not normalized away");
    open(&duplicatesLeft,&files,arch,0x4000,7,7); open(&duplicatesRight,&files,arch,0x5000,7,7);
    success(compareBinaries(duplicatesLeft,duplicatesRight,&diff), "compare duplicate bodies");
    require(diff.matches.empty() && !diff.ambiguous.empty() && diff.unmatchedSource.size()==2, "duplicate body ambiguity is explicit, never arbitrary");

    success(source.editAnnotation(0x1000,"comment","function comment"), "source comment");
    success(source.editAnnotation(0x1001,"bookmark","inside instruction"), "source instruction-byte bookmark");
    success(source.editAnnotation(0x1010,"prototype","uint64_t(void)"), "source prototype");
    success(source.editAnnotation(0x1024,"comment","unowned raw data"), "source unowned annotation");
    TrackingState state;
    success(confirmFunctionMatch(source,target,0x1000,0x2000,&state), "manually confirm first match");
    success(confirmFunctionMatch(source,target,0x1010,0x2010,&state), "manually confirm second match");
    const auto savedCount = state.confirmed.size();
    require(!confirmFunctionMatch(source,target,0x1000,0x2010,&state).ok() && state.confirmed.size()==savedCount, "one-to-one confirmation rejects conflict atomically");
    require(!confirmFunctionMatch(source,target,0x1001,0x2000,&state).ok(), "nonentry manual match rejected");
    const auto tracking = files.make({},true);
    success(saveTracking(source,target,state,tracking), "persist confirmed tracking state");
    TrackingState restored;
    success(loadTracking(source,target,tracking,&restored), "load pinned tracking state");
    require(restored.confirmed.size()==2 && restored.sourceIdentity==state.sourceIdentity, "portable roundtrip");
    const auto bytes=contents(tracking);
    require(!saveTracking(source,target,state,tracking).ok() && contents(tracking)==bytes, "existing tracking file never overwritten");
    const auto input = files.make(fixture(arch,7,11)); const auto inputBytes=contents(input);
    require(!saveTracking(source,target,state,input).ok() && contents(input)==inputBytes, "source bytes cannot be overwritten");
    auto corrupt=bytes; corrupt.back()^=1;
    require(!loadTracking(source,target,files.make(corrupt),&restored).ok() && restored.confirmed.size()==2, "checksum rejects corruption without replacing output");
    for(size_t size : {size_t(0),size_t(23),bytes.size()-1}) {
        require(!loadTracking(source,target,files.make(std::vector<u8>(bytes.begin(),bytes.begin()+size)),&restored).ok(), "truncated state rejected");
    }
    require(!loadTracking(source,changed,tracking,&restored).ok(), "other target/configuration rejected");

    TransferPlan plan;
    success(planAnnotationTransfer(source,target,state,&plan), "plan explicitly confirmed annotation transfer");
    require(plan.edits.size()==3 && plan.skipped.size()==2, "only mapped nonconflicting comment/bookmark/prototype transferred");
    auto forged=plan; forged.edits[0].target=0x2024; TransferResult result;
    require(!applyAnnotationTransfer(source,&target,forged,&result).ok() && target.annotation(0x2000,"comment").empty(), "crafted transfer cannot escape confirmed instruction mapping");
    auto duplicate=plan; duplicate.edits.push_back(duplicate.edits.front());
    require(!applyAnnotationTransfer(source,&target,duplicate,&result).ok(), "duplicate transfer rejected before mutation");
    success(applyAnnotationTransfer(source,&target,plan,&result), "apply confirmed transfer");
    require(result.applied==3 && target.annotation(0x2000,"name")=="target_keeps_name" && target.annotation(0x2000,"comment")=="function comment" && target.annotation(0x2001,"bookmark")=="inside instruction" && target.annotation(0x2010,"prototype")=="uint64_t(void)", "annotations remap and target name survives");
    require(target.annotation(0x2024,"comment").empty() && target.annotation(0x2000,"patch").empty(), "gaps and patches not transferred");
    require(!validateTracking(source,target,state).ok(), "prototype configuration change invalidates old pins");
    require(binaryDiffText(diff).find("ambiguity")!=std::string::npos && trackingText(state).find("manual")!=std::string::npos && transferPlanText(plan).find("Patches/types")!=std::string::npos, "usable reports explain confidence and exclusions");

    Session stale; open(&stale,&files,arch,0x6000,7,11); TrackingState staleState;
    success(confirmFunctionMatch(source,stale,0x1000,0x6000,&staleState), "confirm stale-plan fixture");
    success(planAnnotationTransfer(source,stale,staleState,&plan), "prepare plan before target edit");
    success(stale.editAnnotation(0x6000,"comment","later target edit"), "target edits after planning");
    require(!applyAnnotationTransfer(source,&stale,plan,&result).ok() && stale.annotation(0x6000,"comment")=="later target edit", "target changes are preserved and stale plan rejected atomically");
}
void insertedInstructions(){
    Files files;Session source,target;const std::vector<u8> a={0xb8,7,0,0,0,0xc3},b={0x90,0xb8,7,0,0,0,0xc3};
    success(source.openRawPath(files.make(a),Arch::kX86_64,0x1000,0x1000),"open correspondence source");success(source.attachProject(files.make({},true)),"attach correspondence source project");success(source.analyze(),"analyze correspondence source");
    success(target.openRawPath(files.make(b),Arch::kX86_64,0x2000,0x2000),"open inserted instruction target");success(target.attachProject(files.make({},true)),"attach correspondence target project");success(target.analyze(),"analyze inserted instruction target");
    std::vector<InstructionCorrespondence> pairs;success(correspondInstructions(source,target,0x1000,0x2000,&pairs),"decode instruction correspondence");
    require(pairs.size()==2&&pairs[0].source==0x1000&&pairs[0].target==0x2001&&pairs[1].target==0x2006,"inserted nop preserves exact semantic instruction anchors");
    success(source.editAnnotation(0x1001,"comment","immediate byte"),"comment inside moved instruction");TrackingState tracking;success(confirmFunctionMatch(source,target,0x1000,0x2000,&tracking),"authorize inserted function pair");TransferPlan plan;success(planAnnotationTransfer(source,target,tracking,&plan),"plan inserted instruction transfer");require(plan.edits.size()==1&&plan.edits[0].target==0x2002,"inside-instruction annotation follows exact instruction not old offset");
    TransferResult result;success(applyAnnotationTransfer(source,&target,plan,&result),"apply inserted instruction transfer");require(target.annotation(0x2002,"comment")=="immediate byte"&&target.annotation(0x2001,"comment").empty(),"moved annotation uses width-correct byte offset");
}
void movedBlocks(){
    Files files;Session source,target,changed;
    const std::vector<u8> a={0xb8,0,0,0,0,0x85,0xc0,0x74,6,0xb8,11,0,0,0,0xc3,0xb8,7,0,0,0,0xc3};
    std::vector<u8> b(31,0);const std::vector<u8> taken={0xb8,7,0,0,0,0xc3},entry={0xb8,0,0,0,0,0x85,0xc0,0x74,0xe7,0xb8,11,0,0,0,0xc3};std::copy(taken.begin(),taken.end(),b.begin());std::copy(entry.begin(),entry.end(),b.begin()+16);
    success(source.openRawPath(files.make(a),Arch::kX86_64,0x1000,0x1000),"open moved-CFG source");success(source.attachProject(files.make({},true)),"attach moved-CFG source");success(source.analyze(),"analyze moved-CFG source");
    success(target.openRawPath(files.make(b),Arch::kX86_64,0x2000,0x2010),"open block-reordered target");success(target.attachProject(files.make({},true)),"attach block-reordered target");success(target.analyze(),"analyze block-reordered target");
    std::vector<InstructionCorrespondence> pairs;success(correspondInstructions(source,target,0x1000,0x2010,&pairs),"correspond actual reordered CFG");
    require(pairs.size()==7,"all exact instructions survive physical basic-block permutation");
    bool takenMapped=false,branchMapped=false;for(const auto& pair:pairs){if(pair.source==0x100f&&pair.target==0x2000)takenMapped=true;if(pair.source==0x1007&&pair.target==0x2017)branchMapped=true;}require(takenMapped&&branchMapped,"direct branch remains authorized only when its relocated target maps exactly");
    success(source.editAnnotation(0x1010,"comment","taken immediate"),"annotate moved basic block");TrackingState state;success(confirmFunctionMatch(source,target,0x1000,0x2010,&state),"confirm reordered function pair");TransferPlan plan;success(planAnnotationTransfer(source,target,state,&plan),"plan reordered-block annotation transfer");require(plan.edits.size()==1&&plan.edits[0].target==0x2001,"annotation follows reordered block rather than instruction ordinal");
    auto altered=b;altered[1]=9;success(changed.openRawPath(files.make(altered),Arch::kX86_64,0x2000,0x2010),"open changed-block target");success(changed.analyze(),"analyze changed-block target");success(correspondInstructions(source,changed,0x1000,0x2010,&pairs),"derive partial changed-CFG correspondence");
    bool changedTakenMapped=false,changedBranchMapped=false;for(const auto& pair:pairs){if(pair.source==0x100f)changedTakenMapped=true;if(pair.source==0x1007)changedBranchMapped=true;}require(!changedTakenMapped&&!changedBranchMapped,"changed arithmetic block and branch-to-unproven target remain untransferable");
}
} // namespace
int main() { tests(Arch::kAArch64); tests(Arch::kX86_64);insertedInstructions();movedBlocks(); std::printf("version tracking: %zu checks passed\n",checks); return 0; }
