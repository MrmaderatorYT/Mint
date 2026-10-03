#include "mint/session.h"
#include "mint/base/sha256.h"
#include <fcntl.h>
#include <unistd.h>
#include <cstdlib>
#include <iostream>

using namespace mint;
namespace {
size_t checks = 0;
void require(bool valid, const std::string& message) { ++checks; if (!valid) { std::cerr << "External DWARF: " << message << '\n'; std::exit(1); } }
void okay(const Status& status, const std::string& message) { require(status.ok(), message + ": " + status.toString()); }
ByteView textView(const std::string& text) { return ByteView(reinterpret_cast<const u8*>(text.data()), text.size()); }
void digests() {
    require(sha256({}) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "SHA256 empty vector");
    require(sha256(textView("abc")) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "SHA256 abc vector");
    require(sha256(textView(std::string(1000000, 'a'))) == "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0", "SHA256 multi-block vector");
}
void real(const char* input, const char* debug, const char* compressed, const char* skeleton, const char* dwo) {
    MappedFile primary, external, packed, splitFile, dwoFile;
    okay(primary.open(input), "stripped fixture"); okay(external.open(debug), "external fixture"); okay(packed.open(compressed), "compressed fixture");
    okay(splitFile.open(skeleton), "split skeleton fixture"); okay(dwoFile.open(dwo), "split object fixture");
    ElfImage image, debugImage, packedImage, splitImage, dwoImage;
    okay(image.load(primary.view()), "stripped image"); okay(debugImage.loadDebugObject(external.view()), "debug-only image"); okay(packedImage.load(packed.view()), "compressed image");
    okay(splitImage.load(splitFile.view()), "split skeleton image"); okay(dwoImage.loadDebugObject(dwoFile.view()), "DWO debug-only ELF without PT_LOAD");
    DwarfReport report;
    okay(readDwarf(image, debugImage, &report), "GNU debuglink association"); require(!report.functions.empty() && !report.types.empty(), "external functions/types available");
    okay(readDwarf(packedImage, &report), "compressed section decompression"); require(!report.types.empty() && !report.sources.empty(), "compressed types/source decoded");
    okay(readDwarf(splitImage, dwoImage, &report), "split unit identity association"); require(!report.functions.empty() && !report.types.empty(), "split functions/types decoded");
    require(!readDwarf(debugImage, debugImage, &report).ok(), "absent identity requires acknowledgement");
    okay(readDwarf(debugImage, debugImage, &report, true), "explicit unverified object"); require(report.partial, "unverified provenance retained");
    std::string project = "/private/tmp/mint-external-debug-XXXXXX"; const int fd = mkstemp(project.data()); require(fd >= 0, "owned project temporary"); close(fd); unlink(project.c_str());
    Session session; okay(session.openPath(input), "Session input"); okay(session.attachProject(project), "persistent project"); okay(session.analyze(), "initial analysis");
    okay(session.importExternalDebug(debug), "external metadata adopted and persisted");
    const auto* entry = session.image().findSymbol("mint_debug_entry"); const auto* global = session.image().findSymbol("mint_debug_global");
    require(entry && global, "external fixture linkage"); const Address address = entry->value, globalAddress = global->value;
    okay(session.editAnnotation(address, "comment", "external debug survives"), "persistent comment");
    okay(session.editAnnotation(globalAddress, "data", "MintNode"), "persistent annotation depending on external imported type");
    const std::string digest = session.externalDebugDigest(); require(digest.size() == 64 && session.typesText().find("MintNode") != std::string::npos, "external Program baseline/digest");
    Session reopened; okay(reopened.openPath(input), "reopen input"); okay(reopened.attachProject(project), "external debug restored before Program validation"); okay(reopened.analyze(), "reopen analysis");
    require(reopened.externalDebugDigest() == digest && reopened.annotation(address, "comment") == "external debug survives" && reopened.annotation(globalAddress, "data") == "MintNode", "external-dependent edits survive");
    const std::string content = project + ".debug." + digest + ".bin";
    int corrupt = open(content.c_str(), O_WRONLY | O_CLOEXEC); require(corrupt >= 0, "owned sidecar tamper handle"); u8 byte = 0;
    require(pwrite(corrupt, &byte, 1, 0) == 1, "sidecar tamper"); close(corrupt);
    const auto oldReport = reopened.debugInfoText();
    require(!reopened.attachProject(project).ok() && reopened.annotation(address, "comment") == "external debug survives" && reopened.debugInfoText() == oldReport, "tamper refuses reopen without clobbering live user/report state");
    Session damaged; okay(damaged.openPath(input), "damaged project input"); require(!damaged.attachProject(project).ok(), "cold reopen also refuses tampered sidecar");
    // A foreign binary with same target ISA cannot inherit the source binding.
    Session foreign; okay(foreign.openPath(compressed), "foreign source input"); require(!foreign.attachProject(project).ok(), "source SHA binding rejects another binary");
    unlink(content.c_str()); unlink((project + ".debug").c_str()); unlink((project + ".analysis").c_str()); unlink(project.c_str());
}
}
int main(int argc, char** argv) {
    digests(); require(argc == 1 || argc == 6, "usage: external_debug_test [stripped debug compressed skeleton dwo]");
    if (argc == 6) real(argv[1], argv[2], argv[3], argv[4], argv[5]);
    std::cout << "External DWARF: " << checks << " checks passed\n";
}
