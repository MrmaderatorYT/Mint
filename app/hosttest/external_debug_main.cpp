#include "mint/session.h"
#include "mint/base/sha256.h"
#include <algorithm>
#include <cstring>
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
    require(!report.sources.empty(),"split import retains skeleton source rows");
    const auto* splitEntry=splitImage.findSymbol("mint_debug_entry");
    require(splitEntry && std::any_of(report.functions.begin(),report.functions.end(),[&](const auto& fn){return fn.name=="mint_debug_entry"&&fn.entry==splitEntry->value&&!fn.prototype.empty();}),"split indexed strings/addresses retain exact function identity and prototype");
    require(std::any_of(report.sources.begin(),report.sources.end(),[&](const auto& row){return !row.endSequence&&row.line&&row.address>=splitEntry->value&&row.file.find("dwarf_fixture.c")!=std::string::npos;}),"split source mapping uses linked skeleton addresses");
    const auto* splitInfo=dwoImage.findSection(".debug_info.dwo");require(splitInfo,"DWO info section exists");
    u32 length=0;u16 version=0;require(splitInfo->data.read(0,&length),"DWO header length");
    const size_t prefix=length==0xffffffffu?12:4,offsetWidth=length==0xffffffffu?8:4;
    require(splitInfo->data.read(prefix,&version),"DWO header version");
    require(report.byteOrder==image.memory().byteOrder()&&report.versions==std::vector<u16>{version}&&report.offsetSizes==std::vector<u8>{u8(offsetWidth)},"split report exposes actual version, offset format and byte order");
    const auto* splitGlobal=splitImage.findSymbol("mint_debug_global");require(splitGlobal,"split global symbol");
    require(std::any_of(report.variables.begin(),report.variables.end(),[&](const auto& var){return var.name=="mint_debug_global"&&var.location.kind==DwarfLocation::Kind::kAddress&&var.location.address==splitGlobal->value;}),"GNU/standard indexed global location resolves exact linked address");
    require(std::any_of(report.variables.begin(),report.variables.end(),[&](const auto& var){return var.parameter&&var.name=="value"&&var.scope==splitEntry->value&&!var.locations.empty()&&var.locations.front().range.low==splitEntry->value;}),"optimized split parameter has resolved location-list ranges");
    // Locate the emitted ID in its bounded info section, independently of the
    // v4 GNU attribute layout or v5 fixed header, then prove rejection by ID.
    require(report.splitIds.size()==1,"one split CU identity");
    u8 encodedId[8];for(unsigned i=0;i<8;++i)encodedId[i]=u8(report.splitIds[0]>>((dwoImage.memory().byteOrder()==ByteOrder::kBig?7-i:i)*8));
    size_t identityOffset=0,matches=0;
    for(size_t at=0;splitInfo->data.covers(at,8);++at)if(std::memcmp(splitInfo->data.data()+at,encodedId,8)==0){identityOffset=splitInfo->fileOffset+at;++matches;}
    require(matches==1,"unique split identity payload");
    std::vector<u8> changed(dwoFile.view().data(),dwoFile.view().data()+dwoFile.view().size());
    changed[identityOffset]^=1;ElfImage mismatch;okay(mismatch.loadDebugObject({changed.data(),changed.size()}),"modified split ID fixture loads");
    DwarfReport sentinel;sentinel.units=99;const auto rejected=readDwarf(splitImage,mismatch,&sentinel,true);
    require(!rejected.ok()&&rejected.message().find("identity")!=std::string::npos&&sentinel.units==99,"split-ID mismatch never bypassed by unverified acknowledgement");
    const auto* strings=debugImage.findSection(".debug_str");require(strings&&!strings->data.empty(),"external strings fixture");
    std::vector<u8> badCrc(external.view().data(),external.view().data()+external.view().size());badCrc[strings->fileOffset]^=1;
    ElfImage crcImage;okay(crcImage.loadDebugObject({badCrc.data(),badCrc.size()}),"CRC mismatch remains a loadable ELF");
    sentinel={};sentinel.units=99;const auto crcStatus=readDwarf(image,crcImage,&sentinel,true);
    require(!crcStatus.ok()&&crcStatus.message().find("CRC")!=std::string::npos&&sentinel.units==99,"actual CRC mismatch cannot be acknowledged away");
    if(debugImage.findSection(".note.gnu.build-id")) {
        okay(readDwarf(packedImage,debugImage,&report),"big-endian build-ID identity without a debuglink");
        require(dwarfReportText(report).find("ELF build-ID")!=std::string::npos,"build-ID verification provenance reported");
        const auto* note=debugImage.findSection(".note.gnu.build-id");
        u32 names=0;require(note->data.read(0,&names),"build-ID note name size");
        const auto descriptor=note->fileOffset+12+((u64(names)+3)&~u64{3});
        std::vector<u8> wrongId(external.view().data(),external.view().data()+external.view().size());require(descriptor<wrongId.size(),"build-ID descriptor extent");wrongId[descriptor]^=1;
        ElfImage foreignId;okay(foreignId.loadDebugObject({wrongId.data(),wrongId.size()}),"foreign build-ID fixture");
        sentinel={};sentinel.units=99;require(!readDwarf(packedImage,foreignId,&sentinel,true).ok()&&sentinel.units==99,"actual build-ID mismatch cannot be acknowledged away");
    } else {
        require(!readDwarf(debugImage, debugImage, &report).ok(), "absent identity requires acknowledgement");
        okay(readDwarf(debugImage, debugImage, &report, true), "explicit unverified object"); require(report.partial, "unverified provenance retained");
    }
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
