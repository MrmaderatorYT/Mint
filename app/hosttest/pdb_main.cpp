#include "mint/debug/pdb_reader.h"
#include "mint/session.h"
#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <unistd.h>

using namespace mint;
namespace {
size_t checks = 0;
void require(bool value, const std::string& message) { ++checks; if (!value) { std::cerr << "PDB: " << message << '\n'; std::exit(1); } }
void okay(const Status& status, const std::string& message) { require(status.ok(), message + ": " + status.toString()); }
// Locate bytes in a known-valid generated MSF fixture, so hostile named-stream
// metadata can be tested without corrupting the identity or stream directory.
u64 streamByte(ByteView file,u32 wanted,u32 offset) {
    u32 blockSize=0,directorySize=0,blockMap=0;file.read(32,&blockSize);file.read(44,&directorySize);file.read(52,&blockMap);
    require(blockSize&&directorySize,"fixture directory metadata");std::vector<u8> directory(directorySize);
    for(u64 n=0;n<(u64(directorySize)+blockSize-1)/blockSize;++n){u32 block=0;require(file.read(u64(blockMap)*blockSize+n*4,&block),"fixture directory block");
        const auto count=std::min<u64>(blockSize,directorySize-n*blockSize);require(file.covers(u64(block)*blockSize,count),"fixture directory extent");
        std::memcpy(directory.data()+n*blockSize,file.data()+u64(block)*blockSize,count);}
    ByteView view(directory.data(),directory.size());u32 streams=0;view.read(0,&streams);require(wanted<streams,"fixture stream index");
    u64 cursor=4+u64(streams)*4;
    for(u32 n=0;n<streams;++n){u32 size=0;require(view.read(4+u64(n)*4,&size),"fixture stream size");const u64 blocks=size==~u32{0}?0:(u64(size)+blockSize-1)/blockSize;
        if(n==wanted){u32 block=0;require(offset<size&&view.read(cursor+(offset/blockSize)*4,&block),"fixture stream byte");return u64(block)*blockSize+offset%blockSize;}
        cursor+=blocks*4;}
    require(false,"fixture stream absent");return 0;
}
}
int main(int argc, char** argv) {
    require(argc == 3, "usage: mint_pdb_test linked.exe linked.pdb");
    MappedFile input, file; okay(input.open(argv[1]), "PE fixture"); okay(file.open(argv[2]), "PDB fixture");
    ElfImage image; okay(image.load(input.view()), "PE load");
    require(image.peCodeViewRecords().size() == 1 && image.peCodeViewRecords()[0].age != 0 && image.peCodeViewRecords()[0].path.find(".pdb") != std::string::npos, "actual RSDS GUID/age/path metadata");
    require(!image.runtimeFunctions().empty() && image.runtimeFunctions()[0].unwindValidated, "actual x64 UNWIND_INFO validated");
    DwarfReport report; okay(readPdb(image, file.view(), &report), "MSF7/DBI/TPI import");
    require(report.format == "PDB7/CodeView", "PDB provenance label, not DWARF");
    require(std::any_of(report.functions.begin(), report.functions.end(), [](const auto& function) { return function.name == "mint_debug_entry" && function.entry != kNoAddress; }), "real CodeView public/procedure function");
    require(std::any_of(report.functions.begin(), report.functions.end(), [](const auto& function) { return function.name == "mint_debug_entry" && !function.prototype.empty(); }), "real TPI procedure prototype");
    require(std::any_of(report.types.begin(), report.types.end(), [](const auto& type) { return type.name == "MintNode" && type.byteSize == 16 && type.declaration.find("next:MintNode*") != std::string::npos; }), "real recursive struct storage reconstructed");
    require(std::any_of(report.variables.begin(), report.variables.end(), [](const auto& variable) { return variable.name == "mint_debug_global" && variable.type == "MintNode"; }), "real global symbol type/address");
    const auto source=std::find_if(report.sources.begin(),report.sources.end(),[](const auto& row){return !row.endSequence&&row.line&&row.file.find("dwarf_fixture.c")!=std::string::npos;});
    require(source!=report.sources.end(),"real linked C13 source filename/line resolved through PDB named string stream");
    require(image.memory().isExecutable(source->address),"C13 rows are bound to executable PE addresses");
    const auto sourceAddress=source->address;
    std::vector<u8> mutated(input.view().data(), input.view().data() + input.size());
    const auto* rdata = image.findSection(".rdata"); require(rdata && !rdata->data.empty(), "CodeView section");
    bool changed = false;
    for (size_t at = 0; at + 24 < mutated.size(); ++at) if (!std::memcmp(mutated.data() + at, "RSDS", 4)) { mutated[at + 4] ^= 1; changed = true; break; }
    require(changed, "RSDS mutation target"); ElfImage foreign; okay(foreign.load(ByteView(mutated.data(), mutated.size())), "mutated identity PE");
    DwarfReport unchanged; unchanged.units = 99;
    require(!readPdb(foreign, file.view(), &unchanged, true).ok() && unchanged.units == 99, "provided GUID mismatch cannot be bypassed by unverified opt-in");
    for (size_t length : {size_t{0}, size_t{31}, size_t{55}, file.size() / 2, file.size() - 1}) {
        unchanged.units = 99; const auto status = readPdb(image, file.view().subview(0, length), &unchanged);
        require(!status.ok() && unchanged.units == 99, "truncated MSF directory/import failure atomic");
    }
    u32 nameBytes=0;file.view().read(streamByte(file.view(),1,28),&nameBytes);
    for(u32 offset:{28u,32+nameBytes,36+nameBytes,40+nameBytes}) {
        std::vector<u8> damaged(file.view().data(),file.view().data()+file.size());
        for(unsigned byte=0;byte<4;++byte)damaged[streamByte(file.view(),1,offset+byte)]=0xff;
        unchanged.units=99;
        require(!readPdb(image,ByteView(damaged.data(),damaged.size()),&unchanged).ok()&&unchanged.units==99,"hostile named-stream length/count/capacity/bitmap is rejected atomically");
    }
    std::string project = "/private/tmp/mint-pdb-program-XXXXXX"; const int fd = mkstemp(project.data()); require(fd >= 0, "owned project"); close(fd); unlink(project.c_str());
    Session session; okay(session.openPath(argv[1]), "Session PE"); okay(session.attachProject(project), "PE persistent Program"); okay(session.analyze(), "PE initial analysis");
    okay(session.importExternalDebug(argv[2]), "manual PDB import facade");
    require(session.typesText().find("MintNode") != std::string::npos && session.debugInfoText().find("PDB7/CodeView") != std::string::npos, "PDB Program types and provenance");
    const auto sourceLocation=session.sourceLocationText(sourceAddress);
    require(sourceLocation.find("dwarf_fixture.c:")!=std::string::npos,"PDB source mapping visible through Session facade");
    Session reopened; okay(reopened.openPath(argv[1]), "PE reopen"); okay(reopened.attachProject(project), "PDB sidecar restored");
    require(reopened.externalDebugDigest() == session.externalDebugDigest() && reopened.typesText().find("MintNode") != std::string::npos, "PDB survives exact project reopen");
    require(reopened.sourceLocationText(sourceAddress)==sourceLocation,"C13 source mapping survives persistent reopen");
    unlink((project + ".debug." + session.externalDebugDigest() + ".bin").c_str()); unlink((project + ".debug").c_str()); unlink((project + ".analysis").c_str()); unlink(project.c_str());
    std::cout << "PDB MSF7/CodeView: " << checks << " checks passed\n";
}
