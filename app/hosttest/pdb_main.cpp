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
    std::string project = "/private/tmp/mint-pdb-program-XXXXXX"; const int fd = mkstemp(project.data()); require(fd >= 0, "owned project"); close(fd); unlink(project.c_str());
    Session session; okay(session.openPath(argv[1]), "Session PE"); okay(session.attachProject(project), "PE persistent Program"); okay(session.analyze(), "PE initial analysis");
    okay(session.importExternalDebug(argv[2]), "manual PDB import facade");
    require(session.typesText().find("MintNode") != std::string::npos && session.debugInfoText().find("PDB7/CodeView") != std::string::npos, "PDB Program types and provenance");
    Session reopened; okay(reopened.openPath(argv[1]), "PE reopen"); okay(reopened.attachProject(project), "PDB sidecar restored");
    require(reopened.externalDebugDigest() == session.externalDebugDigest() && reopened.typesText().find("MintNode") != std::string::npos, "PDB survives exact project reopen");
    unlink((project + ".debug." + session.externalDebugDigest() + ".bin").c_str()); unlink((project + ".debug").c_str()); unlink((project + ".analysis").c_str()); unlink(project.c_str());
    std::cout << "PDB MSF7/CodeView: " << checks << " checks passed\n";
}
