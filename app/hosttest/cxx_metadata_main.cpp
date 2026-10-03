#include <cstdlib>
#include <iostream>
#include <string>

#include "mint/analysis/cxx_metadata.h"
#include "mint/base/mapped_file.h"
#include "mint/loader/elf_image.h"

using namespace mint;
static void require(bool condition, const std::string& message) {
    if (!condition) { std::cerr << "FAIL: " << message << '\n'; std::exit(1); }
}

int main(int argc, char** argv) {
    const bool inventory = argc == 3 && std::string(argv[1]) == "--inventory";
    require(argc == 2 || inventory, "usage: mint_cxx_metadata_test [--inventory] <binary>");
    MappedFile file;
    require(file.open(argv[inventory ? 2 : 1]).ok(), "fixture open");
    ElfImage image;
    require(image.load(file.view()).ok(), "fixture ELF load");
    const auto report = inspectCxxMetadata(image);
    if (inventory) {
        unsigned decoded = 0, slots = 0, bases = 0;
        for (const auto& r : report.records) { decoded += r.complete; slots += r.slots.size(); bases += r.bases.size(); }
        require(!report.records.empty(), "real corpus has C++ metadata");
        require(slots <= 8192 && bases <= 4096, "global report budgets");
        require(!cxxMetadataText(image, 64).empty(), "corpus display report");
        std::cout << "C++ metadata corpus: " << report.records.size() << " records, " << decoded << " decoded, " << slots << " slots, " << bases << " bases; passed\n";
        return 0;
    }
    unsigned vtables = 0, rtti = 0, names = 0, methods = 0;
    bool derivedBase = false, multipleBases = false, virtualBase = false, secondarySeparated = false, virtualAddressPoint = false;
    for (const auto& r : report.records) {
        require(!r.symbol.empty(), "original linkage identity retained");
        if (!r.defined) continue;
        if (r.kind == CxxMetadataKind::kVtable) ++vtables;
        if (r.kind == CxxMetadataKind::kTypeInfo) ++rtti;
        if (r.kind == CxxMetadataKind::kTypeName) ++names;
        for (const auto& slot : r.slots) {
            require(slot.executable, "fixture slot points to mapped executable method");
            ++methods;
        }
        if (r.symbol == "_ZTI7Derived") {
            derivedBase = r.complete && r.bases.size() == 1 && r.bases[0].name == "typeinfo for Base" && r.bases[0].isPublic;
        }
        if (r.symbol == "_ZTI8Multiple") {
            multipleBases = r.complete && r.bases.size() == 2 && r.bases[0].offset == 0 && r.bases[1].offset == 8;
        }
        if (r.symbol == "_ZTI7Virtual") {
            virtualBase = r.complete && r.bases.size() == 1 && r.bases[0].isVirtual && r.bases[0].offset < 0;
        }
        if (r.symbol == "_ZTV8Multiple") secondarySeparated = r.slots.size() == 3 && r.addressPoints.size() == 2 && r.addressPoints[1].offsetToTop == -8 && !r.addressPoints[1].slots.empty();
        if (r.symbol == "_ZTV7Virtual") virtualAddressPoint = r.addressPoint != kNoAddress && !r.addressPoints.empty() && !r.addressPoints[0].prefixDisplacements.empty();
    }
    require(vtables >= 4 && rtti >= 5 && names >= 5, "symbol-backed metadata found");
    require(methods >= 7, "primary methods recovered");
    require(derivedBase, "single inheritance recovered through relocations");
    require(multipleBases, "multiple-inheritance base offsets recovered");
    require(virtualBase, "virtual base vtable displacement decoded as signed");
    require(secondarySeparated, "secondary vtable headers separated into verified address points");
    require(virtualAddressPoint, "virtual-inheritance prefix separated from exact RTTI-backed address point");
    bool virtualOffset = false;
    for (const auto& klass : report.classes) if (klass.linkage == "_ZTI7Virtual") virtualOffset = klass.bases.size() == 1 && klass.bases[0].virtualOffsetResolved;
    require(virtualOffset, "virtual-base object displacement resolved through proven RTTI/vtable slot");
    require(inspectCxxMetadata(image, 1).truncated, "record budget enforced");
    require(inspectCxxMetadata(image, 0).records.empty(), "zero budget returns no records");
    const auto text = cxxMetadataText(image);
    require(text.find("linkage: _ZTI7Derived") != std::string::npos, "report retains identity");
    require(text.find("no unproven data-member size") != std::string::npos, "limitations explicit");
    std::cout << "C++ metadata fixture: " << report.records.size() << " records, " << methods << " methods; passed\n";
}
