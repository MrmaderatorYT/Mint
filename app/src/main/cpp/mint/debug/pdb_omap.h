#pragma once
#include "mint/base/byte_view.h"
#include "mint/base/status.h"
#include <vector>

namespace mint {
struct PdbOmapRange {u32 source=0,target=0;u64 size=0;};
struct PdbOriginalSection {u32 rva=0;u64 size=0;bool executable=false;};
// OMAPFROM: greatest source RVA <= query selects an affine mapping until the
// next entry. Zero destinations denote removed code/data and are never addresses.
// Layout: https://learn.microsoft.com/en-us/windows/win32/api/dbghelp/ns-dbghelp-omap
// Original section stream: https://llvm.org/docs/PDB/DbiStream.html
class PdbOmap {
public:
    Status load(ByteView entries,ByteView originalSectionHeaders);
    static Status validateTable(ByteView entries);
    bool active() const {return !entries_.empty();}
    const std::vector<PdbOriginalSection>& sections() const {return sections_;}
    Status source(u16 section,u32 offset,u64 size,u32* rva) const;
    Status translate(u32 source,u64 size,std::vector<PdbOmapRange>* output) const;
private:
    struct Entry {u32 source,target;};
    std::vector<Entry> entries_;
    std::vector<PdbOriginalSection> sections_;
};
}
