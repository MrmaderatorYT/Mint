#pragma once
#include "mint/debug/dwarf_reader.h"

namespace mint {
class ElfImage;
struct CodeViewSourceSection {Address address=0;u64 size=0;bool executable=false;};
// Bounded C13 line/checksum/string subsections. Paths are display metadata only;
// no source file or path named by the PDB is opened. Output publishes atomically.
// Supplying originalSections decodes pre-OMAP coordinates; the caller must
// translate those rows to the current image before adopting them as metadata.
Status readCodeViewLines(const ElfImage& image, ByteView subsections, ByteView globalStrings,
                         std::vector<DwarfSourceRow>* output,
                         const std::vector<CodeViewSourceSection>* originalSections=nullptr);
}
