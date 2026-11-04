#pragma once
#include "mint/debug/dwarf_reader.h"

namespace mint {
class ElfImage;
// MSF7 stream directory, PDB/DBI identity, CodeView public/procedure/data records
// and exact representable TPI storage, named /names strings and bounded C13
// source lines/columns. No PDB or source path is opened automatically.
// OMAPFROM maps original section RVAs, split function ranges and C13 coverage.
// Removed code is omitted; OMAPTO-only inversion is not inferred. Type servers,
// bitfield/virtual object layouts and unsupported CodeView
// records remain explicitly partial rather than being silently reinterpreted.
Status readPdb(const ElfImage& image, ByteView pdb, DwarfReport* out, bool allowUnverified = false);
}
