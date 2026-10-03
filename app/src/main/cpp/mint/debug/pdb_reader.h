#pragma once
#include "mint/debug/dwarf_reader.h"

namespace mint {
class ElfImage;
// MSF7 stream directory, PDB/DBI identity, CodeView public/procedure/data records
// and exact representable TPI storage. No PDB path is opened automatically.
// OMAP, type servers, bitfield/virtual object layouts and unsupported CodeView
// records remain explicitly partial rather than being silently reinterpreted.
Status readPdb(const ElfImage& image, ByteView pdb, DwarfReport* out, bool allowUnverified = false);
}
