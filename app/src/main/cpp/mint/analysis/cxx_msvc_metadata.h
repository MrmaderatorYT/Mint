#pragma once
#include "mint/analysis/cxx_metadata.h"
namespace mint {
class ElfImage;
// Export-linkage-backed MSVC RTTI, not a scan for plausible pointer patterns.
CxxMetadataReport inspectMicrosoftCxxMetadata(const ElfImage& image,size_t limit);
}
