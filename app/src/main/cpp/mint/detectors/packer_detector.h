#pragma once

#include <vector>

#include "mint/detectors/detector.h"

namespace mint { std::vector<DetectorFinding> detectPackers(const ElfImage& image); }
