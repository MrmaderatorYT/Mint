#pragma once

#include <vector>

#include "mint/detectors/detector.h"

namespace mint { std::vector<DetectorFinding> detectAntiTamper(const ElfImage& image); }
