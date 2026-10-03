#pragma once
#include <string>
#include "mint/base/byte_view.h"

namespace mint {
// Content binding, independent of host byte order and external crypto runtimes.
std::string sha256(ByteView bytes);
}
