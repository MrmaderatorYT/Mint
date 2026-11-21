#pragma once

#include <cstddef>
#include <sys/types.h>

namespace mint::testing {

// Compiled into the host test engine only. The write hook can produce partial
// writes and errno failures. The publication hook runs after fsync and close.
struct ProgramSaveHooks {
    ssize_t (*write)(int, const void*, size_t) = nullptr;
    void (*beforeRename)() = nullptr;
};

void setProgramSaveHooks(ProgramSaveHooks hooks);

} // namespace mint::testing
