#pragma once

#include <cstddef>
#include <sys/types.h>

namespace mint::testing {

// Compiled into the host test engine only. The sync hook targets the temporary
// file. The publication hooks bracket rename after the file has been closed.
struct ProgramSaveHooks {
    ssize_t (*write)(int, const void*, size_t) = nullptr;
    void (*beforeRename)() = nullptr;
    int (*syncTemporary)(int) = nullptr;
    int (*rename)(const char*, const char*) = nullptr;
    void (*afterRename)() = nullptr;
};

void setProgramSaveHooks(ProgramSaveHooks hooks);

} // namespace mint::testing
