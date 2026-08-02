#include "mint/ir/varnode.h"

#include <cstdio>

#include "mint/ir/registers.h"

namespace mint {

const char* spaceName(Space space) {
    switch (space) {
        case Space::kInvalid: return "invalid";
        case Space::kConstant: return "const";
        case Space::kRegister: return "reg";
        case Space::kTemp: return "temp";
        case Space::kMemory: return "mem";
    }
    return "?";
}

std::string describeVarnode(const Varnode& node, Arch arch) {
    char buffer[64];
    switch (node.space) {
        case Space::kInvalid:
            return "-";
        case Space::kConstant:
            // Small values read better in decimal; anything larger is almost
            // always an address or a mask, where hex is what you want to see.
            if (node.offset < 16) {
                std::snprintf(buffer, sizeof(buffer), "%llu:%u",
                              static_cast<unsigned long long>(node.offset),
                              unsigned(node.size));
            } else {
                std::snprintf(buffer, sizeof(buffer), "0x%llx:%u",
                              static_cast<unsigned long long>(node.offset),
                              unsigned(node.size));
            }
            return buffer;
        case Space::kRegister:
            return registerName(arch, node.offset, node.size);
        case Space::kTemp:
            std::snprintf(buffer, sizeof(buffer), "t%llu:%u",
                          static_cast<unsigned long long>(node.offset),
                          unsigned(node.size));
            return buffer;
        case Space::kMemory:
            std::snprintf(buffer, sizeof(buffer), "mem:%u", unsigned(node.size));
            return buffer;
    }
    return "?";
}

}  // namespace mint
