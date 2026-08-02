#include <algorithm>
#include <chrono>
#include <cstdio>
#include <string>
#include <vector>

#include "mint/base/mapped_file.h"
#include "mint/loader/elf_image.h"

namespace {

std::string legacyDescribe(const mint::ElfImage& image, mint::Address addr) {
    const mint::ElfSymbol* best = nullptr;
    for (const mint::ElfSymbol& symbol : image.symbols()) {
        if (symbol.undefined || symbol.name.empty() || symbol.value == 0 ||
            symbol.isMappingSymbol() || symbol.size == 0) {
            continue;
        }
        if (symbol.value == addr) return symbol.name;
        if (addr > symbol.value && symbol.size <= ~symbol.value &&
            addr < symbol.value + symbol.size &&
            (best == nullptr || symbol.size < best->size)) {
            best = &symbol;
        }
    }
    if (best == nullptr) return {};
    return best->name;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        std::fprintf(stderr, "usage: mint_perf_test <file.so>\n");
        return 2;
    }
    mint::MappedFile file;
    if (!file.open(argv[1]).ok()) return 1;
    mint::ElfImage image;
    if (!image.load(file.view()).ok()) return 1;

    std::vector<mint::Address> queries;
    for (const mint::ElfSymbol& symbol : image.symbols()) {
        if (!symbol.undefined && symbol.value != 0) queries.push_back(symbol.value);
    }
    if (queries.empty()) return 0;
    const size_t seedCount = queries.size();
    while (queries.size() < 10000) queries.push_back(queries[queries.size() % seedCount]);
    queries.resize(10000);

    volatile size_t indexedLength = 0;
    volatile size_t legacyLength = 0;
    const auto indexedStart = std::chrono::steady_clock::now();
    for (mint::Address address : queries) indexedLength += image.describeAddress(address).size();
    const auto indexedEnd = std::chrono::steady_clock::now();
    const auto legacyStart = std::chrono::steady_clock::now();
    for (mint::Address address : queries) legacyLength += legacyDescribe(image, address).size();
    const auto legacyEnd = std::chrono::steady_clock::now();
    const double indexedNs = std::chrono::duration<double, std::nano>(indexedEnd - indexedStart).count();
    const double legacyNs = std::chrono::duration<double, std::nano>(legacyEnd - legacyStart).count();
    std::printf("lookups: %zu  indexed: %.1f ns/query  legacy: %.1f ns/query  speedup: %.2fx\n",
                queries.size(), indexedNs / queries.size(), legacyNs / queries.size(),
                indexedNs == 0 ? 0.0 : legacyNs / indexedNs);
    // Keep the loops observable under an optimizing build.
    if (indexedLength == 0 && legacyLength != 0) return 1;
    return 0;
}
