#include "mint/analysis/cxx_metadata.h"
#include "mint/analysis/exception_metadata.h"

#include <algorithm>
#include <map>
#include <set>
#include <sstream>

#include "mint/analysis/demangle.h"
#include "mint/loader/elf_image.h"

namespace mint {
namespace {

std::string abiName(const std::string& text) {
    return text.compare(0, 3, "__Z") == 0 ? text.substr(1) : text;
}
std::string displayName(const std::string& text) { return demangleSymbol(abiName(text)); }
bool starts(const std::string& text, const char* prefix) { return abiName(text).compare(0, 4, prefix) == 0; }

bool classified(const std::string& name, CxxMetadataKind* kind) {
    if (starts(name, "_ZTV")) *kind = CxxMetadataKind::kVtable;
    else if (starts(name, "_ZTI")) *kind = CxxMetadataKind::kTypeInfo;
    else if (starts(name, "_ZTS")) *kind = CxxMetadataKind::kTypeName;
    else return false;
    return true;
}

const char* kindName(CxxMetadataKind kind) {
    switch (kind) {
        case CxxMetadataKind::kVtable: return "vtable";
        case CxxMetadataKind::kTypeInfo: return "RTTI";
        case CxxMetadataKind::kTypeName: return "type name";
    }
    return "metadata";
}

class Decoder {
public:
    Decoder(const ElfImage& image, const std::vector<const ElfSymbol*>& selected) : image_(image) {
        // Reuse the image's symbol index; do not build a second multi-million
        // symbol/relocation index just to inspect a bounded report.
        std::vector<std::pair<Address, Address>> ranges;
        for (const auto* s : selected) {
            if (s->undefined || s->value > ~Address(0) - 2064) continue;
            ranges.emplace_back(s->value, s->value + std::min<u64>(s->size ? s->size : 2064, 2064));
        }
        std::sort(ranges.begin(), ranges.end());
        std::vector<std::pair<Address, Address>> merged;
        for (const auto& r : ranges) {
            if (!merged.empty() && r.first <= merged.back().second) merged.back().second = std::max(merged.back().second, r.second);
            else merged.push_back(r);
        }
        for (const auto& r : image.relocations()) {
            auto it = std::upper_bound(merged.begin(), merged.end(), r.offset,
                                      [](Address value, const auto& interval) { return value < interval.first; });
            if (it == merged.begin()) continue;
            --it;
            if (r.offset < it->second && relocations_.size() < 65536) relocations_.emplace(r.offset, &r);
        }
    }

    CxxMetadataRecord record(const ElfSymbol& symbol, CxxMetadataKind kind) const {
        CxxMetadataRecord r;
        r.kind = kind; r.address = symbol.value; r.size = symbol.size;
        r.symbol = symbol.name; r.display = displayName(symbol.name); r.defined = !symbol.undefined;
        if (!r.defined) { r.notes.push_back("Imported metadata: storage is supplied by the dynamic linker."); return r; }
        if (image_.memory().hasOverlaps()) {
            r.notes.push_back("Overlapping memory blocks: decoding is suppressed because byte ownership is ambiguous.");
            return r;
        }
        if (kind == CxxMetadataKind::kTypeName) {
            if (image_.memory().readCString(symbol.value, &r.typeName, 4096)) r.complete = true;
            else r.notes.push_back("Type name storage is not a bounded NUL-terminated string.");
        } else if (kind == CxxMetadataKind::kVtable) decodeVtable(symbol, &r);
        else decodeTypeInfo(symbol, &r);
        return r;
    }
private:
    bool range(const ElfSymbol& symbol, u64 offset, u64 length) const {
        if (offset > ~Address(0) - symbol.value || length > ~Address(0) - (symbol.value + offset)) return false;
        if (symbol.size && (offset > symbol.size || length > symbol.size - offset)) return false;
        // Real file-backed data is required; zero-filled/truncated BSS must not
        // invent RTTI flags, counts, or table slots.
        return image_.memory().viewAt(symbol.value + offset, length).size() == length;
    }
    std::string relocationName(Address at) const {
        auto found = relocations_.find(at);
        return found == relocations_.end() ? std::string() : found->second->symbolName;
    }
    std::string targetName(Address at, Address* target) const {
        *target = kNoAddress;
        std::string name = relocationName(at);
        Address resolved = 0;
        if (image_.resolvePointer(at, &resolved)) {
            // Zero is valid mapped storage in a raw image, but it is not valid
            // evidence for an Itanium RTTI base in an unrelocated null slot.
            if (resolved && image_.memory().isMapped(resolved)) *target = resolved;
            if (name.empty() && *target != kNoAddress) name = image_.describeAddress(*target);
        }
        return name;
    }
    bool typeInfoAt(Address at, CxxBaseClass* base) const {
        base->name = targetName(at, &base->typeInfo);
        if (!starts(base->name, "_ZTI")) return false;
        const auto* symbol = image_.findSymbol(base->name);
        if (!symbol || (!symbol->undefined && base->typeInfo != symbol->value)) return false;
        const auto relocation = relocations_.find(at);
        if (symbol->undefined && relocation != relocations_.end() && relocation->second->addend != 0) return false;
        const auto display = displayName(base->name);
        if (display == base->name) return false; // Prefix alone is not a valid ABI type encoding.
        base->name = display;
        return true;
    }
    void decodeVtable(const ElfSymbol& symbol, CxxMetadataRecord* r) const {
        const u64 width = image_.pointerSize(), extent = symbol.size ? std::min<u64>(symbol.size, 2064) : width * 3;
        if (!range(symbol, 0, width * 3)) { r->notes.push_back("Vtable header/first slot is not file-backed."); return; }
        const std::string expectedRtti = (symbol.name.compare(0, 3, "__Z") == 0 ? "__ZTI" : "_ZTI") + abiName(symbol.name).substr(4);
        std::vector<u64> headers;
        for (u64 offset = 0; offset + width * 2 <= extent; offset += width) {
            CxxBaseClass type;
            if (!range(symbol, offset, width * 2) || !typeInfoAt(symbol.value + offset + width, &type)) continue;
            Address target = kNoAddress; const auto name = targetName(symbol.value + offset + width, &target);
            if (name != expectedRtti) continue;
            i64 toTop = 0; if (width == 4) { i32 value = 0; image_.memory().readInt(symbol.value + offset, &value); toTop = value; }
            else image_.memory().readInt(symbol.value + offset, &toTop);
            if ((headers.empty() && toTop != 0) || toTop > 0 || toTop < -0x40000000) continue;
            headers.push_back(offset);
        }
        if (headers.empty()) { r->notes.push_back("No exact class RTTI-backed final vtable header; no-RTTI/construction layouts are not guessed."); return; }
        u64 previousEnd = 0;
        for (size_t index = 0; index < headers.size() && index < 64; ++index) {
            const u64 offset = headers[index], end = index + 1 < headers.size() ? headers[index + 1] : extent;
            CxxVtableAddressPoint point; point.header = symbol.value + offset; point.addressPoint = point.header + width * 2;
            CxxBaseClass type; typeInfoAt(point.header + width, &type); point.typeInfo = type.typeInfo;
            if (width == 4) { i32 value = 0; image_.memory().readInt(point.header, &value); point.offsetToTop = value; }
            else image_.memory().readInt(point.header, &point.offsetToTop);
            for (u64 word = previousEnd; word < offset && point.prefixDisplacements.size() < 64; word += width) {
                i64 displacement = 0; if (width == 4) { i32 value = 0; image_.memory().readInt(symbol.value + word, &value); displacement = value; }
                else image_.memory().readInt(symbol.value + word, &displacement);
                point.prefixDisplacements.push_back(displacement);
            }
            previousEnd = offset + width * 2;
            for (u64 word = previousEnd; word + width <= end && point.slots.size() < 256 && totalSlots_ < 8192; word += width) {
                if (!range(symbol, word, width)) break;
                CxxVtableSlot slot; slot.address = symbol.value + word; slot.symbol = targetName(slot.address, &slot.target);
                slot.executable = slot.target != kNoAddress && image_.memory().isExecutable(slot.target);
                const auto* method = image_.findSymbol(slot.symbol);
                if (!slot.executable && !(method && method->undefined && method->isFunction()) && slot.symbol != "__cxa_pure_virtual" && slot.symbol != "__cxa_deleted_virtual") break;
                slot.symbol = displayName(slot.symbol); point.slots.push_back(std::move(slot)); ++totalSlots_; previousEnd = word + width;
            }
            point.complete = symbol.size && previousEnd == end;
            // Prefix displacements before another header are ABI storage, not
            // virtual methods; completeness is per address point, not flattened.
            r->addressPoints.push_back(std::move(point));
        }
        const auto& primary = r->addressPoints.front(); r->addressPoint = primary.addressPoint;
        r->offsetToTop = primary.offsetToTop; r->typeInfo = primary.typeInfo; r->slots = primary.slots;
        r->typeName = displayName(expectedRtti); r->complete = symbol.size && symbol.size <= 2064 && previousEnd == symbol.size;
        if (!r->complete) r->notes.push_back("Vtable group includes unclassified ABI storage or exceeds the bounded slot extent; retained address points are verified independently.");
    }
    void decodeTypeInfo(const ElfSymbol& symbol, CxxMetadataRecord* r) const {
        const u64 width = image_.pointerSize();
        if (!range(symbol, 0, width * 2)) { r->notes.push_back("RTTI header is not file-backed."); return; }
        Address vptr = kNoAddress;
        const auto vptrName = targetName(symbol.value, &vptr);
        r->abiClass = displayName(vptrName);
        Address name = kNoAddress;
        targetName(symbol.value + width, &name);
        if (name != kNoAddress) image_.memory().readCString(name, &r->typeName, 4096);
        // A plain substring can be forged by an unrelated user symbol. Require
        // the runtime's exact Itanium linkage identity (with an address suffix
        // only for an in-image vtable address point).
        const auto runtimeClass = [&](const std::string& name, const char* identity) {
            const std::string exact(identity), canonical = abiName(name);
            if (!(canonical == exact || (canonical.size() > exact.size() &&
                  canonical.compare(0, exact.size(), exact) == 0 && canonical[exact.size()] == '+'))) return false;
            const auto* runtime = image_.findSymbol(exact);
            if (!runtime && image_.format() == ImageFormat::kMachO64) runtime = image_.findSymbol('_' + exact);
            if (!runtime) return false;
            if (!runtime->undefined)
                return runtime->value <= ~Address(0) - width * 2 && vptr == runtime->value + width * 2;
            const auto relocation = relocations_.find(symbol.value);
            return relocation != relocations_.end() && relocation->second->addend == static_cast<i64>(width * 2);
        };
        if (runtimeClass(vptrName, "_ZTVN10__cxxabiv120__si_class_type_infoE")) {
            if (!range(symbol, width * 2, width)) { r->notes.push_back("Single-inheritance RTTI base slot is truncated."); return; }
            CxxBaseClass base;
            if (!typeInfoAt(symbol.value + width * 2, &base)) { r->notes.push_back("Single-inheritance base has no verified RTTI symbol."); return; }
            if (totalBases_ >= 4096) { r->notes.push_back("Global base-class budget reached (4096)."); return; }
            base.isPublic = true;
            r->bases.push_back(std::move(base));
            ++totalBases_;
            r->complete = true;
        } else if (runtimeClass(vptrName, "_ZTVN10__cxxabiv121__vmi_class_type_infoE")) {
            if (!range(symbol, width * 2, 8)) { r->notes.push_back("Multiple-inheritance RTTI count is truncated."); return; }
            u32 flags = 0, count = 0;
            image_.memory().readInt(symbol.value + width * 2, &flags);
            image_.memory().readInt(symbol.value + width * 2 + 4, &count);
            if (flags & ~u32(3)) r->notes.push_back("Unknown __vmi ABI flags are retained but not interpreted.");
            if (count > 64 || !range(symbol, width * 2 + 8, u64(count) * width * 2)) {
                r->notes.push_back("Multiple-inheritance base array is truncated or exceeds 64 bases."); return;
            }
            for (u32 i = 0; i < count; ++i) {
                if (totalBases_ >= 4096) { r->notes.push_back("Global base-class budget reached (4096)."); return; }
                const Address slot = symbol.value + width * 2 + 8 + u64(i) * width * 2;
                CxxBaseClass base;
                if (!typeInfoAt(slot, &base)) { r->notes.push_back("A base has no verified RTTI symbol; partial base list retained."); return; }
                u64 offsetFlags = 0;
                if (width == 4) { u32 value = 0; image_.memory().readInt(slot + width, &value); offsetFlags = value; }
                else image_.memory().readInt(slot + width, &offsetFlags);
                base.isVirtual = (offsetFlags & 1) != 0;
                base.isPublic = (offsetFlags & 2) != 0;
                base.offset = static_cast<i64>(offsetFlags >> 8);
                if (offsetFlags & (u64(1) << (width * 8 - 1))) base.offset -= (i64(1) << (width * 8 - 8));
                r->bases.push_back(std::move(base));
                ++totalBases_;
            }
            r->complete = true;
        } else if (runtimeClass(vptrName, "_ZTVN10__cxxabiv117__class_type_infoE")) {
            r->complete = true; // No base-class payload in this ABI record.
        } else {
            r->notes.push_back("RTTI ABI class is unresolved/unsupported; no class layout is inferred.");
        }
    }
    const ElfImage& image_;
    std::map<Address, const ElfRelocation*> relocations_;
    mutable size_t totalSlots_ = 0;
    mutable size_t totalBases_ = 0;
};

}  // namespace

CxxMetadataReport inspectCxxMetadata(const ElfImage& image, size_t limit) {
    CxxMetadataReport report;
    if (image.format() != ImageFormat::kElf64 && image.format() != ImageFormat::kElf32 && image.format() != ImageFormat::kMachO64) {
        report.notes.push_back("Itanium metadata decoding requires a supported little-endian ELF/Mach-O image; Microsoft RTTI is a different ABI.");
        return report;
    }
    limit = std::min<size_t>(limit, 4096);
    std::vector<const ElfSymbol*> found;
    std::set<std::string> identities;
    for (const auto& symbol : image.symbols()) {
        CxxMetadataKind kind;
        if (!classified(symbol.name, &kind)) continue;
        const auto identity = symbol.name + ':' + std::to_string(symbol.value) + (symbol.undefined ? ":import" : ":defined");
        if (identities.find(identity) != identities.end()) continue;
        if (found.size() >= limit) { report.truncated = true; break; }
        // A demangled name may expand substantially. Keep the inventory's
        // metadata payload bounded independently of hostile ELF string tables.
        if (symbol.name.size() > 4096) { report.truncated = true; continue; }
        identities.insert(identity);
        found.push_back(&symbol);
    }
    std::sort(found.begin(), found.end(), [](const ElfSymbol* a, const ElfSymbol* b) {
        if (a->value != b->value) return a->value < b->value;
        return a->name < b->name;
    });
    Decoder decoder(image, found);
    for (const auto* symbol : found) {
        CxxMetadataKind kind;
        classified(symbol->name, &kind);
        report.records.push_back(decoder.record(*symbol, kind));
    }
    for (const auto& rtti : report.records) {
        if (rtti.kind != CxxMetadataKind::kTypeInfo || !rtti.defined) continue;
        CxxMetadataReport::Class klass; klass.name = rtti.display; klass.linkage = rtti.symbol;
        klass.typeInfo = rtti.address; klass.bases = rtti.bases; klass.inheritanceComplete = rtti.complete;
        for (const auto& table : report.records) if (table.kind == CxxMetadataKind::kVtable && table.typeInfo == rtti.address && table.defined) {
            klass.vtable = table.address; klass.addressPoints = table.addressPoints;
            for (auto& base : klass.bases) {
                base.objectOffset = base.offset;
                if (!base.isVirtual || klass.addressPoints.empty()) continue;
                const auto& primary = klass.addressPoints.front();
                if (base.offset >= 0 || base.offset % image.pointerSize() || primary.offsetToTop != 0 ||
                    static_cast<u64>(-base.offset) > primary.addressPoint - table.address) continue;
                const Address slot = primary.addressPoint - static_cast<u64>(-base.offset);
                // The displacement must reside before this verified header,
                // not alias offset-to-top, RTTI or a function-pointer word.
                if (slot >= primary.header || image.memory().viewAt(slot, image.pointerSize()).size() != image.pointerSize()) continue;
                if (image.pointerSize() == 4) { i32 value = 0; image.memory().readInt(slot, &value); base.objectOffset = value; }
                else image.memory().readInt(slot, &base.objectOffset);
                base.virtualOffsetResolved = true;
            }
            break;
        }
        report.classes.push_back(std::move(klass));
    }
    report.notes.push_back("Evidence: Itanium symbol names plus mapped bytes/relocations; original linkage names are preserved.");
    report.notes.push_back("Primary/secondary address points and RTTI-backed virtual-base displacement slots are reconstructed independently; no unproven data-member size or method body is invented. Stripped heuristics, construction vtables and Microsoft RTTI remain separate ABIs. LSDA records relationships, not source-level try/catch reconstruction.");
    return report;
}

std::string cxxMetadataText(const ElfImage& image, size_t limit) {
    const auto report = inspectCxxMetadata(image, limit);
    std::ostringstream out;
    out << "C++ metadata (symbol/relocation-backed Itanium ABI)\n";
    for (const auto& r : report.records) {
        out << "\n0x" << std::hex << r.address << std::dec << " " << kindName(r.kind) << " " << r.display
            << (r.defined ? "" : " [import]") << (r.complete ? " [decoded]" : " [partial]") << '\n';
        out << "  linkage: " << r.symbol << " size=" << r.size << '\n';
        if (!r.abiClass.empty()) out << "  ABI class: " << r.abiClass << '\n';
        if (!r.typeName.empty()) out << "  type: " << r.typeName << '\n';
        if (r.addressPoint != kNoAddress) out << "  address-point=0x" << std::hex << r.addressPoint << std::dec << " offset-to-top=" << r.offsetToTop << '\n';
        for (const auto& slot : r.slots) {
            out << "  slot 0x" << std::hex << slot.address;
            if (slot.target != kNoAddress) out << " -> 0x" << slot.target;
            out << std::dec << " " << slot.symbol << (slot.executable ? " [code]" : " [relocation]") << '\n';
        }
        for (const auto& base : r.bases)
            out << "  base: " << base.name << " offset=" << base.offset << (base.isVirtual ? " [virtual; offset is vtable displacement]" : "") << (base.isPublic ? " [public]" : " [non-public]") << '\n';
        for (size_t index = 1; index < r.addressPoints.size(); ++index) {
            const auto& point = r.addressPoints[index];
            out << "  secondary address-point=0x" << std::hex << point.addressPoint << std::dec << " offset-to-top=" << point.offsetToTop << " methods=" << point.slots.size() << '\n';
            for (const auto& slot : point.slots) out << "    0x" << std::hex << slot.address << std::dec << " " << slot.symbol << '\n';
        }
        for (const auto& note : r.notes) out << "  note: " << note << '\n';
    }
    if (report.records.empty()) out << "No supported C++ metadata symbols found. Absence is not evidence that this binary is not C++.\n";
    if (report.truncated) out << "\nRecord budget reached; report is partial.\n";
    for (const auto& klass : report.classes) {
        out << "\nclass relationship " << klass.name << " RTTI=0x" << std::hex << klass.typeInfo << std::dec << " address-points=" << klass.addressPoints.size() << '\n';
        for (const auto& base : klass.bases) {
            out << "  " << base.name << (base.isVirtual ? " virtual" : " nonvirtual") << " base";
            if (!base.isVirtual || base.virtualOffsetResolved) out << " object-offset=" << base.objectOffset;
            else out << " vtable-displacement=" << base.offset << " [unresolved object offset]";
            out << '\n';
        }
    }
    for (const auto& note : report.notes) out << "\n" << note << '\n';
    out << '\n' << exceptionMetadataText(image, limit);
    return out.str();
}

}  // namespace mint
