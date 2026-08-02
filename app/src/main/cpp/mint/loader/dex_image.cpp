#include "mint/loader/dex_image.h"

#include <algorithm>
#include <cstring>

#include <zlib.h>

namespace mint {
namespace {
bool u32at(ByteView data, u64 off, u32* out) { return data.read(off, out); }
bool u16at(ByteView data, u64 off, u16* out) { return data.read(off, out); }
}

Status DexImage::load(ByteView data) {
    *this = {};
    data_ = data;
    if (data.size() < 112 || std::memcmp(data.data(), "dex\n", 4) != 0 || data.data()[7] != 0)
        return Status::error(ErrorCode::kBadFormat, "not a DEX image");
    u32 fileSize = 0, headerSize = 0, endian = 0, stringCount = 0, typeCount = 0, protoCount = 0, fieldCount = 0, methodCount = 0, classCount = 0, checksum = 0;
    if (!u32at(data, 32, &fileSize) || !u32at(data, 36, &headerSize) || !u32at(data, 40, &endian) || headerSize != 112 || endian != 0x12345678 ||
        !u32at(data, 8, &checksum) || !u32at(data, 56, &stringCount) || !u32at(data, 60, &stringIdsOff_) || !u32at(data, 64, &typeCount) || !u32at(data, 68, &typeIdsOff_) ||
        !u32at(data, 72, &protoCount) || !u32at(data, 76, &protoIdsOff_) || !u32at(data, 80, &fieldCount) || !u32at(data, 88, &methodCount) ||
        !u32at(data, 92, &methodIdsOff_) || !u32at(data, 96, &classCount) || !u32at(data, 100, &classDefsOff_))
        return Status::error(ErrorCode::kTruncated, "truncated DEX header");
    if (fileSize > data.size() || stringCount > 1000000 || typeCount > 1000000 || methodCount > 1000000 || classCount > 100000)
        return Status::error(ErrorCode::kBadFormat, "invalid DEX sizes");
    if (fileSize >= 12 && adler32(1, reinterpret_cast<const Bytef*>(data.data() + 12), fileSize - 12) != checksum)
        return Status::error(ErrorCode::kBadFormat, "DEX checksum mismatch");
    stringOffsets_.resize(stringCount); strings_.resize(stringCount);
    for (u32 i = 0; i < stringCount; ++i) {
        if (!u32at(data, stringIdsOff_ + i * 4, &stringOffsets_[i])) return Status::error(ErrorCode::kTruncated, "invalid DEX string offset");
        ByteCursor cursor(data, stringOffsets_[i]); cursor.nextUleb128();
        if (!cursor.ok() || !data.cString(cursor.offset(), &strings_[i], 1 << 20)) return Status::error(ErrorCode::kTruncated, "invalid DEX string");
    }
    typeIds_.resize(typeCount);
    for (u32 i = 0; i < typeCount; ++i) if (!u32at(data, typeIdsOff_ + i * 4, &typeIds_[i])) return Status::error(ErrorCode::kTruncated, "invalid DEX type");
    methods_.reserve(methodCount);
    for (u32 i = 0; i < methodCount; ++i) {
        u16 classIndex = 0, protoIndex = 0; u32 nameIndex = 0;
        if (!u16at(data, methodIdsOff_ + i * 8, &classIndex) || !u16at(data, methodIdsOff_ + i * 8 + 2, &protoIndex) || !u32at(data, methodIdsOff_ + i * 8 + 4, &nameIndex)) return Status::error(ErrorCode::kTruncated, "invalid DEX method");
        DexMethod method; method.index = i; method.classDescriptor = typeAt(classIndex); method.name = stringAt(nameIndex);
        u32 protoShorty = 0, returnType = 0, parameters = 0;
        if (u32at(data, protoIdsOff_ + protoIndex * 12, &protoShorty) && u32at(data, protoIdsOff_ + protoIndex * 12 + 4, &returnType) && u32at(data, protoIdsOff_ + protoIndex * 12 + 8, &parameters)) {
            method.prototype = stringAt(protoShorty) + ":" + typeAt(returnType);
            if (parameters) { u32 count = 0; if (u32at(data, parameters, &count) && count < 10000) for (u32 p = 0; p < count; ++p) { u16 type = 0; if (u16at(data, parameters + 4 + p * 2, &type)) method.prototype += "," + typeAt(type); } }
        }
        methods_.push_back(std::move(method));
    }
    classes_.reserve(classCount);
    for (u32 i = 0; i < classCount; ++i) {
        const u64 off = classDefsOff_ + i * 32; u32 classType = 0, access = 0, superType = 0, interfaces = 0, classData = 0;
        if (!u32at(data, off, &classType) || !u32at(data, off + 4, &access) || !u32at(data, off + 8, &superType) || !u32at(data, off + 12, &interfaces) || !u32at(data, off + 24, &classData)) return Status::error(ErrorCode::kTruncated, "invalid DEX class");
        DexClass klass; klass.descriptor = typeAt(classType); klass.superclass = typeAt(superType);
        if (interfaces) { u32 count = 0; if (u32at(data, interfaces, &count) && count < 10000) for (u32 p = 0; p < count; ++p) { u16 type = 0; if (u16at(data, interfaces + 4 + p * 2, &type)) klass.interfaces.push_back(typeAt(type)); } }
        // class_data_item uses ULEB128 method indexes. Parse just the method
        // lists; field lists are skipped while preserving bounds.
        if (classData && classData < data.size()) {
            ByteCursor cursor(data, classData); const u64 staticFields = cursor.nextUleb128(); const u64 instanceFields = cursor.nextUleb128(); const u64 directMethods = cursor.nextUleb128(); const u64 virtualMethods = cursor.nextUleb128();
            for (u64 field = 0; field < staticFields + instanceFields && cursor.ok(); ++field) { cursor.nextUleb128(); cursor.nextUleb128(); }
            auto readMethods = [&](u64 count) {
                u32 methodIndex = 0;
                for (u64 method = 0; method < count && cursor.ok(); ++method) {
                    methodIndex += static_cast<u32>(cursor.nextUleb128()); const u32 accessFlags = static_cast<u32>(cursor.nextUleb128()); const u32 code = static_cast<u32>(cursor.nextUleb128());
                    if (methodIndex < methods_.size()) { methods_[methodIndex].accessFlags = accessFlags; if (code) readCode(code, &methods_[methodIndex]); klass.methodIndices.push_back(methodIndex); }
                }
            };
            readMethods(directMethods); readMethods(virtualMethods);
        }
        classes_.push_back(std::move(klass));
    }
    loaded_ = true; return Status::success();
}

std::string DexImage::stringAt(u32 index) const { return index < strings_.size() ? strings_[index] : "?"; }
std::string DexImage::typeAt(u32 index) const { return index < typeIds_.size() ? stringAt(typeIds_[index]) : "?"; }

bool DexImage::readCode(u32 codeOffset, DexMethod* method) {
    u16 registers = 0, ins = 0, outs = 0, tries = 0; u32 insns = 0;
    if (!u16at(data_, codeOffset, &registers) || !u16at(data_, codeOffset + 2, &ins) || !u16at(data_, codeOffset + 4, &outs) || !u16at(data_, codeOffset + 6, &tries) || !u32at(data_, codeOffset + 12, &insns) || insns > 1u << 20 || !data_.covers(codeOffset + 16, insns * 2ull)) return false;
    method->registersSize = registers; method->insSize = ins; method->outsSize = outs; method->code.resize(insns);
    for (u32 i = 0; i < insns; ++i) data_.read(codeOffset + 16 + i * 2, &method->code[i]);
    return true;
}

const DexMethod* DexImage::findMethod(const std::string& classDescriptor, const std::string& name) const { for (const DexMethod& m : methods_) if (m.classDescriptor == classDescriptor && m.name == name) return &m; return nullptr; }

}  // namespace mint
