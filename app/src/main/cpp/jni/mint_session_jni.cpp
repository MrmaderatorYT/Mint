// JNI surface for the analysis engine.
//
// Every bulk transfer goes through caller-provided parallel arrays. That is not
// aesthetic preference: a large library disassembles to hundreds of thousands of
// instructions, and returning one Java object per row would mean hundreds of
// thousands of JNI crossings and allocations to fill a list the user scrolls
// through a screenful at a time. The arrays let a screenful cost exactly one
// crossing.

#include <jni.h>

#include <algorithm>
#include <cstdio>
#include <string>
#include <vector>

#include "jni/jni_util.h"
#include "mint/base/log.h"
#include "mint/session.h"
#include "mint/analysis/cxx_metadata.h"
#include "mint/plugin/architecture_bridge.h"

using mint::Address;
using mint::DexMethod;
using mint::i8;
using mint::i16;
using mint::i32;
using mint::i64;
using mint::kNoAddress;
using mint::Session;
using mint::u8;
using mint::u16;
using mint::u32;

namespace {

Session* asSession(jlong handle) { return reinterpret_cast<Session*>(handle); }

/// Bit flags packed into the `flags` column of the function list, so the Java
/// side gets everything it needs to render a row without a second call.
enum FunctionFlags : jint {
    kFlagIncomplete = 1 << 0,
    kFlagHasIndirect = 1 << 1,
    kFlagUndecodable = 1 << 2,
};

std::string dexInstructionText(u16 unit, const DexMethod& method, u32 pc) {
    const u8 op = static_cast<u8>(unit & 0xff);
    const u8 va = static_cast<u8>((unit >> 8) & 0xff);
    const u8 vb = static_cast<u8>((unit >> 12) & 0xf);
    switch (op) {
        case 0x00: return "nop";
        case 0x01: return "move v" + std::to_string(va) + ", v" + std::to_string(vb);
        case 0x0e: return "return-void";
        case 0x0f: return "return v" + std::to_string(va);
        case 0x12: return "const/4 v" + std::to_string(va) + ", #" + std::to_string(static_cast<i8>(unit >> 12));
        case 0x13: return "const/16 v" + std::to_string(va);
        case 0x14: return "const v" + std::to_string(va);
        case 0x28: return "goto " + std::to_string(static_cast<i8>(unit >> 8));
        case 0x29: return "goto/16";
        case 0x2a: return "goto/32";
        case 0x32: return "if-eq v" + std::to_string(va) + ", v" + std::to_string(vb);
        case 0x33: return "if-ne v" + std::to_string(va) + ", v" + std::to_string(vb);
        case 0x34: return "if-lt v" + std::to_string(va) + ", v" + std::to_string(vb);
        case 0x35: return "if-ge v" + std::to_string(va) + ", v" + std::to_string(vb);
        case 0x36: return "if-gt v" + std::to_string(va) + ", v" + std::to_string(vb);
        case 0x37: return "if-le v" + std::to_string(va) + ", v" + std::to_string(vb);
        case 0x38: return "if-eqz v" + std::to_string(va);
        case 0x39: return "if-nez v" + std::to_string(va);
        case 0x3a: return "if-ltz v" + std::to_string(va);
        case 0x3b: return "if-gez v" + std::to_string(va);
        case 0x3c: return "if-gtz v" + std::to_string(va);
        case 0x3d: return "if-lez v" + std::to_string(va);
        default: return "op_0x" + [&] { char buf[8]; snprintf(buf, sizeof(buf), "%02x", op); return std::string(buf); }();
    }
}

Address dexBranchTarget(const DexMethod& method, u32 pc) {
    if (pc >= method.code.size()) return kNoAddress;
    const u16 unit = method.code[pc];
    const u8 op = static_cast<u8>(unit & 0xff);
    i32 delta = 0;
    if (op == 0x28) delta = static_cast<i8>(unit >> 8);
    else if (op == 0x29 && pc + 1 < method.code.size()) delta = static_cast<i16>(method.code[pc + 1]);
    else if (op == 0x2a && pc + 2 < method.code.size()) delta = static_cast<i32>(method.code[pc + 1] | (static_cast<u32>(method.code[pc + 2]) << 16));
    else if ((op >= 0x32 && op <= 0x3d) && pc + 1 < method.code.size()) delta = static_cast<i16>(method.code[pc + 1]);
    else return kNoAddress;
    return static_cast<Address>(static_cast<i64>(pc) + delta);
}

}  // namespace

extern "C" {

JNIEXPORT jlong JNICALL
Java_com_ccs_mint_core_MintSession_nativeOpenPath(JNIEnv* env, jclass, jstring path) {
    const std::string nativePath = mint::jni::fromJava(env, path);
    if (nativePath.empty()) {
        mint::jni::throwIllegalArgument(env, "path is empty");
        return 0;
    }

    auto session = new Session();
    mint::Status status = session->openPath(nativePath);
    if (!status.ok()) {
        delete session;
        mint::jni::throwIoException(env, status.toString());
        return 0;
    }
    return reinterpret_cast<jlong>(session);
}

JNIEXPORT jlong JNICALL
Java_com_ccs_mint_core_MintSession_nativeOpenRaw(JNIEnv* env,jclass,jstring path,jstring architecture,jlong base,jlong entry) {
    const auto name=mint::jni::fromJava(env,architecture);
    auto arch=mint::Arch::kUnknown;
    for(const auto& description:mint::architectureDescriptions())
        if(description.id==name || mint::archName(description.architecture)==name || (name=="x86_64" && description.architecture==mint::Arch::kX86_64))arch=description.architecture;
    auto* session=new Session();auto status=session->openRawPath(mint::jni::fromJava(env,path),arch,static_cast<Address>(base),static_cast<Address>(entry));
    if(!status.ok()){delete session;mint::jni::throwIoException(env,status.toString());return 0;}
    return reinterpret_cast<jlong>(session);
}
JNIEXPORT jobjectArray JNICALL
Java_com_ccs_mint_core_MintSession_nativeRawArchitectures(JNIEnv* env, jclass) {
    try {
        const auto descriptions = mint::architectureDescriptions();
        if (descriptions.size() > mint::kMaxArchitectureDescriptions) { mint::jni::throwIllegalState(env, "architecture registry limit exceeded"); return nullptr; }
        jclass stringClass = env->FindClass("java/lang/String"); if (!stringClass) return nullptr;
        jobjectArray output = env->NewObjectArray(static_cast<jsize>(descriptions.size() * 9), stringClass, nullptr);
        env->DeleteLocalRef(stringClass); if (!output) return nullptr;
        jsize index = 0;
        for (const auto& description : descriptions) {
            // Names are display-only; never pass arbitrary native bytes through
            // JNI's modified-UTF8 constructor. Stable IDs remain exact ASCII.
            auto name = description.name; for (char& c : name) if (static_cast<unsigned char>(c) < 32 || static_cast<unsigned char>(c) > 126) c = '?';
            const std::string fields[] = {description.id, name, std::to_string(static_cast<unsigned>(description.architecture)),
                std::to_string(description.pointerSize), std::to_string(description.minInstructionSize), std::to_string(description.maxInstructionSize),
                std::to_string(description.instructionAlignment), description.decode ? (mint::architecturePluginHasLifter(description.architecture)?"2":"1") : "0", description.thumbAddressTag ? "1" : "0"};
            for (const auto& field : fields) {
                jstring value = mint::jni::toJava(env, field); if (!value) return nullptr;
                env->SetObjectArrayElement(output, index++, value); env->DeleteLocalRef(value); if (env->ExceptionCheck()) return nullptr;
            }
        }
        return output;
    } catch (...) { mint::jni::throwIllegalState(env, "cannot snapshot architecture registry"); return nullptr; }
}
JNIEXPORT jlong JNICALL
Java_com_ccs_mint_core_MintSession_nativeOpenMachO(JNIEnv* env,jclass,jstring path,jstring architecture) {
    const auto name=mint::jni::fromJava(env,architecture);auto arch=mint::Arch::kUnknown;
    for(const auto& description:mint::architectureDescriptions())if(description.id==name)arch=description.architecture;
    if(arch!=mint::Arch::kAArch64 && arch!=mint::Arch::kX86_64 && arch!=mint::Arch::kX86_32 && arch!=mint::Arch::kArm32){mint::jni::throwIoException(env,"unsupported Mach-O slice architecture");return 0;}
    auto* session=new Session();const auto status=session->openMachOPath(mint::jni::fromJava(env,path),arch);
    if(!status.ok()){delete session;mint::jni::throwIoException(env,status.toString());return 0;}return reinterpret_cast<jlong>(session);
}
JNIEXPORT jlong JNICALL
Java_com_ccs_mint_core_MintSession_nativeOpenFd(JNIEnv* env, jclass, jint fd) {
    // The storage picker hands out a file descriptor with no path we are allowed
    // to open, so this is the path every user-chosen file actually takes.
    auto session = new Session();
    mint::Status status = session->openFd(fd);
    if (!status.ok()) {
        delete session;
        mint::jni::throwIoException(env, status.toString());
        return 0;
    }
    return reinterpret_cast<jlong>(session);
}

JNIEXPORT void JNICALL
Java_com_ccs_mint_core_MintSession_nativeClose(JNIEnv*, jclass, jlong handle) {
    delete asSession(handle);
}

JNIEXPORT jboolean JNICALL
Java_com_ccs_mint_core_MintSession_nativeAnalyze(JNIEnv* env, jclass, jlong handle) {
    Session* session = asSession(handle);
    if (session == nullptr) {
        mint::jni::throwIllegalState(env, "session is closed");
        return JNI_FALSE;
    }
    mint::Status status = session->analyze();
    if (!status.ok()) {
        mint::jni::throwIllegalState(env, status.toString());
        return JNI_FALSE;
    }
    return JNI_TRUE;
}

JNIEXPORT void JNICALL
Java_com_ccs_mint_core_MintSession_nativeCancel(JNIEnv*, jclass, jlong handle) {
    Session* session = asSession(handle);
    if (session != nullptr) session->requestCancel();
}

JNIEXPORT jint JNICALL
Java_com_ccs_mint_core_MintSession_nativeProgress(JNIEnv*, jclass, jlong handle) {
    Session* session = asSession(handle);
    return session == nullptr ? 0 : session->progress();
}

/// File and image metadata, as a single formatted description. Cheap enough to
/// build eagerly and it saves a dozen tiny accessors.
JNIEXPORT jstring JNICALL
Java_com_ccs_mint_core_MintSession_nativeImageSummary(JNIEnv* env, jclass, jlong handle) {
    Session* session = asSession(handle);
    if (session == nullptr) return mint::jni::toJava(env, "");

    std::string out;
    if (session->isDexLike()) {
        out += session->kind() == Session::InputKind::kApk ? "format=APK" : "format=DEX";
        out += "\narch=dalvik";
        out += "\nsize=" + std::to_string(session->file().size());
        out += "\nclasses=" + std::to_string(session->dex().classes().size());
        out += "\nmethods=" + std::to_string(session->dex().methods().size());
    } else {
        const mint::ElfImage& image = session->image();
        out += "format="+std::string(session->image().formatName())+"\narch=";
        out += mint::architectureName(image.arch());
        out += "\nsoname=" + (image.soname().empty() ? std::string("-") : image.soname());
        out += "\nentry=" + std::to_string(image.entryPoint());
        out += "\npie=" + std::string(image.isPositionIndependent() ? "yes" : "no");
        out += "\nstripped=" + std::string(image.isStripped() ? "yes" : "no");
        out += "\nsize=" + std::to_string(session->file().size());
        out += "\nsections=" + std::to_string(image.sections().size());
        out += "\nsymbols=" + std::to_string(image.symbols().size());
        out += "\nrelocations=" + std::to_string(image.relocations().size());
        out += "\nneeded=";
        for (size_t i = 0; i < image.neededLibraries().size(); ++i) {
            if (i != 0) out += ",";
            out += image.neededLibraries()[i];
        }
    }
    return mint::jni::toJava(env, out);
}

/// Analysis counters, written into a caller-provided array to avoid inventing a
/// Java class for eight numbers.
JNIEXPORT jint JNICALL
Java_com_ccs_mint_core_MintSession_nativeStats(JNIEnv* env, jclass, jlong handle,
                                               jlongArray out) {
    Session* session = asSession(handle);
    if (session == nullptr) return 0;

    auto values = mint::jni::longArray(env, out);
    if (!values.valid() || values.length() < 8) return 0;

    if (session->isDexLike()) {
        size_t instructions = 0;
        for (const mint::DexMethod& method : session->dex().methods()) instructions += method.code.size();
        values.data()[0] = static_cast<jlong>(instructions);
        values.data()[1] = static_cast<jlong>(session->dex().methods().size());
        values.data()[2] = static_cast<jlong>(session->dex().methods().size());
        values.data()[3] = 0;
        values.data()[4] = 0;
        values.data()[5] = 0;
        values.data()[6] = 0;
        values.data()[7] = 0;
        return 8;
    }
    const mint::CodeAnalyzer::Stats& stats = session->analyzer().stats();
    values.data()[0] = static_cast<jlong>(stats.instructions);
    values.data()[1] = static_cast<jlong>(stats.functions);
    values.data()[2] = static_cast<jlong>(stats.blocks);
    values.data()[3] = static_cast<jlong>(stats.edges);
    values.data()[4] = static_cast<jlong>(stats.indirectJumps);
    values.data()[5] = static_cast<jlong>(stats.undecodableSites);
    values.data()[6] = static_cast<jlong>(stats.incompleteFunctions);
    values.data()[7] = static_cast<jlong>(stats.functionsFromSweep);
    return 8;
}

JNIEXPORT jint JNICALL
Java_com_ccs_mint_core_MintSession_nativeFunctionCount(JNIEnv*, jclass, jlong handle) {
    Session* session = asSession(handle);
    if (session == nullptr) return 0;
    return static_cast<jint>(session->isDexLike() ? session->dex().methods().size()
                                                   : session->analyzer().functions().size());
}

/// One page of the function list. Returns how many rows were written.
JNIEXPORT jint JNICALL
Java_com_ccs_mint_core_MintSession_nativeFunctions(JNIEnv* env, jclass, jlong handle,
                                                  jint offset, jint limit,
                                                  jlongArray outEntry, jintArray outSize,
                                                  jintArray outBlocks, jintArray outInsns,
                                                  jintArray outFlags,
                                                  jobjectArray outNames) {
    Session* session = asSession(handle);
    if (session == nullptr || offset < 0 || limit <= 0) return 0;

    if (session->isDexLike()) {
        const std::vector<mint::DexMethod>& methods = session->dex().methods();
        if (static_cast<size_t>(offset) >= methods.size()) return 0;
        auto entries = mint::jni::longArray(env, outEntry);
        auto sizes = mint::jni::intArray(env, outSize);
        auto blocks = mint::jni::intArray(env, outBlocks);
        auto insns = mint::jni::intArray(env, outInsns);
        auto flags = mint::jni::intArray(env, outFlags);
        if (!entries.valid() || !sizes.valid() || !blocks.valid() || !insns.valid() || !flags.valid()) return 0;
        jint capacity = std::min(limit, entries.length());
        capacity = std::min(capacity, sizes.length()); capacity = std::min(capacity, blocks.length());
        capacity = std::min(capacity, insns.length()); capacity = std::min(capacity, flags.length());
        if (outNames != nullptr) capacity = std::min(capacity, env->GetArrayLength(outNames));
        const jint count = static_cast<jint>(std::min<size_t>(capacity, methods.size() - offset));
        for (jint i = 0; i < count; ++i) {
            const mint::DexMethod& method = methods[static_cast<size_t>(offset) + i];
            entries.data()[i] = static_cast<jlong>(Session::dexMethodAddress(static_cast<u32>(offset + i)));
            sizes.data()[i] = static_cast<jint>(method.code.size() * 2);
            blocks.data()[i] = method.code.empty() ? 0 : 1;
            insns.data()[i] = static_cast<jint>(method.code.size());
            flags.data()[i] = 0;
            if (outNames != nullptr) {
                jstring name = mint::jni::toJava(env, method.classDescriptor + "->" + method.name);
                env->SetObjectArrayElement(outNames, i, name); env->DeleteLocalRef(name);
            }
        }
        return count;
    }

    const std::vector<mint::Function>& functions = session->analyzer().functions();
    if (static_cast<size_t>(offset) >= functions.size()) return 0;

    auto entries = mint::jni::longArray(env, outEntry);
    auto sizes = mint::jni::intArray(env, outSize);
    auto blocks = mint::jni::intArray(env, outBlocks);
    auto insns = mint::jni::intArray(env, outInsns);
    auto flags = mint::jni::intArray(env, outFlags);
    if (!entries.valid() || !sizes.valid() || !blocks.valid() || !insns.valid() ||
        !flags.valid()) {
        return 0;
    }

    // Every output array bounds the page independently; take the smallest so a
    // mismatched caller cannot make us write past one of them.
    jint capacity = std::min(limit, entries.length());
    capacity = std::min(capacity, sizes.length());
    capacity = std::min(capacity, blocks.length());
    capacity = std::min(capacity, insns.length());
    capacity = std::min(capacity, flags.length());
    if (outNames != nullptr) {
        capacity = std::min(capacity, env->GetArrayLength(outNames));
    }
    if (capacity <= 0) return 0;

    const size_t available = functions.size() - static_cast<size_t>(offset);
    const jint count = static_cast<jint>(
        std::min<size_t>(static_cast<size_t>(capacity), available));

    for (jint i = 0; i < count; ++i) {
        const mint::Function& function = functions[static_cast<size_t>(offset) + i];
        entries.data()[i] = static_cast<jlong>(function.entry);
        sizes.data()[i] = static_cast<jint>(function.highAddress - function.lowAddress);
        blocks.data()[i] = static_cast<jint>(function.cfg.size());
        insns.data()[i] = static_cast<jint>(function.instructionCount());

        jint bits = 0;
        if (function.incomplete) bits |= kFlagIncomplete;
        if (function.indirectJumps != 0) bits |= kFlagHasIndirect;
        if (function.undecodableSites != 0) bits |= kFlagUndecodable;
        flags.data()[i] = bits;

        if (outNames != nullptr) {
            jstring name = mint::jni::toJava(env, session->displayNameAt(function.entry));
            env->SetObjectArrayElement(outNames, i, name);
            // Local refs are bounded by default (16 on old devices); a page of
            // several hundred names would exhaust the table without this.
            env->DeleteLocalRef(name);
        }
    }
    return count;
}

/// One page of the disassembly listing, starting at `startAddress` and walking
/// forward through decoded instructions.
JNIEXPORT jint JNICALL
Java_com_ccs_mint_core_MintSession_nativeListing(JNIEnv* env, jclass, jlong handle,
                                                jlong startAddress, jint limit,
                                                jlongArray outAddress, jintArray outSize,
                                                jintArray outFlow, jlongArray outTarget,
                                                jobjectArray outText,
                                                jobjectArray outComment) {
    Session* session = asSession(handle);
    if (session == nullptr || limit <= 0) return 0;

    if (session->isDexLike()) {
        const u32 index = Session::dexMethodIndex(static_cast<Address>(startAddress));
        const std::vector<mint::DexMethod>& methods = session->dex().methods();
        if (index >= methods.size()) return 0;
        const mint::DexMethod& method = methods[index];
        const Address entry = Session::dexMethodAddress(index);
        const Address requested = static_cast<Address>(startAddress);
        const u32 first = requested > entry ? static_cast<u32>((requested - entry) / 2) : 0;
        auto addresses = mint::jni::longArray(env, outAddress); auto sizes = mint::jni::intArray(env, outSize);
        auto flows = mint::jni::intArray(env, outFlow); auto targets = mint::jni::longArray(env, outTarget);
        if (!addresses.valid() || !sizes.valid() || !flows.valid() || !targets.valid()) return 0;
        jint capacity = std::min(limit, addresses.length()); capacity = std::min(capacity, sizes.length());
        capacity = std::min(capacity, flows.length()); capacity = std::min(capacity, targets.length());
        if (outText != nullptr) capacity = std::min(capacity, env->GetArrayLength(outText));
        if (outComment != nullptr) capacity = std::min(capacity, env->GetArrayLength(outComment));
        jint written = 0;
        for (u32 pc = first; written < capacity && pc < method.code.size(); ++pc, ++written) {
            const Address address = entry + pc * 2ull;
            addresses.data()[written] = static_cast<jlong>(address); sizes.data()[written] = 2;
            const Address branch = dexBranchTarget(method, pc);
            flows.data()[written] = branch == kNoAddress ? 0 : 1;
            targets.data()[written] = branch == kNoAddress ? -1 : static_cast<jlong>(entry + branch * 2ull);
            if (outText != nullptr) { jstring value = mint::jni::toJava(env, dexInstructionText(method.code[pc], method, pc)); env->SetObjectArrayElement(outText, written, value); env->DeleteLocalRef(value); }
            if (outComment != nullptr) { jstring value = mint::jni::toJava(env, ""); env->SetObjectArrayElement(outComment, written, value); env->DeleteLocalRef(value); }
        }
        return written;
    }

    const mint::CodeMap& code = session->analyzer().code();
    if (!code.finalized()) return 0;

    auto addresses = mint::jni::longArray(env, outAddress);
    auto sizes = mint::jni::intArray(env, outSize);
    auto flows = mint::jni::intArray(env, outFlow);
    auto targets = mint::jni::longArray(env, outTarget);
    if (!addresses.valid() || !sizes.valid() || !flows.valid() || !targets.valid()) {
        return 0;
    }

    jint capacity = std::min(limit, addresses.length());
    capacity = std::min(capacity, sizes.length());
    capacity = std::min(capacity, flows.length());
    capacity = std::min(capacity, targets.length());
    if (outText != nullptr) capacity = std::min(capacity, env->GetArrayLength(outText));
    if (outComment != nullptr) {
        capacity = std::min(capacity, env->GetArrayLength(outComment));
    }
    if (capacity <= 0) return 0;

    const auto rows = session->programListing(static_cast<Address>(startAddress),static_cast<size_t>(capacity));

    jint written = 0;
    for (; written < static_cast<jint>(rows.size()); ++written) {
        const auto& row = rows[written];
        addresses.data()[written] = static_cast<jlong>(row.address);
        sizes.data()[written] = row.size;
        flows.data()[written] = static_cast<jint>(row.flow);
        targets.data()[written] = static_cast<jlong>(row.target);

        if (outText != nullptr) {
            jstring value = mint::jni::toJava(env, row.text);
            env->SetObjectArrayElement(outText, written, value);
            env->DeleteLocalRef(value);
        }
        if (outComment != nullptr) {
            jstring value = mint::jni::toJava(env, row.comment);
            env->SetObjectArrayElement(outComment, written, value);
            env->DeleteLocalRef(value);
        }
    }
    return written;
}

/// The MintIR listing for the function containing `address`.
JNIEXPORT jstring JNICALL
Java_com_ccs_mint_core_MintSession_nativeFunctionIr(JNIEnv* env, jclass, jlong handle,
                                                   jlong address) {
    Session* session = asSession(handle);
    if (session == nullptr) return mint::jni::toJava(env, "");
    return mint::jni::toJava(env, session->irTextFor(static_cast<Address>(address)));
}

/// Warnings from every stage, newline-separated. Small and read once.
JNIEXPORT jstring JNICALL
Java_com_ccs_mint_core_MintSession_nativeWarnings(JNIEnv* env, jclass, jlong handle) {
    Session* session = asSession(handle);
    if (session == nullptr) return mint::jni::toJava(env, "");

    std::string out;
    for (const std::string& warning : session->allWarnings()) {
        if (!out.empty()) out += "\n";
        out += warning;
    }
    return mint::jni::toJava(env, out);
}

JNIEXPORT jstring JNICALL
Java_com_ccs_mint_core_MintSession_nativeDecompiledC(JNIEnv* env, jclass, jlong handle,
                                                     jlong address) {
    Session* session = asSession(handle);
    if (session == nullptr) return mint::jni::toJava(env, "");
    return mint::jni::toJava(env, session->decompiledCFor(static_cast<Address>(address)));
}

JNIEXPORT jstring JNICALL
Java_com_ccs_mint_core_MintSession_nativeFunctionCfg(JNIEnv* env, jclass, jlong handle,
                                                     jlong address) {
    Session* session = asSession(handle);
    if (session == nullptr) return mint::jni::toJava(env, "");
    return mint::jni::toJava(env, session->cfgTextFor(static_cast<Address>(address)));
}

JNIEXPORT jstring JNICALL
Java_com_ccs_mint_core_MintSession_nativeExportJson(JNIEnv* env, jclass, jlong handle) {
    Session* session = asSession(handle);
    if (session == nullptr) return mint::jni::toJava(env, "");
    return mint::jni::toJava(env, session->exportJsonText());
}

JNIEXPORT jstring JNICALL
Java_com_ccs_mint_core_MintSession_nativeXrefs(JNIEnv* env, jclass, jlong handle,
                                              jlong address) {
    Session* session = asSession(handle);
    if (session == nullptr) return mint::jni::toJava(env, "");
    return mint::jni::toJava(env, session->xrefsText(static_cast<Address>(address)));
}

JNIEXPORT jstring JNICALL
Java_com_ccs_mint_core_MintSession_nativeStrings(JNIEnv* env, jclass, jlong handle,
                                                jlong functionAddress) {
    Session* session = asSession(handle);
    if (session == nullptr) return mint::jni::toJava(env, "");
    return mint::jni::toJava(
        env, session->stringsText(static_cast<Address>(functionAddress)));
}

JNIEXPORT jstring JNICALL
Java_com_ccs_mint_core_MintSession_nativeProgramPrototypes(JNIEnv* env, jclass, jlong handle) {
    Session* session = asSession(handle);
    if (session == nullptr) return mint::jni::toJava(env, "");
    return mint::jni::toJava(env, session->programPrototypesText());
}

JNIEXPORT jstring JNICALL
Java_com_ccs_mint_core_MintSession_nativeProgramCoverage(JNIEnv* env, jclass, jlong handle) {
    Session* session = asSession(handle);
    if (session == nullptr) return mint::jni::toJava(env, "");
    return mint::jni::toJava(env, session->programCoverageText());
}

JNIEXPORT jstring JNICALL
Java_com_ccs_mint_core_MintSession_nativeProgramWrites(JNIEnv* env, jclass, jlong handle) {
    Session* session = asSession(handle);
    if (session == nullptr) return mint::jni::toJava(env, "");
    return mint::jni::toJava(env, session->programWriteSummaryText());
}

JNIEXPORT jstring JNICALL
Java_com_ccs_mint_core_MintSession_nativeWriteMap(JNIEnv* env, jclass, jlong handle,
                                                 jlong address) {
    Session* session = asSession(handle);
    if (session == nullptr) return mint::jni::toJava(env, "");
    return mint::jni::toJava(env, session->writeMapText(static_cast<Address>(address)));
}

JNIEXPORT jstring JNICALL
Java_com_ccs_mint_core_MintSession_nativeCallGraph(JNIEnv* env, jclass, jlong handle) {
    Session* session = asSession(handle);
    if (session == nullptr) return mint::jni::toJava(env, "");
    return mint::jni::toJava(env, session->callGraphText());
}

JNIEXPORT void JNICALL
Java_com_ccs_mint_core_MintSession_nativeProject(JNIEnv* env,jclass,jlong handle,jstring path) {
    auto* session=asSession(handle);
    if (!session) {mint::jni::throwIllegalState(env,"session is closed");return;}
    const auto status=session->attachProject(mint::jni::fromJava(env,path));
    if (!status.ok()) mint::jni::throwIoException(env,status.toString());
}
JNIEXPORT void JNICALL
Java_com_ccs_mint_core_MintSession_nativeEdit(JNIEnv* env,jclass,jlong handle,jlong address,jstring kind,jstring value) {
    auto* session=asSession(handle);
    if (!session) {mint::jni::throwIllegalState(env,"session is closed");return;}
    auto status=session->editAnnotation(static_cast<Address>(address),mint::jni::fromJava(env,kind),mint::jni::fromJava(env,value));
    if (!status.ok()) mint::jni::throwIllegalArgument(env,status.toString());
}
JNIEXPORT void JNICALL
Java_com_ccs_mint_core_MintSession_nativeUndo(JNIEnv* env,jclass,jlong handle,jboolean redo) {
    auto* session=asSession(handle);
    if (!session) {mint::jni::throwIllegalState(env,"session is closed");return;}
    auto status=session->undoEdit(redo);
    if (!status.ok()) mint::jni::throwIllegalState(env,status.toString());
}
JNIEXPORT jstring JNICALL
Java_com_ccs_mint_core_MintSession_nativeAnnotation(JNIEnv* env,jclass,jlong handle,jlong address,jstring kind) {
    auto* session=asSession(handle);
    return mint::jni::toJava(env,session ? session->annotation(static_cast<Address>(address),mint::jni::fromJava(env,kind)) : "");
}
JNIEXPORT jstring JNICALL
Java_com_ccs_mint_core_MintSession_nativeSearch(JNIEnv* env,jclass,jlong handle,jstring query) {
    auto* session=asSession(handle);
    return mint::jni::toJava(env,session ? session->searchText(mint::jni::fromJava(env,query)) : "");
}
JNIEXPORT jstring JNICALL
Java_com_ccs_mint_core_MintSession_nativeReferences(JNIEnv* env,jclass,jlong handle,jlong address) {
    auto* session=asSession(handle);
    return mint::jni::toJava(env,session ? session->referencesText(static_cast<Address>(address)) : "");
}
JNIEXPORT jstring JNICALL
Java_com_ccs_mint_core_MintSession_nativeProgramInfo(JNIEnv* env,jclass,jlong handle,jint kind,jlong address) {
    auto* session=asSession(handle);if(!session)return mint::jni::toJava(env,"");
    return mint::jni::toJava(env,kind==0?session->typesText():kind==1?session->memoryBlocksText():kind==2?session->provenanceText(static_cast<Address>(address)):kind==4?session->debugInfoText():kind==5?session->sourceLocationText(static_cast<Address>(address)):kind==6?session->typesCHeaderText():kind==7?session->interproceduralText():mint::cxxMetadataText(session->image()));
}
JNIEXPORT jstring JNICALL
Java_com_ccs_mint_core_MintSession_nativeScript(JNIEnv* env,jclass,jlong handle,jstring source,jboolean allowEdits) {
    auto* session=asSession(handle);if(!session){mint::jni::throwIllegalState(env,"session is closed");return nullptr;}
    std::string output;const auto status=session->runScript(mint::jni::fromJava(env,source),allowEdits,&output);
    if(!status.ok())output+="\n[Script stopped: "+status.toString()+"]\n";
    return mint::jni::toJava(env,output);
}
JNIEXPORT jstring JNICALL
Java_com_ccs_mint_core_MintSession_nativeAssemble(JNIEnv* env,jclass,jlong handle,jlong address,jstring source,jboolean apply) {
    auto* session=asSession(handle);if(!session){mint::jni::throwIllegalState(env,"session is closed");return nullptr;}
    std::string bytes;const auto status=session->assembleAt(static_cast<Address>(address),mint::jni::fromJava(env,source),apply,&bytes);
    if(!status.ok()){mint::jni::throwIllegalArgument(env,status.toString());return nullptr;}
    return mint::jni::toJava(env,bytes);
}
JNIEXPORT jstring JNICALL
Java_com_ccs_mint_core_MintSession_nativePower(JNIEnv* env,jclass,jlong handle,jstring operation,jstring text,jstring arguments,jlong address,jlong value,jboolean flag) {
    auto* session=asSession(handle);if(!session){mint::jni::throwIllegalState(env,"session is closed");return nullptr;}
    const auto op=mint::jni::fromJava(env,operation),first=mint::jni::fromJava(env,text),second=mint::jni::fromJava(env,arguments);
    std::string output;mint::Status status=mint::Status::success();
    if(op=="plugin-load") {status=session->loadPlugin(first,flag);if(status.ok())output=session->pluginCommandsText();}
    else if(op=="local-list")output=session->localVariablesText(static_cast<Address>(address));
    else if(op=="abi")output=session->abiText(static_cast<Address>(address));
    else if(op=="debug-import"){status=session->importExternalDebug(first,flag);if(status.ok())output=session->debugInfoText();}
    else if(op=="local-edit") {
        const auto split=second.find('\n');
        if(split==std::string::npos || second.find('\n',split+1)!=std::string::npos)
            status=mint::Status::error(mint::ErrorCode::kBadFormat,"invalid local edit payload");
        else status=session->editLocalVariable(static_cast<Address>(address),first,second.substr(0,split),second.substr(split+1));
    }
    else if(op=="plugin-list")output=session->pluginCommandsText();
    else if(op=="library-import") {status=session->importLibrary(first,flag);if(status.ok())output=flag?session->signatureLibraryText():session->typesText();}
    else if(op=="library-signatures")output=session->signatureLibraryText();
    else if(op=="plugin-run")status=session->runPlugin(first,second,flag,&output);
    else if(op=="debug-connect") {
        if(value<1 || value>65535)status=mint::Status::error(mint::ErrorCode::kBadFormat,"port must be 1..65535");
        else {status=session->connectDebugger(first,static_cast<mint::u32>(value),second=="dap",flag);if(status.ok())status=session->debuggerCommand("status",0,0,&output);}
    } else if(op=="debug")status=session->debuggerCommand(first,static_cast<Address>(address),static_cast<mint::u64>(value),&output);
    else if(op=="compare-open") {
        status=session->openComparison(first,second);
        if(status.ok())status=session->comparisonCommand("diff",0,0,"",&output);
    } else if(op=="compare-open-raw") {
        status=session->openComparison(first,second,session->image().arch(),session->image().imageBase(),session->image().entryPoint());
        if(status.ok())status=session->comparisonCommand("diff",0,0,"",&output);
    } else if(op=="compare-open-macho") {
        status=session->openComparison(first,second,session->image().arch(),0,0,true);
        if(status.ok())status=session->comparisonCommand("diff",0,0,"",&output);
    } else if(op=="compare")status=session->comparisonCommand(first,static_cast<Address>(address),static_cast<Address>(value),second,&output);
    else status=mint::Status::error(mint::ErrorCode::kBadFormat,"unknown power-user operation");
    if(!status.ok()){mint::jni::throwIllegalState(env,status.toString());return nullptr;}
    return mint::jni::toJava(env,output);
}
JNIEXPORT void JNICALL
Java_com_ccs_mint_core_MintSession_nativeType(JNIEnv* env,jclass,jlong handle,jstring declaration,jboolean erase) {
    auto* session=asSession(handle);if(!session){mint::jni::throwIllegalState(env,"session is closed");return;}
    auto status=erase?session->eraseType(mint::jni::fromJava(env,declaration)):session->defineType(mint::jni::fromJava(env,declaration));
    if(!status.ok())mint::jni::throwIllegalArgument(env,status.toString());
}
JNIEXPORT void JNICALL
Java_com_ccs_mint_core_MintSession_nativeReanalyze(JNIEnv* env,jclass,jlong handle) {
    auto* session=asSession(handle);if(!session){mint::jni::throwIllegalState(env,"session is closed");return;}
    auto status=session->reanalyze();if(!status.ok())mint::jni::throwIllegalState(env,status.toString());
}
JNIEXPORT void JNICALL
Java_com_ccs_mint_core_MintSession_nativeExportPatched(JNIEnv* env,jclass,jlong handle,jstring path) {
    auto* session=asSession(handle);if(!session){mint::jni::throwIllegalState(env,"session is closed");return;}
    auto status=session->exportPatchedCopy(mint::jni::fromJava(env,path));if(!status.ok())mint::jni::throwIoException(env,status.toString());
}
}  // extern "C"
