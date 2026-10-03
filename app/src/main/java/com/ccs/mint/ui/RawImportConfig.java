package com.ccs.mint.ui;

import java.util.Locale;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import com.ccs.mint.core.RawArchitecture;

/** Explicit native import configuration: raw memory map or selected Mach-O slice. */
public final class RawImportConfig {
    private static Map<String, RawArchitecture> builtins() {
        Map<String, RawArchitecture> result = new LinkedHashMap<>();
        RawArchitecture[] values = {
                new RawArchitecture("aarch64", "AArch64", 1, 8, 4, 4, 4, false),
                new RawArchitecture("x86-64", "x86-64", 2, 8, 1, 15, 1, false),
                new RawArchitecture("arm", "ARM (A32)", 4, 4, 4, 4, 4, true),
                new RawArchitecture("thumb", "ARM Thumb/Thumb-2", 5, 4, 2, 4, 2, true),
                new RawArchitecture("x86-32", "x86 (IA-32)", 6, 4, 1, 15, 1, false),
                new RawArchitecture("riscv32", "RISC-V RV32GC", 7, 4, 2, 4, 2, false),
                new RawArchitecture("riscv64", "RISC-V RV64GC", 8, 8, 2, 4, 2, false)};
        for (RawArchitecture value : values) result.put(value.id, value);
        return result;
    }
    private static volatile Map<String, RawArchitecture> registered = Collections.unmodifiableMap(builtins());

    /** Replaces the explicit process-only snapshot atomically. No native call,
     * automatic plugin loading, persistence, or acceptance of guessed metadata. */
    public static synchronized void installArchitectures(RawArchitecture[] descriptors) {
        if (descriptors == null || descriptors.length > RawArchitecture.MAX_DESCRIPTORS) throw new IllegalArgumentException("Invalid decoder registry snapshot");
        Map<String, RawArchitecture> next = builtins(); Set<String> seen = new HashSet<>();
        for (RawArchitecture descriptor : descriptors) {
            if (descriptor == null || !seen.add(descriptor.id)) throw new IllegalArgumentException("Duplicate or missing decoder descriptor");
            RawArchitecture builtin = next.get(descriptor.id);
            if (builtin != null && !builtin.sameAbi(descriptor)) throw new IllegalArgumentException("Built-in decoder ABI cannot be replaced");
            if (builtin == null && descriptor.numericId < 128) throw new IllegalArgumentException("Unknown built-in decoder identity");
            for (RawArchitecture value : next.values()) if (!value.id.equals(descriptor.id) && value.numericId == descriptor.numericId)
                throw new IllegalArgumentException("Duplicate decoder numeric identity");
            next.put(descriptor.id, descriptor);
        }
        registered = Collections.unmodifiableMap(next);
    }
    public final String architecture;
    public final long baseAddress;
    public final long entryAddress;
    public final boolean machOSlice;

    public RawImportConfig(String architecture, long baseAddress, long entryAddress) {
        if (architecture == null) throw new IllegalArgumentException("Select a raw architecture");
        String normalized = architecture.trim().toLowerCase(Locale.ROOT);
        boolean slice=normalized.startsWith("macho:");if(slice)normalized=normalized.substring(6);
        Map<String, RawArchitecture> snapshot = registered;
        if (!snapshot.containsKey(normalized)) {
            if (normalized.equals("arm64")) normalized = "aarch64";
            if (normalized.equals("x86_64") || normalized.equals("amd64")) normalized = "x86-64";
            if (normalized.equals("arm32")) normalized = "arm";
            if (normalized.equals("x86") || normalized.equals("i386") || normalized.equals("x86_32")) normalized = "x86-32";
            if (normalized.equals("rv32")) normalized = "riscv32";
            if (normalized.equals("rv64")) normalized = "riscv64";
        }
        RawArchitecture descriptor = snapshot.get(normalized);
        if (descriptor == null) throw new IllegalArgumentException("Raw decoder is not registered; explicitly reload its trusted plugin first");
        if(slice && (!normalized.equals("aarch64") && !normalized.equals("x86-64") && !normalized.equals("x86-32") && !normalized.equals("arm") || baseAddress!=0 || entryAddress!=0))throw new IllegalArgumentException("Mach-O slice selection requires a supported CPU and container-provided addresses");
        long canonicalEntry = descriptor.thumbAddressTag ? entryAddress & ~1L : entryAddress;
        if (Long.compareUnsigned(canonicalEntry, baseAddress) < 0) {
            throw new IllegalArgumentException("Entry address must be at or above the base address");
        }
        int alignment = descriptor.thumbAddressTag && (entryAddress & 1) != 0 ? 2 : descriptor.instructionAlignment;
        if ((canonicalEntry & (alignment - 1L)) != 0 || (descriptor.thumbAddressTag && (baseAddress & 1) != 0))
            throw new IllegalArgumentException("Entry address must align to " + alignment + " bytes (ARM mappings also require an even base)");
        if(descriptor.pointerSize == 4 && (Long.compareUnsigned(baseAddress,0xffffffffL)>0 || Long.compareUnsigned(entryAddress,0xffffffffL)>0))
            throw new IllegalArgumentException("32-bit decoder requires 32-bit addresses");
        this.architecture = (slice?"macho:":"")+normalized;this.machOSlice=slice;
        this.baseAddress = baseAddress;
        this.entryAddress = entryAddress;
    }
    public static RawImportConfig machOSlice(String architecture){return new RawImportConfig("macho:"+architecture,0,0);}
    public String decoderId(){return machOSlice?architecture.substring(6):architecture;}
    public com.ccs.mint.core.MintSession open(String path)throws java.io.IOException {
        return machOSlice?com.ccs.mint.core.MintSession.openMachO(path,decoderId()):com.ccs.mint.core.MintSession.openRaw(path,architecture,baseAddress,entryAddress);
    }

    /** Addresses are hexadecimal, optionally prefixed by 0x, across all 64 bits. */
    public static RawImportConfig fromHex(String architecture, String base, String entry) {
        return new RawImportConfig(architecture, parseAddress(base, "Base"), parseAddress(entry, "Entry"));
    }

    private static long parseAddress(String text, String label) {
        if (text == null) throw new IllegalArgumentException(label + " address is required");
        String digits = text.trim();
        if (digits.startsWith("0x") || digits.startsWith("0X")) digits = digits.substring(2);
        if (digits.isEmpty() || digits.length() > 16 || !digits.matches("[0-9a-fA-F]+")) {
            throw new IllegalArgumentException(label + " address must be a 64-bit hexadecimal value");
        }
        try {
            return Long.parseUnsignedLong(digits, 16);
        } catch (NumberFormatException exception) {
            throw new IllegalArgumentException(label + " address must be a 64-bit hexadecimal value", exception);
        }
    }

    /** Stable identity fragment keeps alternate mappings of identical bytes separate. */
    String projectSuffix() {
        if(machOSlice)return "-macho-"+decoderId();
        return "-raw-" + architecture + "-" + Long.toUnsignedString(baseAddress, 16) +
                "-" + Long.toUnsignedString(entryAddress, 16);
    }

    public String describe() {
        if(machOSlice)return "Mach-O slice "+decoderId()+"; addresses from container";
        return "raw " + architecture + "; base 0x" + Long.toUnsignedString(baseAddress, 16) +
                "; entry 0x" + Long.toUnsignedString(entryAddress, 16);
    }
}
