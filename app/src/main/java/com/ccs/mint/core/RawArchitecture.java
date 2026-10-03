package com.ccs.mint.core;

import java.util.HashSet;
import java.util.Set;

/** Immutable decoder metadata. Constructing/validating it never loads JNI. */
public final class RawArchitecture {
    /** Seven builtins plus all127 custom numeric IDs128..254. */
    public static final int MAX_DESCRIPTORS = 134;
    public final String id, name;
    public final int numericId, pointerSize, minimumInstructionSize, maximumInstructionSize, instructionAlignment;
    public final boolean thumbAddressTag;
    public final boolean hasLifter;

    public RawArchitecture(String id, String name, int numericId, int pointerSize,
            int minimumInstructionSize, int maximumInstructionSize, int instructionAlignment,
            boolean thumbAddressTag) {
        this(id,name,numericId,pointerSize,minimumInstructionSize,maximumInstructionSize,instructionAlignment,thumbAddressTag,numericId<128);
    }
    public RawArchitecture(String id, String name, int numericId, int pointerSize,
            int minimumInstructionSize, int maximumInstructionSize, int instructionAlignment,
            boolean thumbAddressTag,boolean hasLifter) {
        if (id == null || !id.matches("[a-z0-9_-]{1,64}") || name == null || name.isEmpty() || name.length() > 128 ||
                numericId <= 0 || numericId >= 255 || (pointerSize != 4 && pointerSize != 8) ||
                minimumInstructionSize <= 0 || minimumInstructionSize > maximumInstructionSize || maximumInstructionSize > 16 ||
                instructionAlignment <= 0 || instructionAlignment > minimumInstructionSize ||
                (instructionAlignment & (instructionAlignment - 1)) != 0 ||
                (thumbAddressTag && numericId != 4 && numericId != 5)) {
            throw new IllegalArgumentException("Invalid raw decoder descriptor");
        }
        for (int i = 0; i < name.length(); i++) if (name.charAt(i) < 32 || name.charAt(i) == 127)
            throw new IllegalArgumentException("Invalid raw decoder display name");
        this.id = id; this.name = name; this.numericId = numericId; this.pointerSize = pointerSize;
        this.minimumInstructionSize = minimumInstructionSize; this.maximumInstructionSize = maximumInstructionSize;
        this.instructionAlignment = instructionAlignment; this.thumbAddressTag = thumbAddressTag;
        this.hasLifter=hasLifter;
    }

    public boolean sameAbi(RawArchitecture other) {
        return other != null && id.equals(other.id) && numericId == other.numericId && pointerSize == other.pointerSize &&
                minimumInstructionSize == other.minimumInstructionSize && maximumInstructionSize == other.maximumInstructionSize &&
                instructionAlignment == other.instructionAlignment && thumbAddressTag == other.thumbAddressTag;
    }

    static RawArchitecture[] fromNativeMetadata(String[] fields) {
        if (fields == null || fields.length % 9 != 0 || fields.length > MAX_DESCRIPTORS * 9)
            throw new IllegalStateException("Invalid native architecture registry snapshot");
        RawArchitecture[] result = new RawArchitecture[fields.length / 9];
        Set<String> ids = new HashSet<>(); Set<Integer> numericIds = new HashSet<>();
        try {
            for (int i = 0; i < result.length; i++) {
                int at = i * 9;
                if (!"0".equals(fields[at + 8]) && !"1".equals(fields[at + 8]))
                    throw new IllegalArgumentException("Invalid Thumb address flag");
                result[i] = new RawArchitecture(fields[at], fields[at + 1], Integer.parseInt(fields[at + 2]),
                        Integer.parseInt(fields[at + 3]), Integer.parseInt(fields[at + 4]), Integer.parseInt(fields[at + 5]),
                        Integer.parseInt(fields[at + 6]), "1".equals(fields[at + 8]),!"1".equals(fields[at+7]));
                if (!ids.add(result[i].id) || !numericIds.add(result[i].numericId))
                    throw new IllegalArgumentException("Duplicate native decoder identity");
                // Field7: builtin0, external decoder-only1, external semantic lifter2.
                if (!"0".equals(fields[at + 7]) && !"1".equals(fields[at + 7]) && !"2".equals(fields[at+7]))
                    throw new IllegalArgumentException("Invalid decoder capability flag");
                if (!"0".equals(fields[at + 7]) != (result[i].numericId >= 128))
                    throw new IllegalArgumentException("Invalid external decoder identity");
            }
        } catch (IllegalArgumentException exception) {
            throw new IllegalStateException("Invalid native architecture registry snapshot", exception);
        }
        return result;
    }
}
