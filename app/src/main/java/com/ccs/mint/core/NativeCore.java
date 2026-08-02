package com.ccs.mint.core;

/**
 * Entry point to the native analysis engine.
 *
 * <p>All heavy work — loading, disassembly, lifting, decompilation — happens in
 * C++. The Java side holds handles and never touches instructions one at a
 * time: a per-instruction JNI crossing would dominate the cost of analysing a
 * library with half a million of them, so results always come back in batches.
 */
public final class NativeCore {

    private static volatile boolean loaded;
    private static volatile UnsatisfiedLinkError loadFailure;

    private NativeCore() {}

    /**
     * Loads {@code libmintcore.so}. Safe to call repeatedly; the first failure
     * is remembered and rethrown so callers see the original error rather than
     * a confusing "already failed" state.
     */
    public static synchronized void load() {
        if (loaded) {
            return;
        }
        if (loadFailure != null) {
            throw loadFailure;
        }
        try {
            System.loadLibrary("mintcore");
            loaded = true;
        } catch (UnsatisfiedLinkError error) {
            loadFailure = error;
            throw error;
        }
    }

    public static boolean isLoaded() {
        return loaded;
    }

    /**
     * Engine and decoder versions, for the about screen and for bug reports.
     * Also the cheapest end-to-end proof that the native library loaded and its
     * statically linked disassembler decoders are present.
     */
    public static String engineInfo() {
        load();
        return nativeEngineInfo();
    }

    private static native String nativeEngineInfo();
}
