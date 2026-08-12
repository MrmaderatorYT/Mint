package com.ccs.mint.core;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.io.Closeable;
import java.io.IOException;

/**
 * An open binary and the analysis derived from it.
 *
 * <p>Holds a handle to native state; {@link #close()} is what releases the file
 * mapping and every analysis structure, so a session must be closed even if
 * nothing went wrong. It is not thread-safe: run analysis on a background thread
 * and read results from one thread at a time.
 *
 * <p>Bulk results are read into caller-supplied arrays rather than returned as
 * object lists. That shape exists because a large library holds several hundred
 * thousand instructions: the UI shows a screenful at a time, and one JNI
 * crossing per screenful is the difference between scrolling smoothly and not.
 */
public final class MintSession implements Closeable {

    /** Bit flags in the {@code flags} column of {@link #functions}. */
    public static final int FLAG_INCOMPLETE = 1;
    public static final int FLAG_HAS_INDIRECT = 1 << 1;
    public static final int FLAG_UNDECODABLE = 1 << 2;

    /** Indices into the array filled by {@link #stats(long[])}. */
    public static final int STAT_INSTRUCTIONS = 0;
    public static final int STAT_FUNCTIONS = 1;
    public static final int STAT_BLOCKS = 2;
    public static final int STAT_EDGES = 3;
    public static final int STAT_INDIRECT_JUMPS = 4;
    public static final int STAT_UNDECODABLE = 5;
    public static final int STAT_INCOMPLETE_FUNCTIONS = 6;
    public static final int STAT_SWEEP_FUNCTIONS = 7;
    public static final int STAT_COUNT = 8;

    private long handle;

    private MintSession(long handle) {
        this.handle = handle;
    }

    /**
     * Opens a file by path. Only usable for files the app itself owns — anything
     * the user picked arrives as a descriptor, so use {@link #open(ParcelFileDescriptor)}
     * for those.
     */
    @NonNull
    public static MintSession open(@NonNull String path) throws IOException {
        NativeCore.load();
        long handle = nativeOpenPath(path);
        if (handle == 0) {
            throw new IOException("could not open " + path);
        }
        return new MintSession(handle);
    }

    /**
     * Opens an already-open file descriptor — how a file chosen through the
     * storage picker arrives, since a SAF document has no path the app may open.
     * Pass {@code ParcelFileDescriptor.getFd()}.
     *
     * <p>Takes an int rather than a {@code ParcelFileDescriptor} so this class
     * stays free of Android types: the engine facade is then exercisable on a
     * desktop JVM, which is where the JNI marshalling gets tested.
     *
     * <p>The descriptor stays owned by the caller. The native side maps it, and
     * the mapping outlives the descriptor being closed.
     */
    @NonNull
    public static MintSession openDescriptor(int fd) throws IOException {
        NativeCore.load();
        long handle = nativeOpenFd(fd);
        if (handle == 0) {
            throw new IOException("could not map the selected file");
        }
        return new MintSession(handle);
    }

    /**
     * Loads and disassembles. Expensive — seconds on a large library — so call it
     * off the main thread.
     */
    public void analyze() {
        checkOpen();
        nativeAnalyze(handle);
    }

    /** Requests a cooperative stop. The native handle remains valid until the
     * worker that is currently using it has returned. */
    public void cancelAnalysis() {
        if (handle != 0) nativeCancel(handle);
    }

    /** Analysis progress from 0 to 100; safe to poll while analyze() runs. */
    public int progress() {
        checkOpen();
        return nativeProgress(handle);
    }

    /** Newline-separated {@code key=value} description of the loaded image. */
    @NonNull
    public String imageSummary() {
        checkOpen();
        return nativeImageSummary(handle);
    }

    /**
     * Fills {@code out} with the analysis counters; see the {@code STAT_*}
     * indices. {@code out} must hold at least {@link #STAT_COUNT} elements.
     */
    public void stats(@NonNull long[] out) {
        checkOpen();
        if (out.length < STAT_COUNT) {
            throw new IllegalArgumentException("stats array must hold " + STAT_COUNT);
        }
        nativeStats(handle, out);
    }

    public int functionCount() {
        checkOpen();
        return nativeFunctionCount(handle);
    }

    /**
     * Reads one page of the function list into the given columns, and returns how
     * many rows were written. Every array bounds the page, so the shortest one
     * wins; passing {@code null} for {@code names} skips building the strings,
     * which is worth doing when only the counts are needed.
     */
    public int functions(int offset, int limit, @NonNull long[] entry, @NonNull int[] size,
                        @NonNull int[] blocks, @NonNull int[] instructions,
                        @NonNull int[] flags, @Nullable String[] names) {
        checkOpen();
        return nativeFunctions(handle, offset, limit, entry, size, blocks, instructions,
                flags, names);
    }

    /**
     * Reads one page of the disassembly listing starting at {@code startAddress},
     * and returns how many rows were written. {@code target} holds -1 where an
     * instruction has no statically known branch target.
     */
    public int listing(long startAddress, int limit, @NonNull long[] address,
                       @NonNull int[] size, @NonNull int[] flow, @NonNull long[] target,
                       @Nullable String[] text, @Nullable String[] comment) {
        checkOpen();
        return nativeListing(handle, startAddress, limit, address, size, flow, target,
                text, comment);
    }

    /**
     * The MintIR listing for the function containing {@code address}.
     *
     * <p>Lifted on demand rather than cached: one function costs well under a
     * millisecond, while IR for a whole library would be tens of megabytes of heap
     * for something only one screen reads.
     */
    @NonNull
    public String functionIr(long address) {
        checkOpen();
        return nativeFunctionIr(handle, address);
    }

    /** SSA-backed pseudo-C for the function containing {@code address}. */
    @NonNull
    public String decompiledC(long address) {
        checkOpen();
        return nativeDecompiledC(handle, address);
    }

    /** Compact CFG rows: {@code blockId start end successorId...}. */
    @NonNull
    public String cfg(long address) {
        checkOpen();
        return nativeFunctionCfg(handle, address);
    }

    /**
     * The program's call graph as {@code index entry calleeIndex...} rows, one per
     * function, where every index is a position in the list {@link #functions} pages
     * out. Direct calls only — an indirect call is left out rather than guessed.
     *
     * <p>Whole-program, so it is a single crossing rather than a paged one: the text
     * is a few hundred kilobytes for a large library, which is cheaper to move once
     * than to assemble from thousands of per-function queries.
     */
    @NonNull
    public String callGraph() {
        checkOpen();
        return nativeCallGraph(handle);
    }

    /**
     * Structural problems found while loading and analysing, newline-separated.
     * Worth showing: a library whose section table disagrees with its program
     * headers has usually been through a protector.
     */
    @NonNull
    public String warnings() {
        checkOpen();
        return nativeWarnings(handle);
    }

    public boolean isOpen() {
        return handle != 0;
    }

    @Override
    public void close() {
        if (handle != 0) {
            nativeClose(handle);
            handle = 0;
        }
    }

    private void checkOpen() {
        if (handle == 0) {
            throw new IllegalStateException("session is closed");
        }
    }

    private static native long nativeOpenPath(String path);

    private static native long nativeOpenFd(int fd);

    private static native void nativeClose(long handle);

    private static native boolean nativeAnalyze(long handle);

    private static native void nativeCancel(long handle);

    private static native int nativeProgress(long handle);

    private static native String nativeImageSummary(long handle);

    private static native int nativeStats(long handle, long[] out);

    private static native int nativeFunctionCount(long handle);

    private static native int nativeFunctions(long handle, int offset, int limit,
                                              long[] entry, int[] size, int[] blocks,
                                              int[] instructions, int[] flags,
                                              String[] names);

    private static native int nativeListing(long handle, long startAddress, int limit,
                                            long[] address, int[] size, int[] flow,
                                            long[] target, String[] text,
                                            String[] comment);

    private static native String nativeFunctionIr(long handle, long address);

    private static native String nativeDecompiledC(long handle, long address);

    private static native String nativeFunctionCfg(long handle, long address);

    private static native String nativeCallGraph(long handle);

    private static native String nativeWarnings(long handle);
}
