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

    /** Process-local registry, including explicitly loaded decoder plugins.
     * Does not discover or load any extension library from disk. */
    @NonNull
    public static RawArchitecture[] rawArchitectures() {
        NativeCore.load();
        return RawArchitecture.fromNativeMetadata(nativeRawArchitectures());
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
    @NonNull
    public static MintSession openRaw(String path,String architecture,long base,long entry) throws IOException {
        NativeCore.load();long handle=nativeOpenRaw(path,architecture,base,entry);
        if(handle==0)throw new IOException("could not import raw binary");
        return new MintSession(handle);
    }
    public static MintSession openMachO(String path,String architecture)throws IOException {
        NativeCore.load();long handle=nativeOpenMachO(path,architecture);if(handle==0)throw new IOException("Cannot open selected Mach-O slice");return new MintSession(handle);
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

    /** Schema version of {@link #exportJson()}; bumped when a field changes meaning. */
    public static final int JSON_SCHEMA = 1;

    /**
     * The analysis as JSON — functions, sizes, block and instruction counts, and the
     * call edges between them, for a tool outside Mint to read.
     *
     * <p>The document carries its own {@code schema} field. A consumer that checks it
     * can refuse a file it does not understand rather than misreading one.
     */
    @NonNull
    public String exportJson() {
        checkOpen();
        return nativeExportJson(handle);
    }

    /**
     * Who calls the function containing {@code address}, with the address of each
     * call site, and what it calls. Direct calls only.
     */
    @NonNull
    public String xrefs(long address) {
        checkOpen();
        return nativeXrefs(handle, address);
    }

    /**
     * Printable strings in the image with their addresses, grouped by segment. Pass
     * a function's address to list only what that function refers to, or 0 for the
     * whole image.
     */
    @NonNull
    public String strings(long functionAddress) {
        checkOpen();
        return nativeStrings(handle, functionAddress);
    }

    /**
     * The program as a C header — one prototype per function, taken from the same
     * emitter that writes the bodies. Expensive the first time (it decompiles), and
     * cached afterwards.
     */
    @NonNull
    public String programPrototypes() {
        checkOpen();
        return nativeProgramPrototypes(handle);
    }

    /**
     * Lifter coverage across the program: how much became real IR rather than
     * intrinsics, and which opcodes account for the rest. Expensive the first time —
     * it lifts the program — and cached afterwards, so call it off the main thread.
     */
    @NonNull
    public String programCoverage() {
        checkOpen();
        return nativeProgramCoverage(handle);
    }

    /** Which functions write the most, program-wide. Shares the pass with {@link #programCoverage()}. */
    @NonNull
    public String programWrites() {
        checkOpen();
        return nativeProgramWrites(handle);
    }

    /**
     * A map of the memory the function containing {@code address} writes: every
     * store placed against a base and a byte offset, with a density bar per slot.
     *
     * <p>Answers what a function modifies, which is what separates a pure helper
     * from something with side effects. Counts are static — a store inside a loop
     * counts once, because this reads the code rather than running it.
     */
    @NonNull
    public String writeMap(long address) {
        checkOpen();
        return nativeWriteMap(handle, address);
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

    /** Calls must use the workspace's serial worker, as with analysis/listing. */
    public void attachProject(String path) { checkOpen(); nativeProject(handle,path); }
    public void edit(long address,String kind,String value) { checkOpen(); nativeEdit(handle,address,kind,value); }
    public String annotation(long address,String kind) { checkOpen(); return nativeAnnotation(handle,address,kind); }
    public void undoEdit(boolean redo) { checkOpen(); nativeUndo(handle,redo); }
    public String search(String query) { checkOpen(); return nativeSearch(handle,query); }
    public String references(long address) { checkOpen(); return nativeReferences(handle,address); }
    public String types() { checkOpen(); return nativeProgramInfo(handle,0,0); }
    public String memoryBlocks() { checkOpen(); return nativeProgramInfo(handle,1,0); }
    public String provenance(long address) { checkOpen(); return nativeProgramInfo(handle,2,address); }
    public String cxxMetadata() { checkOpen(); return nativeProgramInfo(handle,3,0); }
    public String debugInfo() { checkOpen(); return nativeProgramInfo(handle,4,0); }
    public String sourceLocation(long address) { checkOpen(); return nativeProgramInfo(handle,5,address); }
    public String typesCHeader() { checkOpen();return nativeProgramInfo(handle,6,0); }
    public String interproceduralPrototypes() {checkOpen();return nativeProgramInfo(handle,7,0);}
    public String locals(long function) {checkOpen();return nativePower(handle,"local-list","","",function,0,false);}
    public String abi(long function) {checkOpen();return nativePower(handle,"abi","","",function,0,false);}
    public String importDebug(String path,boolean allowUnverified) {checkOpen();return nativePower(handle,"debug-import",path,"",0,0,allowUnverified);}
    public void editLocal(long function,String identity,String name,String type) {
        checkOpen();if(identity==null || name==null || type==null || name.indexOf('\n')>=0 || type.indexOf('\n')>=0)
            throw new IllegalArgumentException("Invalid local-variable edit");
        nativePower(handle,"local-edit",identity,name+'\n'+type,function,0,false);
    }
    public String importLibrary(String text,boolean signatures) {checkOpen();return nativePower(handle,"library-import",text,"",0,0,signatures);}
    public String signatureLibrary() {checkOpen();return nativePower(handle,"library-signatures","","",0,0,false);}
    public String runScript(String source,boolean allowEdits) { checkOpen(); return nativeScript(handle,source,allowEdits); }
    public String assemble(long address,String source,boolean apply) { checkOpen(); return nativeAssemble(handle,address,source,apply); }
    public String loadPlugin(String path,boolean trustNativeCode) {checkOpen();return nativePower(handle,"plugin-load",path,"",0,0,trustNativeCode);}
    public String pluginCommands() {checkOpen();return nativePower(handle,"plugin-list","","",0,0,false);}
    public String runPlugin(String command,String arguments,boolean allowEdits) {checkOpen();return nativePower(handle,"plugin-run",command,arguments,0,0,allowEdits);}
    public String connectDebugger(String host,int port,boolean dap,boolean allowRemote) {checkOpen();return nativePower(handle,"debug-connect",host,dap?"dap":"rsp",0,port,allowRemote);}
    public String debugger(String operation,long address,long value) {checkOpen();return nativePower(handle,"debug",operation,"",address,value,false);}
    public String openComparison(String input,String project,boolean sameRawMapping) {checkOpen();return nativePower(handle,sameRawMapping?"compare-open-raw":"compare-open",input,project,0,0,false);}
    public String openComparisonMachO(String input,String project){checkOpen();return nativePower(handle,"compare-open-macho",input,project,0,0,false);}
    public String comparison(String operation,long source,long target,String path) {checkOpen();return nativePower(handle,"compare",operation,path,source,target,false);}
    public void defineType(String declaration) { checkOpen(); nativeType(handle,declaration,false); }
    public void eraseType(String name) { checkOpen(); nativeType(handle,name,true); }
    public void reanalyze() { checkOpen(); nativeReanalyze(handle); }
    public void exportPatchedCopy(String newPath) throws IOException { checkOpen(); nativeExportPatched(handle,newPath); }
    private static native long nativeOpenRaw(String path,String arch,long base,long entry);
    private static native long nativeOpenMachO(String path,String architecture);
    private static native String[] nativeRawArchitectures();
    private static native String nativeProgramInfo(long handle,int kind,long address);
    private static native String nativeScript(long handle,String source,boolean allowEdits);
    private static native String nativeAssemble(long handle,long address,String source,boolean apply);
    private static native String nativePower(long handle,String operation,String text,String arguments,long address,long value,boolean flag);
    private static native void nativeType(long handle,String declaration,boolean erase);
    private static native void nativeReanalyze(long handle);
    private static native void nativeExportPatched(long handle,String path);
    private static native void nativeProject(long handle,String path);
    private static native void nativeEdit(long handle,long address,String kind,String value);
    private static native String nativeAnnotation(long handle,long address,String kind);
    private static native void nativeUndo(long handle,boolean redo);
    private static native String nativeSearch(long handle,String query);
    private static native String nativeReferences(long handle,long address);
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

    private static native String nativeExportJson(long handle);

    private static native String nativeXrefs(long handle, long address);

    private static native String nativeStrings(long handle, long functionAddress);

    private static native String nativeProgramPrototypes(long handle);

    private static native String nativeProgramCoverage(long handle);

    private static native String nativeProgramWrites(long handle);

    private static native String nativeWriteMap(long handle, long address);

    private static native String nativeCallGraph(long handle);

    private static native String nativeWarnings(long handle);
}
