import com.ccs.mint.core.MintSession;
import com.ccs.mint.core.NativeCore;
import com.ccs.mint.core.RawArchitecture;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Comparator;
import java.util.stream.Stream;
import java.util.concurrent.atomic.AtomicReference;

/** End-to-end contracts for explicit raw Programs and the platform JNI surface. */
public final class PlatformJniProbe {
    private static int checks;
    private static int failures;
    private interface Action { void run() throws Exception; }

    private static void check(boolean condition, String description) {
        checks++;
        System.out.println((condition ? "  ok   " : "  FAIL ") + description);
        if (!condition) failures++;
    }

    private static void rejects(Class<? extends Exception> expected, Action action, String description) {
        try {
            action.run();
            check(false, description + " (unexpectedly accepted)");
        } catch (Exception exception) {
            check(expected.isInstance(exception), description + " (" + exception.getClass().getSimpleName() + ")");
        }
    }

    private static byte[] rawFixture() {
        byte[] bytes = new byte[128];
        ByteBuffer code = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
        code.putInt(0, 0x94000004);       // bl base + 0x10
        code.putInt(4, 0xd65f03c0);       // ret
        code.putInt(8, 0xd503201f);       // nop padding
        code.putInt(12, 0xd503201f);
        code.putInt(16, 0xd28000e0);      // mov x0, #7
        code.putInt(20, 0xd65f03c0);      // ret
        code.putInt(24, 0xd65f03c0);      // explicit user-only function root
        code.putLong(64, 0x1000);        // typed pointer data
        byte[] text = "Mint raw platform".getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(text, 0, bytes, 80, text.length);
        return bytes;
    }

    private static String firstListing(MintSession session, long address) {
        String[] text = new String[1];
        int count = session.listing(address, 1, new long[1], new int[1], new int[1], new long[1], text, new String[1]);
        check(count == 1 && text[0] != null, "listing row available at 0x" + Long.toUnsignedString(address, 16));
        return count == 1 && text[0] != null ? text[0] : "";
    }

    private static byte[] words(int... words) {
        ByteBuffer bytes = ByteBuffer.allocate(words.length * 4).order(ByteOrder.LITTLE_ENDIAN);
        for (int word : words) bytes.putInt(word);
        return bytes.array();
    }

    private static byte[] scalarA64() {
        return words(0xd28000e0, 0xd65f03c0, 0xd503201f, 0xd503201f,
                0xd2800100, 0xd65f03c0, 0xd503201f, 0xd503201f);
    }

    private static void putString(byte[] bytes, int offset, String text) {
        byte[] value = text.getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(value, 0, bytes, offset, value.length);
    }

    /** Real ELF linkage metadata, rather than an inferred sub_ADDRESS label. */
    private static byte[] symbolicElf64() {
        byte[] bytes = new byte[0x400];
        ByteBuffer file = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
        file.putInt(0, 0x464c457f); bytes[4] = 2; bytes[5] = bytes[6] = 1;
        file.putShort(16, (short) 2); file.putShort(18, (short) 183); file.putInt(20, 1);
        file.putLong(24, 0x1000); file.putLong(32, 64); file.putLong(40, 0x280);
        file.putShort(52, (short) 64); file.putShort(54, (short) 56); file.putShort(56, (short) 1);
        file.putShort(58, (short) 64); file.putShort(60, (short) 4);
        file.putInt(64, 1); file.putInt(68, 5); file.putLong(72, 0x100); file.putLong(80, 0x1000);
        file.putLong(96, 32); file.putLong(104, 32); file.putLong(112, 4);
        System.arraycopy(scalarA64(), 0, bytes, 0x100, 32);
        String names = "\0fixture_entry\0fixture_other\0"; putString(bytes, 0x180, names);
        for (int i = 0; i < 2; i++) {
            int symbol = 0x1d8 + i * 24;
            file.putInt(symbol, i == 0 ? 1 : 15); bytes[symbol + 4] = 0x12;
            file.putShort(symbol + 6, (short) 1); file.putLong(symbol + 8, 0x1000 + i * 16);
            file.putLong(symbol + 16, 8);
        }
        file.putInt(0x2c4, 1); file.putLong(0x2c8, 6); file.putLong(0x2d0, 0x1000);
        file.putLong(0x2d8, 0x100); file.putLong(0x2e0, 32); file.putLong(0x2f0, 4);
        file.putInt(0x304, 3); file.putLong(0x318, 0x180); file.putLong(0x320, names.length()); file.putLong(0x330, 1);
        file.putInt(0x344, 2); file.putLong(0x358, 0x1c0); file.putLong(0x360, 72);
        file.putInt(0x368, 2); file.putInt(0x36c, 1); file.putLong(0x370, 8); file.putLong(0x378, 24);
        return bytes;
    }

    private static byte[] elf32() {
        byte[] bytes = new byte[0x106]; ByteBuffer file = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
        file.putInt(0, 0x464c457f); bytes[4] = bytes[5] = bytes[6] = 1;
        file.putShort(16, (short) 2); file.putShort(18, (short) 3); file.putInt(20, 1);
        file.putInt(24, 0x1000); file.putInt(28, 52); file.putShort(40, (short) 52);
        file.putShort(42, (short) 32); file.putShort(44, (short) 1);
        file.putInt(52, 1); file.putInt(56, 0x100); file.putInt(60, 0x1000);
        file.putInt(68, 6); file.putInt(72, 6); file.putInt(76, 5); file.putInt(80, 1);
        bytes[0x100] = (byte) 0xb8; bytes[0x101] = 7; bytes[0x105] = (byte) 0xc3;
        return bytes;
    }

    private static byte[] pe32() {
        byte[] bytes = new byte[0x400]; ByteBuffer file = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
        file.putShort(0, (short) 0x5a4d); file.putInt(0x3c, 0x80); file.putInt(0x80, 0x4550);
        file.putShort(0x84, (short) 0x14c); file.putShort(0x86, (short) 1);
        file.putShort(0x94, (short) 224); file.putShort(0x96, (short) 0x102);
        int optional = 0x98; file.putShort(optional, (short) 0x10b); file.putInt(optional + 16, 0x1000);
        file.putInt(optional + 28, 0x400000); file.putInt(optional + 32, 0x1000); file.putInt(optional + 36, 0x200);
        file.putInt(optional + 56, 0x2000); file.putInt(optional + 60, 0x200); file.putInt(optional + 92, 16);
        int section = optional + 224; putString(bytes, section, ".text");
        file.putInt(section + 8, 0x200); file.putInt(section + 12, 0x1000);
        file.putInt(section + 16, 0x200); file.putInt(section + 20, 0x200); file.putInt(section + 36, 0x60000020);
        bytes[0x200] = (byte) 0xb8; bytes[0x201] = 7; bytes[0x205] = (byte) 0xc3;
        return bytes;
    }

    private static long functionNamed(MintSession session, String wanted) {
        long[] addresses = new long[256]; String[] names = new String[256];
        for (int offset = 0; offset < session.functionCount(); offset += 256) {
            int count = session.functions(offset, 256, addresses, new int[256], new int[256], new int[256], new int[256], names);
            for (int i = 0; i < count; i++) if (wanted.equals(names[i])) return addresses[i];
        }
        return -1;
    }

    private static void rawArchitectures(Path directory) throws Exception {
        String[] architectures = {"aarch64", "x86-64", "arm", "thumb", "x86-32", "riscv32", "riscv64"};
        String[] summaries = {"arm64", "x86-64", "arm", "thumb", "x86-32", "riscv32", "riscv64"};
        RawArchitecture[] registry = MintSession.rawArchitectures();
        check(registry.length >= 7 && registry.length <= 64, "native raw architecture registry marshals a bounded descriptor snapshot");
        byte[][] code = {words(0xd28000e0, 0xd65f03c0), new byte[]{(byte) 0xb8, 7, 0, 0, 0, (byte) 0xc3},
                words(0xe3a00007, 0xe12fff1e), new byte[]{7, 0x20, 0x70, 0x47},
                new byte[]{(byte) 0xb8, 7, 0, 0, 0, (byte) 0xc3}, words(0x00700513, 0x00008067), words(0x00700513, 0x00008067)};
        for (int i = 0; i < architectures.length; i++) {
            final String architecture = architectures[i]; final byte[] machine = code[i];
            RawArchitecture descriptor = null;
            for (RawArchitecture entry : registry) if (entry.id.equals(architecture)) descriptor = entry;
            int width = i == 0 || i == 1 || i == 6 ? 8 : 4;
            check(descriptor != null && descriptor.pointerSize == width && descriptor.instructionAlignment > 0 && descriptor.maximumInstructionSize >= descriptor.minimumInstructionSize,
                    "raw " + architecture + " registry metadata preserves ABI widths/alignment");
            Path binary = directory.resolve("raw-" + architecture + ".bin"); Files.write(binary, machine);
            try (MintSession session = MintSession.openRaw(binary.toString(), architecture, 0x3000, 0x3000)) {
                session.analyze();
                check(session.imageSummary().contains("arch=" + summaries[i]) && session.imageSummary().contains("format=raw"), "raw " + architecture + " descriptor reaches JNI");
                check(session.functionCount() == 1 && session.functionIr(0x3000).contains("7"), "raw " + architecture + " actual decoder/lifter yields scalar IR");
                check(!session.decompiledC(0x3000).isEmpty() && !session.cfg(0x3000).isEmpty(), "raw " + architecture + " decompiler/CFG usable");
                check(!session.assemble(0x3000, "ret", false).isEmpty() && session.annotation(0x3000, "patch").isEmpty(), "raw " + architecture + " assembler preview uses correct ISA without edits");
            }
            if (i == 2 || i == 3 || i == 4 || i == 5) {
                final long wrappingBase = i == 3 ? 0xffff_fffeL : 0xffff_fffcL;
                rejects(IOException.class, () -> { try (MintSession ignored = MintSession.openRaw(binary.toString(), architecture, 0x1_0000_0000L, 0x1_0000_0000L)) {} }, "32-bit " + architecture + " rejects base above u32");
                rejects(IOException.class, () -> { try (MintSession ignored = MintSession.openRaw(binary.toString(), architecture, wrappingBase, wrappingBase)) {} }, "32-bit " + architecture + " rejects extent wrapping u32");
            }
        }
        Path thumb = directory.resolve("raw-thumb.bin");
        try (MintSession session = MintSession.openRaw(thumb.toString(), "arm", 0x3000, 0x3001)) {
            session.analyze();
            check(firstListing(session, 0x3000).contains("movs") && session.functionIr(0x3000).contains("7"), "ARM odd entry tag selects real Thumb decoder/lifter");
            check(session.assemble(0x3001, "ret", false).equals("70 47"), "tagged Thumb patch preview preserves canonical address and mode");
        }
        Path wide = directory.resolve("raw-aarch64.bin");
        rejects(IOException.class, () -> { try (MintSession ignored = MintSession.openRaw(wide.toString(), "aarch64", -4, -4)) {} }, "64-bit raw extent overflow rejected across JNI");
    }

    private static void powerWorkflow(Path directory) throws Exception {
        Path source = directory.resolve("symbolic.elf"), sourceProject = directory.resolve("symbolic.mint");
        Path target = directory.resolve("comparison.bin"), targetProject = directory.resolve("comparison.mint");
        Path tracking = directory.resolve("confirmed.matches"), corrupt = directory.resolve("corrupt.matches");
        byte[] originalSource = symbolicElf64(), originalTarget = scalarA64();
        Files.write(source, originalSource); Files.write(target, originalTarget);
        String library = "MINTSIG 1\nabi=aapcs64\nfixture_entry\tuint32_t(void)\n";
        try (MintSession targetSession = MintSession.openRaw(target.toString(), "aarch64", 0x1000, 0x1000)) {
            targetSession.attachProject(targetProject.toString()); targetSession.analyze();
            targetSession.edit(0x1010, "function", "code");
            targetSession.edit(0x1000, "name", "target_owned_name");
            targetSession.edit(0x1000, "bookmark", "target protected bookmark");
            targetSession.assemble(0x1010, "mov x0, #11", true);
            String targetListing = firstListing(targetSession, 0x1010);
            check(targetListing.contains("#0xb") || targetListing.contains("#11"), "comparison target persists its independent patch overlay");
        }
        try (MintSession session = MintSession.open(source.toString())) {
            session.attachProject(sourceProject.toString()); session.analyze();
            check(functionNamed(session, "fixture_entry") == 0x1000 && functionNamed(session, "fixture_other") == 0x1010,
                    "signature workflow uses real ELF linkage symbols");
            check(session.importLibrary("MINT_TYPES 1 8\nNode=struct{value:i32;next:Node*}\nAlias=Node*\n", false).contains("Node=struct"), "atomic authored type-library import crosses JNI");
            check(session.typesCHeader().contains("offsetof(Node, next)") && session.typesCHeader().contains("_Static_assert(sizeof(void*) == 8"), "C header exports checked target layout through JNI");
            String beforeTypes = session.types();
            rejects(IllegalStateException.class, () -> session.importLibrary("MINT_TYPES 1 4\nWrong=u32\n", false), "foreign pointer-width type library rejected through JNI");
            rejects(IllegalStateException.class, () -> session.importLibrary("MINT_TYPES 1 8\nLoop=struct{self:Loop}\n", false), "malformed recursive type library rejected atomically through JNI");
            check(session.types().equals(beforeTypes), "failed library imports preserve all existing definitions");
            check(session.importLibrary(library, true).equals(library) && session.signatureLibrary().equals(library), "strict signature library round trips canonical text through JNI");
            check(session.decompiledC(0x1000).contains("uint32_t fixture_entry(void)"), "original linkage signature reaches actual pseudo-C");
            session.edit(0x1000, "name", "source_entry");
            check(session.decompiledC(0x1000).contains("uint32_t source_entry(void)"), "user rename preserves original linkage signature binding");
            session.edit(0x1000, "prototype", "int32_t(void)");
            check(session.decompiledC(0x1000).contains("int32_t source_entry(void)"), "explicit user prototype overrides imported signature");
            session.undoEdit(false);
            check(session.decompiledC(0x1000).contains("uint32_t source_entry(void)"), "undo exposes persisted linkage signature again");
            rejects(IllegalStateException.class, () -> session.importLibrary("MINTSIG 1\nabi=sysv64\nfixture_entry\tvoid(void)\n", true), "foreign signature ABI rejected through JNI");
            rejects(IllegalStateException.class, () -> session.importLibrary(library + "fixture_entry\tvoid(void)\n", true), "duplicate authored signature rejected through JNI");
            check(session.signatureLibrary().equals(library), "invalid signature import never replaces persisted library");
            check(session.interproceduralPrototypes().contains("authoritative"), "interprocedural authored prototype evidence crosses JNI");

            String preview = session.assemble(0x1010, "mov x0, #9; ret", false);
            check(preview.equals("20 01 80 d2 c0 03 5f d6") && session.annotation(0x1010, "patch").isEmpty(), "scalar assembler preview is exact little-endian bytes without mutation");
            session.assemble(0x1010, "mov x0, #9", true);
            check(firstListing(session, 0x1010).contains("#9") && session.decompiledC(0x1010).contains("9"), "assembler apply updates listing and pseudo-C across JNI");
            session.undoEdit(false); check(firstListing(session, 0x1010).contains("#8"), "assembler patch undo restores original native instruction");
            session.undoEdit(true); check(firstListing(session, 0x1010).contains("#9"), "assembler patch redo replays persisted overlay");
            String patch = session.annotation(0x1010, "patch");
            rejects(IllegalArgumentException.class, () -> session.assemble(0x1010, "unknown_instruction x0", true), "unknown assembler mnemonic fails closed across JNI");
            rejects(IllegalArgumentException.class, () -> session.assemble(0x1010, "nop;".repeat(257), true), "assembler 1024-byte bound enforced across JNI");
            rejects(IllegalArgumentException.class, () -> session.assemble(0x1011, "nop", true), "unaligned AArch64 assembly rejected across JNI");
            check(session.annotation(0x1010, "patch").equals(patch), "failed assembly leaves accepted patch overlay unchanged");

            String script = session.runScript("assert(os==nil and io==nil and package==nil and debug==nil and load==nil); local f=mint.functions(); assert(#f==2); assert(#mint.read('0x1000',8)==8); assert(#mint.architectures()>=7); print(f[1].entry)", false);
            check(script.contains("0x1000") && !script.contains("Script stopped"), "bounded Lua structured read-only API reaches JNI without filesystem/process capabilities");
            String previousComment = session.annotation(0x1000, "comment");
            check(session.runScript("mint.edit('0x1000','comment','denied')", false).contains("read-only") && session.annotation(0x1000, "comment").equals(previousComment), "read-only Lua cannot persist edits across JNI");
            check(session.runScript("mint.read('0xfffffffffffffffff',1)", false).contains("Script stopped") && session.runScript("mint.read(1.5,1)", false).contains("Script stopped"), "Lua rejects u64 overflow and floating-point addresses across JNI");
            check(session.runScript("while true do end", false).contains("instruction limit"), "Lua runaway script is stopped by instruction budget through JNI");
            check(session.runScript("mint.edit('0x1000','comment','Lua JNI review'); print(mint.annotation('0x1000','comment'))", true).contains("Lua JNI review") && session.annotation(0x1000, "comment").equals("Lua JNI review"), "explicit Lua edit permission writes the same persistent Program");
            check(!session.runScript("mint.undo(); assert(mint.annotation('0x1000','comment')==''); mint.redo()", true).contains("Script stopped") && session.annotation(0x1000, "comment").equals("Lua JNI review"), "Lua undo/redo share Program transactions through JNI");
            check(session.runScript("print('session survived')", false).contains("session survived"), "Lua failures leave the JNI session usable");

            String plugins = session.pluginCommands();
            rejects(IllegalStateException.class, () -> session.loadPlugin(source.toString(), false), "native plugin load requires explicit trust before touching code");
            rejects(IllegalStateException.class, () -> session.runPlugin("not-loaded", "", false), "unknown plugin command rejected through JNI");
            check(session.pluginCommands().equals(plugins) && plugins.contains("not sandboxed"), "failed plugin request preserves command registry and states native trust boundary");
            check(session.debugger("status", 0, 0).contains("disconnected"), "debugger has no implicit connection or target launch");
            rejects(IllegalStateException.class, () -> session.connectDebugger("example.com", 3333, false, false), "debugger DNS endpoint refused before network through JNI");
            rejects(IllegalStateException.class, () -> session.connectDebugger("192.0.2.1", 3333, false, false), "unauthenticated remote debugger needs explicit acknowledgement through JNI");
            rejects(IllegalStateException.class, () -> session.connectDebugger("127.0.0.1", 0, true, false), "debugger port bounds checked across JNI");
            rejects(IllegalStateException.class, () -> session.debugger("step", 0, 0), "disconnected debugger cannot operate target through JNI");
            rejects(IllegalStateException.class, () -> session.debugger("memory", 0, 16385), "debugger read budget enforced across JNI");
            check(session.debugger("disconnect", 0, 0).contains("disconnected"), "explicit local debugger disconnect remains safe when disconnected");

            session.edit(0x1000, "comment", "transfer entry review"); session.edit(0x1004, "comment", "transfer exact instruction offset");
            session.edit(0x1000, "bookmark", "source bookmark must not replace target");
            session.edit(0x1000, "prototype", "uint32_t(void)");
            rejects(IllegalStateException.class, () -> session.openComparison(target.toString(), sourceProject.toString(), true), "comparison cannot create competing writers for the source project");
            String diff = session.openComparison(target.toString(), targetProject.toString(), true);
            check(diff.contains("Native binary diff") && diff.contains("0x1000 -> 0x1000") && diff.contains("No annotations are transferred automatically"), "semantic comparison consumes target persistent patch overlay without automatic transfer");
            check(!diff.contains("0x1010 -> 0x1010"), "semantic diff retains changed constants rather than treating distinct patched functions as exact matches");
            check(session.comparison("preview", 0, 0, "").contains("0 applicable"), "diff candidates alone never authorize annotation transfer");
            rejects(IllegalStateException.class, () -> session.comparison("confirm", 0x1000, 0x1004, ""), "manual match requires an actual target function entry");
            check(session.comparison("confirm", 0x1000, 0x1000, "").contains("manual; code/CFG fingerprints pinned"), "explicit one-to-one manual match recorded through JNI");
            session.comparison("confirm", 0x1010, 0x1010, "");
            check(session.comparison("save", 0, 0, tracking.toString()).contains("Saved confirmed matches") && Files.isRegularFile(tracking), "version tracking state is persisted through JNI");
            rejects(IllegalStateException.class, () -> session.comparison("save", 0, 0, tracking.toString()), "tracking save refuses to overwrite existing state through JNI");
            String authorized = session.comparison("tracking", 0, 0, "");
            byte[] malformed = Files.readAllBytes(tracking); malformed[malformed.length - 1] ^= 1; Files.write(corrupt, malformed);
            rejects(IllegalStateException.class, () -> session.comparison("load", 0, 0, corrupt.toString()), "corrupted tracking checksum rejected through JNI");
            check(session.comparison("tracking", 0, 0, "").equals(authorized), "failed tracking load preserves confirmed manual authorization");
        }
        try (MintSession session = MintSession.open(source.toString())) {
            session.attachProject(sourceProject.toString()); session.analyze();
            check(session.signatureLibrary().equals(library) && session.typesCHeader().contains("offsetof(Node, next)"), "cold source reopen restores authored signature/type libraries through JNI");
            check(firstListing(session, 0x1010).contains("#9") && session.annotation(0x1000, "comment").equals("transfer entry review"), "cold source reopen restores assembler and Lua/edit state before comparison");
            session.openComparison(target.toString(), targetProject.toString(), true);
            check(session.comparison("load", 0, 0, tracking.toString()).contains("0x1010 -> 0x1010"), "tracking file reopens against exact current source and target Programs");
            String plan = session.comparison("preview", 0, 0, "");
            check(plan.contains("0x1004 -> 0x1004 comment") && plan.contains("Skipped 0x1000 name") && plan.contains("Patches/types/structural decisions excluded"), "transfer preview maps exact instruction offsets and preserves target conflicts");
            check(session.comparison("apply", 0, 0, "").contains("Applied: 3"), "confirmed transfer applies only two comments and an entry prototype through JNI");
            rejects(IllegalStateException.class, () -> session.comparison("load", 0, 0, tracking.toString()), "persisted matches reject target prototype/config changes after transfer");
            check(session.annotation(0x1000, "name").equals("source_entry") && session.annotation(0x1000, "comment").equals("transfer entry review"), "version transfer never rewrites source annotations");
        }
        try (MintSession restored = MintSession.openRaw(target.toString(), "aarch64", 0x1000, 0x1000)) {
            restored.attachProject(targetProject.toString()); restored.analyze();
            check(restored.annotation(0x1000, "comment").equals("transfer entry review") && restored.annotation(0x1004, "comment").equals("transfer exact instruction offset"), "transferred function/instruction comments survive target reopen");
            check(restored.annotation(0x1000, "name").equals("target_owned_name") && restored.annotation(0x1000, "bookmark").equals("target protected bookmark"), "target user edits win annotation conflicts across cold reopen");
            check(restored.annotation(0x1000, "prototype").equals("uint32_t(void)") && restored.decompiledC(0x1000).contains("uint32_t target_owned_name(void)"), "confirmed prototype transfer reaches target decompiler after reopen");
            String targetListing = firstListing(restored, 0x1010);
            check((targetListing.contains("#0xb") || targetListing.contains("#11")) && restored.annotation(0x1010, "patch").equals("60 01 80 d2") && !restored.types().contains("Node=struct"), "transfer preserves distinct target patch and excludes source type library");
        }
        check(Arrays.equals(Files.readAllBytes(source), originalSource) && Arrays.equals(Files.readAllBytes(target), originalTarget), "all advanced JNI workflows preserve original source/target files");
        Path high = directory.resolve("script-high.bin"); Files.write(high, words(0xd28000e0, 0xd65f03c0));
        try (MintSession session = MintSession.openRaw(high.toString(), "aarch64", Long.MIN_VALUE + 0x1000, Long.MIN_VALUE + 0x1000)) {
            session.analyze();
            check(session.runScript("local f=mint.functions(); assert(f[1].entry=='0x8000000000001000'); assert(#mint.read(f[1].entry,8)==8); print(f[1].entry)", false).contains("0x8000000000001000"), "Lua u64 address strings preserve all JNI high bits without number rounding");
        }
    }
    private static void localAndAbiWorkflow(Path directory) throws Exception {
        Path binary=directory.resolve("local-a64.bin"),project=directory.resolve("local-a64.mint");
        byte[] original=words(0xd28000e1,0xf81f83e1,0xf85f83e2,0x8b020000,0xd65f03c0);Files.write(binary,original);String identity=null;
        try(MintSession session=MintSession.openRaw(binary.toString(),"aarch64",0x1000,0x1000)){
            session.attachProject(project.toString());session.analyze();String locals=session.locals(0x1000);
            for(String line:locals.split("\n")){String[] row=line.split("\t",-1);if(row.length>=5&&row[0].startsWith("stack:")&&row[3].equals("8")){identity=row[0];break;}}
            check(identity!=null,"actual stack local identity exposed through JNI");
            if(identity!=null){session.editLocal(0x1000,identity,"reviewed_counter","uint64_t");check(session.locals(0x1000).contains("reviewed_counter\tuint64_t"),"local rename/type persisted to the authoritative Program");check(session.decompiledC(0x1000).contains("reviewed_counter"),"local override reaches actual pseudo-C emitter");final String selected=identity;rejects(IllegalStateException.class,()->session.editLocal(0x1000,selected,"wrong_width","u32"),"local width change rejected without reinterpretation");check(session.locals(0x1000).contains("reviewed_counter"),"rejected local edit preserves accepted override");session.undoEdit(false);check(!session.locals(0x1000).contains("reviewed_counter"),"local override shares Program undo");session.undoEdit(true);}
            session.edit(0x1000,"prototype","@aapcs64 uint64_t(uint64_t a,uint64_t b,uint64_t c,uint64_t d,uint64_t e,uint64_t f,uint64_t g,uint64_t h,uint64_t i)");check(session.abi(0x1000).contains("Calling convention: aapcs64")&&session.abi(0x1000).contains("arg 8")&&session.abi(0x1000).contains("entry SP 0"),"AAPCS64 ninth argument has explicit stack storage in JNI report");
        }
        try(MintSession reopened=MintSession.openRaw(binary.toString(),"aarch64",0x1000,0x1000)){reopened.attachProject(project.toString());reopened.analyze();if(identity!=null)check(reopened.locals(0x1000).contains("reviewed_counter")&&reopened.decompiledC(0x1000).contains("reviewed_counter"),"local identity/rename/type reopen into the same native function/emitter");check(reopened.abi(0x1000).contains("entry SP 0"),"explicit ABI declaration survives Program reopen");}
        check(Arrays.equals(original,Files.readAllBytes(binary)),"local and prototype edits never modify source bytes");
        Path x86=directory.resolve("stack-abi-x86.bin");Files.write(x86,new byte[]{(byte)0xb8,7,0,0,0,(byte)0xc3});
        try(MintSession session=MintSession.openRaw(x86.toString(),"x86-32",0x2000,0x2000)){session.attachProject(directory.resolve("cdecl-storage.mint").toString());session.analyze();session.edit(0x2000,"prototype","@cdecl32 uint32_t(uint32_t first,uint32_t second)");String abi=session.abi(0x2000);check(abi.contains("Calling convention: cdecl32")&&abi.contains("entry SP 4")&&abi.contains("entry SP 8"),"x86-32 parameters have callee-entry stack slots not SysV64 registers");}
        try(MintSession session=MintSession.openRaw(x86.toString(),"x86-64",0x2000,0x2000)){session.attachProject(directory.resolve("windows-storage.mint").toString());session.analyze();session.edit(0x2000,"prototype","@windows64 uint64_t(uint64_t a,uint64_t b,uint64_t c,uint64_t d,uint64_t e)");String abi=session.abi(0x2000);check(abi.contains("Calling convention: windows64")&&abi.contains("shadow 32")&&abi.contains("arg 4")&&abi.contains("entry SP 40"),"explicit Windows64 storage includes shadow space and fifth-argument stack slot");}
    }
    private static String rspRequest(InputStream input) throws Exception {
        int value;do{value=input.read();if(value<0)throw new IOException("mock RSP client closed");}while(value=='+');if(value!='$')throw new IOException("mock expected RSP marker");StringBuilder request=new StringBuilder();int checksum=0;
        while((value=input.read())!='#'){if(value<0||request.length()>65536)throw new IOException("mock truncated/oversized request");request.append((char)value);checksum=(checksum+value)&255;}
        int high=Character.digit((char)input.read(),16),low=Character.digit((char)input.read(),16);if(high<0||low<0||high*16+low!=checksum)throw new IOException("mock request checksum mismatch");return request.toString();
    }
    private static void rspReply(OutputStream output,String text)throws Exception{int sum=0;for(byte value:text.getBytes(StandardCharsets.US_ASCII))sum=(sum+(value&255))&255;output.write(("+$"+text+"#"+String.format(java.util.Locale.ROOT,"%02x",sum)).getBytes(StandardCharsets.US_ASCII));output.flush();}
    private static void debuggerMappingWorkflow(Path directory)throws Exception{
        Path binary=directory.resolve("debug-map.bin");Files.write(binary,words(0xd28000e0,0xd65f03c0));AtomicReference<Throwable> failure=new AtomicReference<>();
        try(ServerSocket listener=new ServerSocket(0,1,InetAddress.getByName("127.0.0.1"))){listener.setSoTimeout(5000);Thread server=new Thread(()->{try(Socket socket=listener.accept()){socket.setSoTimeout(5000);String[] expected={"qSupported:swbreak+;vContSupported+","vCont?","?","m7fff1000,4","Z0,7fff1000,4"};String[] replies={"PacketSize=4000","vCont;c;s","T05thread:2;","01020304","OK"};for(int i=0;i<expected.length;i++){String request=rspRequest(socket.getInputStream());if(!request.equals(expected[i]))throw new IOException("mock got "+request+", expected "+expected[i]);rspReply(socket.getOutputStream(),replies[i]);}}catch(Throwable error){failure.set(error);}},"mint-jni-loopback-mock");server.setDaemon(true);server.start();
            try(MintSession session=MintSession.openRaw(binary.toString(),"aarch64",0x1000,0x1000)){session.analyze();session.connectDebugger("127.0.0.1",listener.getLocalPort(),false,false);check(session.debugger("map-image",0x7fff1000,0).contains("Mapped image base 0x1000"),"explicit runtime mapping crosses JNI without guessing image slide");check(session.debugger("memory-image",0x1000,4).contains("01 02 03 04"),"image memory read sends the mapped runtime address to actual loopback transport");check(session.debugger("break-image",0x1000,0).contains("stopped"),"image breakpoint reaches exact mapped runtime address and instruction width");session.debugger("unmap",0,0);rejects(IllegalStateException.class,()->session.debugger("memory-image",0x1000,4),"unmapped image reads fail before any new remote request");session.debugger("disconnect",0,0);}
            server.join(5500);check(!server.isAlive()&&failure.get()==null,"JNI loopback mock verified exact protocol requests without operating a real debugger");if(failure.get()!=null)System.out.println(failure.get());
        }
    }

    private static void rawProgram(Path directory) throws Exception {
        final long base = 0x1000, callee = 0x1010, extra = 0x1018;
        Path binary = directory.resolve("raw.bin");
        Path project = directory.resolve("program.mint");
        Path exported = directory.resolve("patched.bin");
        byte[] original = rawFixture();
        Files.write(binary, original);

        rejects(IOException.class, () -> { try (MintSession ignored = MintSession.open(binary.toString())) {} },
                "raw bytes never silently use automatic container detection");
        rejects(IOException.class, () -> { try (MintSession ignored = MintSession.openRaw(binary.toString(), "risc-v", base, base)) {} },
                "unsupported raw ISA rejected across JNI");
        rejects(IOException.class, () -> { try (MintSession ignored = MintSession.openRaw(binary.toString(), "aarch64", base, base + 1)) {} },
                "unaligned AArch64 raw entry rejected across JNI");
        rejects(IOException.class, () -> { try (MintSession ignored = MintSession.openRaw(binary.toString(), "aarch64", base, 0x2000)) {} },
                "raw entry outside backing rejected across JNI");

        try (MintSession session = MintSession.openRaw(binary.toString(), "aarch64", base, base)) {
            check(session.imageSummary().contains("format=raw") && session.imageSummary().contains("arch=arm64"),
                    "raw format/architecture summary crosses JNI");
            session.attachProject(project.toString());
            check(Files.isRegularFile(project), "project source binding is persisted before analysis");
            session.analyze();
            check(session.memoryBlocks().contains("mode=full"), "first analysis reports full discovery across JNI");
            check(Files.isRegularFile(Path.of(project + ".analysis")), "derived Program snapshot is saved separately from user state");
            check(session.functionCount() >= 2, "raw entry/direct call discover functions");
            check(session.progress() == 100, "raw analysis completes");
            long[] entries = new long[8];
            String[] names = new String[8];
            int count = session.functions(0, 8, entries, new int[8], new int[8], new int[8], new int[8], names);
            boolean foundEntry = false, foundCallee = false;
            for (int i = 0; i < count; ++i) { foundEntry |= entries[i] == base; foundCallee |= entries[i] == callee; }
            check(foundEntry && foundCallee, "function entries survive JNI marshalling");
            check(session.memoryBlocks().contains("Format: raw") && session.memoryBlocks().contains("r-x") &&
                    session.memoryBlocks().contains("128 / 128 bytes"), "Program memory block metadata crosses JNI");
            check(session.provenance(base).contains("Origin: entry-point") && session.provenance(base).contains("Confidence:"),
                    "provenance/confidence crosses JNI");
            check(session.references(callee).contains("1000") && session.references(callee).contains("1010"),
                    "code references cross JNI");
            check(session.cfg(base).contains(" " + base + " "), "CFG uses raw virtual addresses");
            check(session.functionIr(callee).contains("7") && !session.decompiledC(callee).isEmpty(),
                    "raw IR and pseudo-C cross JNI");

            session.edit(base, "name", "platform_entry");
            session.edit(base, "comment", "Persistent JNI comment\nдруга лінія");
            session.edit(base, "bookmark", "entry bookmark");
            check(session.memoryBlocks().contains("mode=metadata functions=0"), "metadata changes preserve native discovery");
            check(session.search("platform_entry").contains("1000") && session.search("Persistent JNI comment").contains("comment:"),
                    "global symbol/comment search crosses JNI");
            check(session.annotation(base, "comment").equals("Persistent JNI comment\nдруга лінія"),
                    "UTF-8 multiline annotations round trip");

            session.defineType("Packet=struct{tag:u8;value:u32}");
            session.defineType("Choice=union{integer:u64;real:f64}");
            session.defineType("Mode=enum:i32{Off=-1;On=2}");
            session.defineType("Wire=packed{tag:u8;value:u32}");
            session.defineType("Octets=u8[8]");
            String types = session.types();
            check(types.contains("Packet=struct") && types.contains("size=8 alignment=4") && types.contains("+0x4 value: u32"),
                    "structure layout manager crosses JNI");
            check(types.contains("Choice=union") && types.contains("Mode=enum") && types.contains("Wire=packed") && types.contains("Octets=u8[8]"),
                    "union/enum/packed/array type definitions cross JNI");
            session.defineType("Scratch=u16");
            session.undoEdit(false);
            check(!session.types().contains("Scratch="), "undo type-library mutation crosses JNI");
            session.undoEdit(true);
            check(session.types().contains("Scratch=u16"), "redo type-library mutation crosses JNI");
            session.eraseType("Scratch");
            check(!session.types().contains("Scratch="), "unused user type can be erased across JNI");
            String beforeInvalidType = session.types();
            rejects(IllegalArgumentException.class, () -> session.defineType("Loop=struct{self:Loop}"), "recursive by-value type rejected");
            check(session.types().equals(beforeInvalidType), "invalid type definition leaves the library unchanged");
            session.edit(base + 96, "data", "Packet");
            check(firstListing(session, base + 96).contains("Packet"), "named aggregate data appears in listing");
            rejects(IllegalArgumentException.class, () -> session.eraseType("Packet"), "cannot erase a type still used by data");
            check(session.types().contains("Packet=struct"), "failed type erasure is atomic");
            session.edit(base + 104, "data", "u32");
            String beforeResize = session.types();
            rejects(IllegalArgumentException.class, () -> session.defineType("Packet=struct{tag:u8;value:u64}"),
                    "type resize cannot overlap another defined data object");
            check(session.types().equals(beforeResize), "failed aggregate resize keeps old layout");
            session.edit(base + 64, "data", "pointer");
            check(session.references(base).contains("user pointer") && session.references(base).contains("1040"),
                    "typed data pointer reference crosses JNI");
            session.edit(extra, "function", "code");
            check(session.provenance(extra).contains("Origin: user"), "explicit function seed triggers reanalysis and user provenance");
            rejects(IllegalArgumentException.class, () -> session.edit(extra, "data", "u64"), "defined data cannot hide an explicit function seed");
            rejects(IllegalArgumentException.class, () -> session.edit(base + 96, "function", "code"), "function seed cannot start inside defined data");
            rejects(IllegalArgumentException.class, () -> session.edit(0, "source", "tamper"), "project source identity is read-only across JNI");
            session.edit(base, "prototype", "int32_t(uint64_t context)");
            check(session.decompiledC(base).contains("int32_t platform_entry(uint64_t context)"),
                    "user signature/name updates decompiler");
            session.undoEdit(false);
            check(session.annotation(base, "prototype").isEmpty(), "undo persists prototype removal");
            session.undoEdit(true);
            check(!session.annotation(base, "prototype").isEmpty(), "redo persists prototype restoration");

            session.edit(callee, "patch", "20 01 80 d2"); // mov x0, #9
            check(session.memoryBlocks().contains("mode=incremental functions=1"), "flow-preserving patch reanalyzes one function across JNI");
            check(firstListing(session, callee).contains("#9"), "patch changes decoded listing via JNI");
            check(session.search("bytes: 20 01 80 d2").contains("1010"), "byte search sees patch overlay");
            String patchedC = session.decompiledC(callee);
            check(patchedC.contains("9"), "patch invalidates decompiler analysis");
            if (!patchedC.contains("9")) System.out.println("-- patched pseudo-C diagnostic --\n" + patchedC + "\n-- patched IR --\n" + session.functionIr(callee));
            rejects(IllegalArgumentException.class, () -> session.edit(callee + 1, "patch", "cc"), "overlapping patch rejected");
            rejects(IllegalArgumentException.class, () -> session.edit(0x2000, "patch", "cc"), "unmapped patch rejected");
            rejects(IllegalArgumentException.class, () -> session.edit(callee, "patch", "zz"), "malformed patch rejected");
            check(session.annotation(callee, "patch").equals("20 01 80 d2"), "rejected patch leaves persisted overlay unchanged");
            session.reanalyze();
            check(session.memoryBlocks().contains("mode=full"), "explicit reanalysis bypasses derived cache");
            check(firstListing(session, callee).contains("#9"), "explicit reanalysis replays persisted patches");
            check(Arrays.equals(Files.readAllBytes(binary), original), "in-memory patch never changes input bytes");
            session.exportPatchedCopy(exported.toString());
            byte[] patched = original.clone();
            ByteBuffer.wrap(patched).order(ByteOrder.LITTLE_ENDIAN).putInt(16, 0xd2800120);
            check(Arrays.equals(Files.readAllBytes(exported), patched), "patched-copy export maps VA bytes to file offsets");
            rejects(IOException.class, () -> session.exportPatchedCopy(exported.toString()), "export refuses to overwrite an existing copy");
            rejects(IOException.class, () -> session.exportPatchedCopy(binary.toString()), "export refuses to overwrite input");
            check(Arrays.equals(Files.readAllBytes(binary), original), "failed export preserves source bytes");
            session.undoEdit(false);
            check(firstListing(session, callee).contains("#7") && session.annotation(callee, "patch").isEmpty(),
                    "undo patch restores original code and persisted state");
            session.undoEdit(true);
            check(firstListing(session, callee).contains("#9"), "redo patch replays overlay");
            check(!session.cxxMetadata().isEmpty(), "C++ metadata report is marshalled for a raw image");
            check(session.references(base).contains("user pointer"), "updated reference index saved after patched analysis");
        }

        try (MintSession restored = MintSession.openRaw(binary.toString(), "aarch64", base, base)) {
            restored.attachProject(project.toString());
            restored.analyze();
            check(restored.memoryBlocks().contains("mode=restored"), "cold reopen adopts validated derived analysis across JNI");
            check(restored.memoryBlocks().contains("Derived references: ready"), "cold reopen restores lazy-built reference index");
            check(restored.annotation(base, "name").equals("platform_entry") &&
                    restored.annotation(base, "bookmark").equals("entry bookmark"), "cold reopen restores symbols/bookmarks");
            check(restored.types().contains("Packet=struct") && restored.annotation(base + 96, "data").equals("Packet"),
                    "cold reopen restores type library and defined data");
            check(restored.annotation(callee, "patch").equals("20 01 80 d2") && firstListing(restored, callee).contains("#9"),
                    "cold reopen replays patch before native analysis");
            check(restored.provenance(extra).contains("Origin: user") && restored.decompiledC(base).contains("platform_entry"),
                    "cold reopen restores function seeds and decompiler overrides");
        }
        byte[] projectBeforeMismatch = Files.readAllBytes(project);
        try (MintSession incompatible = MintSession.openRaw(binary.toString(), "aarch64", base, base + 4)) {
            rejects(IOException.class, () -> incompatible.attachProject(project.toString()), "source fingerprint rejects different raw entry config");
        }
        Path modified = directory.resolve("different-source.bin");
        byte[] changed = original.clone(); changed[127] = 1; Files.write(modified, changed);
        try (MintSession incompatible = MintSession.openRaw(modified.toString(), "aarch64", base, base)) {
            rejects(IOException.class, () -> incompatible.attachProject(project.toString()), "source fingerprint rejects different input bytes");
        }
        check(Arrays.equals(Files.readAllBytes(project), projectBeforeMismatch), "rejected reopen leaves existing project untouched");

        try (MintSession zero = MintSession.openRaw(binary.toString(), "aarch64", 0, 0)) {
            zero.analyze();
            long[] entry = new long[1];
            check(zero.functions(0, 1, entry, new int[1], new int[1], new int[1], new int[1], new String[1]) == 1 && entry[0] == 0,
                    "explicit raw entry zero is a valid discovered function");
        }
        try (MintSession high = MintSession.openRaw(binary.toString(), "aarch64", Long.MIN_VALUE, Long.MIN_VALUE)) {
            high.analyze();
            long[] entry = new long[1];
            check(high.functions(0, 1, entry, new int[1], new int[1], new int[1], new int[1], new String[1]) == 1 && entry[0] == Long.MIN_VALUE,
                    "unsigned high raw addresses preserve all bits across JNI");
            check(firstListing(high, Long.MIN_VALUE).contains("bl"), "listing accepts a high-bit virtual address");
        }
    }

    private static byte[] thinMachO64(boolean arm) {
        byte[] bytes=new byte[0x300];ByteBuffer file=ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);long base=0x100000000L;
        file.putInt(0,0xfeedfacf);file.putInt(4,arm?0x0100000c:0x01000007);file.putInt(8,3);file.putInt(12,2);file.putInt(16,2);file.putInt(20,176);file.putInt(24,0x200000);
        int at=32;file.putInt(at,0x19);file.putInt(at+4,152);putString(bytes,at+8,"__TEXT");file.putLong(at+24,base);file.putLong(at+32,bytes.length);file.putLong(at+48,bytes.length);file.putInt(at+56,5);file.putInt(at+60,5);file.putInt(at+64,1);
        putString(bytes,at+72,"__text");putString(bytes,at+88,"__TEXT");file.putLong(at+104,base+0x200);file.putLong(at+112,8);file.putInt(at+120,0x200);file.putInt(at+136,0x80000400);
        at+=152;file.putInt(at,0x80000028);file.putInt(at+4,24);file.putLong(at+8,0x200);
        if(arm){file.putInt(0x200,0xd28000e0);file.putInt(0x204,0xd65f03c0);}else{bytes[0x200]=(byte)0xb8;bytes[0x201]=9;bytes[0x205]=(byte)0xc3;}return bytes;
    }
    private static byte[] fatMachO64(){
        byte[] x86=thinMachO64(false),arm=thinMachO64(true),bytes=new byte[0x2300];ByteBuffer file=ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
        file.putInt(0,0xcafebabe);file.putInt(4,2);file.putInt(8,0x01000007);file.putInt(16,0x1000);file.putInt(20,x86.length);file.putInt(24,12);file.putInt(28,0x0100000c);file.putInt(36,0x2000);file.putInt(40,arm.length);file.putInt(44,12);
        System.arraycopy(x86,0,bytes,0x1000,x86.length);System.arraycopy(arm,0,bytes,0x2000,arm.length);return bytes;
    }
    private static void selectedMachO(Path directory)throws Exception{
        byte[] original=fatMachO64();Path input=directory.resolve("universal-macho.bin"),project=directory.resolve("selected-arm.mint"),exported=directory.resolve("selected-arm-patched.bin");Files.write(input,original);long entry=0x100000200L;
        try(MintSession selected=MintSession.openMachO(input.toString(),"aarch64")){
            check(selected.imageSummary().contains("arch=arm64"),"explicit JNI selects second ARM universal slice, not first supported x64");selected.attachProject(project.toString());selected.analyze();check(selected.functionIr(entry).contains("7"),"selected nonfirst-slice semantics reach actual JNI IR");
            selected.edit(entry,"name","selected_macho_arm");selected.defineType("SelectedSlicePacket=struct{tag:u32;length:u32}");selected.assemble(entry,"mov x0,9",true);selected.exportPatchedCopy(exported.toString());
            check(selected.openComparisonMachO(input.toString(),"").contains("Native binary diff"),"comparison factory preserves explicitly selected Mach-O architecture");
        }
        try(MintSession reopened=MintSession.openMachO(input.toString(),"aarch64")){reopened.attachProject(project.toString());reopened.analyze();check(reopened.annotation(entry,"name").equals("selected_macho_arm")&&reopened.typesCHeader().contains("SelectedSlicePacket")&&!reopened.annotation(entry,"patch").isEmpty(),"JNI cold reopen retains selected-slice typed Program and overlay");}
        try(MintSession wrong=MintSession.open(input.toString())){check(wrong.imageSummary().contains("arch=x86-64"),"default universal import still uses first supported slice");rejects(IOException.class,()->wrong.attachProject(project.toString()),"first-slice import rejects second-slice Program identity");}
        byte[] expected=original.clone();ByteBuffer.wrap(expected).order(ByteOrder.LITTLE_ENDIAN).putInt(0x2200,0xd2800120);check(Arrays.equals(Files.readAllBytes(exported),expected),"JNI exported full universal container changes only exact second-slice instruction bytes");check(Arrays.equals(Files.readAllBytes(input),original),"JNI selected-slice patch never modifies original input");
        try(MintSession patched=MintSession.openMachO(exported.toString(),"aarch64")){patched.analyze();check(patched.functionIr(entry).contains("9"),"JNI selected-slice factory reopens exported whole container with patched semantics");}
        rejects(IOException.class,()->{try(MintSession absent=MintSession.openMachO(input.toString(),"x86-32")){}},"explicit absent Mach-O CPU does not silently use another slice");
    }

    private static void nativeContainer(String path,Path directory) throws Exception {
        try (MintSession session = MintSession.open(path)) {
            String summary = session.imageSummary();
            System.out.println("-- optional native fixture: " + path + " --\n" + summary);
            check(summary.contains("format=PE32") || summary.contains("format=Mach-O64") || summary.contains("format=ELF64") || summary.contains("format=ELF32"),
                    "native container format name crosses JNI");
            session.attachProject(directory.resolve("container-"+checks+".mint").toString());session.analyze();
            check(session.functionCount() > 0, "optional native fixture analysis discovers functions");
            check(!session.memoryBlocks().isEmpty() && !session.cxxMetadata().isEmpty(), "optional native image Program reports cross JNI");
            if (summary.contains("format=PE32") || summary.contains("format=Mach-O64")) {
                check(!session.warnings().isEmpty(), "incomplete container semantics are explicitly warned");
            }
            if (summary.contains("format=PE32")) {
                long[] entries = new long[1];
                session.functions(0, 1, entries, new int[1], new int[1], new int[1], new int[1], new String[1]);
                check(session.decompiledC(entries[0]).contains("authoritative prototypes use explicit target ABI storage"), "PE pseudo-C discloses authoritative ABI storage requirement");
                rejects(IllegalStateException.class, () -> session.importLibrary("MINTSIG 1\nabi=sysv64\nentry\tvoid(void)\n", true), "PE signature libraries refuse foreign calling convention through JNI");
                if(summary.contains("arch=x86-32")){session.edit(entries[0],"prototype","@stdcall32 uint32_t(uint32_t first,uint32_t second)");String abi=session.abi(entries[0]);check(abi.contains("Calling convention: stdcall32")&&abi.contains("entry SP 4")&&abi.contains("entry SP 8"),"PE32 explicit Windows stack convention reports exact callee-entry storage");}
            }
            check(!session.debugInfo().isEmpty(), "bounded DWARF capability/limitations report crosses JNI");
            long debugEntry = functionNamed(session, "mint_debug_entry");
            if (debugEntry != -1 && session.debugInfo().contains("dwarf_fixture.c")) {
                check(session.types().contains("MintNode") && session.typesCHeader().contains("offsetof(MintNode, next)"), "real DWARF types reach Program and C header through JNI");
                check(session.sourceLocation(debugEntry).contains("dwarf_fixture.c:"), "real DWARF line locations reach synchronized JNI views");
                String code = session.decompiledC(debugEntry);
                check(code.contains("MintNode") && code.contains("DWARF source:") && code.contains("Mint field offset"), "real DWARF prototype/source/field evidence reaches actual pseudo-C through JNI");
                check(session.programPrototypes().contains("MintNode"), "DWARF-derived prototypes reach exported program header through JNI");
            }
            if (Path.of(path).getFileName().toString().endsWith("-exceptions.so")) {
                String exceptions = session.cxxMetadata();
                check(exceptions.contains("LLVM/GNU Itanium LSDA inventory") && exceptions.contains("landing-pad=0x") && exceptions.contains("catch(...)"),
                        "real C++ fixture exposes bounded call-site/landing-pad/catch-all metadata through JNI");
                long[] entries = new long[256]; int count = session.functions(0, 256, entries, new int[256], new int[256], new int[256], new int[256], new String[256]);
                boolean unwindRoot = false;
                for (int i = 0; i < count; i++) unwindRoot |= session.provenance(entries[i]).contains("Origin: unwind");
                check(unwindRoot, "real headerless .eh_frame roots retain unwind provenance across JNI");
            }
        }
    }

    public static void main(String[] args) throws Exception {
        System.out.println("engine: " + NativeCore.engineInfo());
        Path directory = Files.createTempDirectory("mint-platform-jni-");
        try {
            rawProgram(directory);
            rawArchitectures(directory);
            powerWorkflow(directory);
            localAndAbiWorkflow(directory);
            debuggerMappingWorkflow(directory);
            selectedMachO(directory);
            Path native32 = directory.resolve("synthetic-elf32.elf"), windows32 = directory.resolve("synthetic-pe32.exe");
            Files.write(native32, elf32()); Files.write(windows32, pe32());
            nativeContainer(native32.toString(),directory); nativeContainer(windows32.toString(),directory);
            for (String argument : args) nativeContainer(argument,directory);
        } finally {
            // Only this probe's newly owned temporary tree is removed.
            try (Stream<Path> paths = Files.walk(directory)) {
                for (Path owned : (Iterable<Path>) paths.sorted(Comparator.reverseOrder())::iterator) Files.deleteIfExists(owned);
            }
        }
        System.out.println("platform JNI contracts: " + checks + " checks, " + failures + " failures");
        if (failures != 0) throw new AssertionError("platform JNI contract failures: " + failures);
    }
}
