import com.ccs.mint.core.MintSession;
import com.ccs.mint.core.NativeCore;

/**
 * Exercises the real JNI layer on a desktop JVM.
 *
 * <p>The engine itself is tested by mint_probe, but that never crosses JNI. The
 * marshalling is where the risk actually lives: six parallel output arrays per
 * call, local-reference lifetime for every string, and bounds checks that must
 * hold when a caller passes mismatched array lengths. Those paths have no
 * equivalent in the C++ probe, and without this they would first run on a user's
 * phone.
 *
 * <p>Deliberately hostile in places — short arrays, null columns, out-of-range
 * offsets, double close — because those are the cases a real UI will produce
 * while scrolling and rotating.
 */
public final class JniProbe {

    private static int failures = 0;

    private static void check(boolean condition, String what) {
        if (condition) {
            System.out.println("  ok   " + what);
        } else {
            System.out.println("  FAIL " + what);
            failures++;
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("usage: JniProbe <file.so>");
            System.exit(2);
        }

        System.out.println("engine: " + NativeCore.engineInfo());

        try (MintSession session = MintSession.open(args[0])) {
            System.out.println("\n-- image summary --");
            System.out.println(session.imageSummary());

            session.analyze();

            long[] stats = new long[MintSession.STAT_COUNT];
            session.stats(stats);
            System.out.println("\n-- stats --");
            System.out.println("  instructions        " + stats[MintSession.STAT_INSTRUCTIONS]);
            System.out.println("  functions           " + stats[MintSession.STAT_FUNCTIONS]);
            System.out.println("  blocks              " + stats[MintSession.STAT_BLOCKS]);
            System.out.println("  edges               " + stats[MintSession.STAT_EDGES]);
            System.out.println("  indirect jumps      " + stats[MintSession.STAT_INDIRECT_JUMPS]);
            System.out.println("  incomplete          " + stats[MintSession.STAT_INCOMPLETE_FUNCTIONS]);

            System.out.println("\n-- marshalling --");
            check(stats[MintSession.STAT_INSTRUCTIONS] > 1000, "instruction count crossed JNI");

            int total = session.functionCount();
            check(total == (int) stats[MintSession.STAT_FUNCTIONS],
                    "functionCount agrees with stats");

            // A normal page.
            int page = 64;
            long[] entry = new long[page];
            int[] size = new int[page];
            int[] blocks = new int[page];
            int[] insns = new int[page];
            int[] flags = new int[page];
            String[] names = new String[page];

            int got = session.functions(0, page, entry, size, blocks, insns, flags, names);
            check(got > 0 && got <= page, "function page returned " + got + " rows");

            boolean namesPopulated = true;
            boolean entriesAscending = true;
            for (int i = 0; i < got; i++) {
                if (names[i] == null || names[i].isEmpty()) namesPopulated = false;
                if (i > 0 && Long.compareUnsigned(entry[i], entry[i - 1]) <= 0) {
                    entriesAscending = false;
                }
            }
            check(namesPopulated, "every row got a non-empty name");
            check(entriesAscending, "function entries are strictly ascending");

            System.out.println("\n  first 5 functions:");
            for (int i = 0; i < Math.min(5, got); i++) {
                System.out.printf("    0x%08x  %3d blocks %4d insns flags=%d  %.50s%n",
                        entry[i], blocks[i], insns[i], flags[i], names[i]);
            }

            // Short arrays: the page must clamp to the smallest column, not
            // overrun. If the bounds logic is wrong this is where it corrupts the
            // heap, and the JVM notices.
            long[] shortEntry = new long[3];
            int gotShort = session.functions(0, page, shortEntry, size, blocks, insns,
                    flags, names);
            check(gotShort == 3, "page clamps to the shortest column (got " + gotShort + ")");

            // Null name column: skips string building entirely.
            int gotNoNames = session.functions(0, page, entry, size, blocks, insns, flags,
                    null);
            check(gotNoNames == got, "null name column still returns rows");

            // Offset past the end must return 0, not misbehave.
            check(session.functions(total + 1000, page, entry, size, blocks, insns, flags,
                    names) == 0, "offset past the end returns 0");
            check(session.functions(-1, page, entry, size, blocks, insns, flags, names) == 0,
                    "negative offset returns 0");
            check(session.functions(0, 0, entry, size, blocks, insns, flags, names) == 0,
                    "zero limit returns 0");

            // The listing, starting at the first function's entry.
            long[] addr = new long[page];
            int[] isize = new int[page];
            int[] flow = new int[page];
            long[] target = new long[page];
            String[] text = new String[page];
            String[] comment = new String[page];

            session.functions(0, 1, entry, size, blocks, insns, flags, names);
            long start = entry[0];
            int lines = session.listing(start, page, addr, isize, flow, target, text,
                    comment);
            check(lines > 0, "listing returned " + lines + " lines from 0x"
                    + Long.toHexString(start));

            boolean textPopulated = true;
            boolean addrAscending = true;
            for (int i = 0; i < lines; i++) {
                if (text[i] == null || text[i].isEmpty()) textPopulated = false;
                if (i > 0 && Long.compareUnsigned(addr[i], addr[i - 1]) <= 0) {
                    addrAscending = false;
                }
            }
            check(textPopulated, "every listing line got text");
            check(addrAscending, "listing addresses are ascending");

            System.out.println("\n  first 12 listing lines:");
            for (int i = 0; i < Math.min(12, lines); i++) {
                String c = (comment[i] == null || comment[i].isEmpty())
                        ? "" : "  ; " + comment[i];
                System.out.printf("    %08x  %-30s%s%n", addr[i], text[i], c);
            }

            // The IR crosses JNI as one string per function, so this is also a
            // check that a multi-kilobyte return value survives the trip.
            String ir = session.functionIr(start);
            check(!ir.isEmpty(), "IR for the first function crossed JNI ("
                    + ir.length() + " chars)");
            check(!ir.contains("structural checks"), "that IR passes the verifier");
            System.out.println("\n  first 6 IR lines:");
            String[] irLines = ir.split("\n");
            for (int i = 0; i < Math.min(6, irLines.length); i++) {
                System.out.println("    " + irLines[i]);
            }

            String pseudoC = session.decompiledC(start);
            check(!pseudoC.isEmpty(), "SSA pseudo-C crossed JNI (" + pseudoC.length() + " chars)");

            // Struct recovery is only worth having if it fires on ordinary code, so
            // measure it across a sample rather than asserting it works on one
            // hand-picked function.
            long[] sampleEntries = new long[page];
            int sampled = session.functions(0, page, sampleEntries, size, blocks, insns,
                    flags, null);
            int withLayout = 0;
            int fieldsFound = 0;
            for (int i = 0; i < sampled; i++) {
                String c = session.decompiledC(sampleEntries[i]);
                if (!c.contains("/* layout via ")) continue;
                withLayout++;
                for (int at = c.indexOf("+0x"); at >= 0; at = c.indexOf("+0x", at + 1)) {
                    fieldsFound++;
                }
            }
            check(withLayout > 0, "struct layouts recovered in " + withLayout + " of "
                    + sampled + " functions (" + fieldsFound + " fields)");

            // The call graph is whole-program and indexed rather than addressed, so
            // the things that can break it are all structural: a row per function,
            // indices inside the function table, and the entry column agreeing with
            // what the function pages already reported.
            String callGraph = session.callGraph();
            check(!callGraph.isEmpty(), "call graph crossed JNI ("
                    + callGraph.length() + " chars)");
            String[] graphRows = callGraph.split("\n");
            check(graphRows.length == total,
                    "call graph has one row per function (" + graphRows.length
                            + " rows for " + total + " functions)");

            boolean indicesInRange = true;
            boolean rowsInOrder = true;
            boolean entriesMatch = true;
            int edges = 0;
            int withCallees = 0;
            long[] firstPage = new long[page];
            session.functions(0, page, firstPage, size, blocks, insns, flags, null);
            for (int i = 0; i < graphRows.length; i++) {
                String[] fields = graphRows[i].trim().split("\\s+");
                if (fields.length < 2) {
                    rowsInOrder = false;
                    break;
                }
                if (Integer.parseInt(fields[0]) != i) rowsInOrder = false;
                if (i < page && Long.parseLong(fields[1]) != firstPage[i]) entriesMatch = false;
                if (fields.length > 2) withCallees++;
                for (int f = 2; f < fields.length; f++) {
                    int callee = Integer.parseInt(fields[f]);
                    if (callee < 0 || callee >= total) indicesInRange = false;
                    edges++;
                }
            }
            check(rowsInOrder, "call graph rows are indexed 0..n in order");
            check(entriesMatch, "call graph entry column matches the function table");
            check(indicesInRange, "every callee index is inside the function table");
            check(edges > 0, "call graph recovered " + edges + " direct call edges from "
                    + withCallees + " functions");

            String warnings = session.warnings();
            System.out.println("\n-- warnings (" + (warnings.isEmpty() ? 0
                    : warnings.split("\n").length) + ") --");
            if (!warnings.isEmpty()) System.out.println(warnings);

            check(session.isOpen(), "session reports open");
        }

        // Double close must be harmless: an Activity being destroyed twice is
        // ordinary Android behaviour.
        MintSession twice = MintSession.open(args[0]);
        twice.close();
        twice.close();
        check(!twice.isOpen(), "double close is safe and leaves the session closed");

        boolean threw = false;
        try {
            twice.functionCount();
        } catch (IllegalStateException expected) {
            threw = true;
        }
        check(threw, "use after close throws IllegalStateException");

        threw = false;
        try {
            MintSession.open("/nonexistent/path/to/nothing.so");
        } catch (Exception expected) {
            threw = true;
        }
        check(threw, "opening a missing file throws");

        System.out.println(failures == 0
                ? "\nALL JNI CHECKS PASSED"
                : "\n" + failures + " JNI CHECK(S) FAILED");
        System.exit(failures == 0 ? 0 : 1);
    }
}
