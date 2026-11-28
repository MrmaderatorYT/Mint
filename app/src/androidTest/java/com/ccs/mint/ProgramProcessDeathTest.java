package com.ccs.mint;

import android.content.Context;
import android.os.Process;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import com.ccs.mint.core.MintSession;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.stream.Stream;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.junit.Assert.*;
import static org.junit.Assume.assumeTrue;

/** Two instrumentation launches exercise process death without touching normal projects. */
@RunWith(AndroidJUnit4.class)
public class ProgramProcessDeathTest {
    private static final long ENTRY = 0x1000L;
    private static final byte[] SOURCE = {
            (byte) 0xe0, 0, (byte) 0x80, (byte) 0xd2,
            (byte) 0xc0, 3, 0x5f, (byte) 0xd6
    };
    private static final String PATCH = "20 01 80 d2";
    private static final String ORIGINAL_BYTES = "e0 00 80 d2";
    private static final String NOTE = "Committed before Android process death";

    private static Path fixture(String phase) {
        final var args = InstrumentationRegistry.getArguments();
        assumeTrue(phase.equals(args.getString("mintRecoveryPhase")));
        final String token = args.getString("mintRecoveryToken", "");
        assertTrue("An invocation-specific token is required", token.matches("[a-f0-9]{32}"));
        final Context target = InstrumentationRegistry.getInstrumentation().getTargetContext();
        return target.getCacheDir().toPath().resolve("mint-process-death-" + token);
    }

    private static MintSession open(Path folder, String project, boolean full) throws Exception {
        final MintSession session = MintSession.openRaw(
                folder.resolve("input.bin").toString(), "aarch64", ENTRY, ENTRY);
        try {
            session.attachProject(folder.resolve(project).toString());
            if (full) session.reanalyze();
            else session.analyze();
            return session;
        } catch (Exception | Error failure) {
            session.close();
            throw failure;
        }
    }

    @Test public void commitAndKill() throws Exception {
        final Path directory = fixture("write");
        Files.createDirectory(directory);
        Files.write(directory.resolve("input.bin"), SOURCE);
        try (MintSession session = open(directory, "program.mint", false)) {
            session.edit(ENTRY, "name", "process_death_entry");
            session.edit(ENTRY, "comment", NOTE);
            session.defineType("ProcessDeathRecord=struct{value:u64}");
            session.edit(ENTRY, "prototype", "uint64_t(void)");
            session.edit(ENTRY, "patch", PATCH);
            session.undoEdit(false);
            assertEquals(ORIGINAL_BYTES, session.patchReviewBytes(ENTRY, 4));
            session.undoEdit(true);
            assertEquals(PATCH, session.annotation(ENTRY, "patch"));
            assertEquals(PATCH, session.patchReviewBytes(ENTRY, 4));
            assertTrue(session.functionIr(ENTRY).contains("9:8"));
            Files.write(directory.resolve("pid"),
                    Integer.toString(Process.myPid()).getBytes(StandardCharsets.US_ASCII));

            // The host runner expects Android to terminate this instrumentation
            // launch. Leave the native handle live to bypass graceful shutdown.
            Process.killProcess(Process.myPid());
            fail("Expected Android to kill the current process");
        }
    }

    @Test public void reopenInNewProcess() throws Exception {
        final Path directory = fixture("read");
        assertTrue("The previous instrumentation launch must commit the fixture", Files.isDirectory(directory));
        try {
            final int previousPid = Integer.parseInt(new String(
                    Files.readAllBytes(directory.resolve("pid")), StandardCharsets.US_ASCII));
            assertNotEquals(previousPid, Process.myPid());
            final Path program = directory.resolve("program.mint");
            final Path cache = directory.resolve("program.mint.analysis");
            assertTrue("The previous process populated a derived cache", Files.size(cache) > 4);
            final byte[] committed = Files.readAllBytes(program);
            Files.copy(program, directory.resolve("oracle.mint"));
            assertFalse(Files.exists(directory.resolve("oracle.mint.analysis")));
            try (MintSession oracle = open(directory, "oracle.mint", true)) {
                assertMode(oracle, "full");
                try (MintSession warm = open(directory, "program.mint", false)) {
                    assertMode(warm, "restored");
                    assertEquivalent(oracle, warm);
                }

                Files.write(cache, new byte[] {0, 1, 2, 3});
                try (MintSession recovered = open(directory, "program.mint", false)) {
                    assertMode(recovered, "full");
                    assertEquivalent(oracle, recovered);
                    final Path exported = directory.resolve("exported.bin");
                    recovered.exportPatchedCopy(exported.toString());
                    byte[] expected = SOURCE.clone();
                    expected[0] = 0x20;
                    expected[1] = 0x01;
                    assertArrayEquals(expected, Files.readAllBytes(exported));
                }
                assertTrue("Recovery replaced the corrupt cache", Files.size(cache) > 4);
                try (MintSession reopened = open(directory, "program.mint", false)) {
                    assertMode(reopened, "restored");
                    assertEquivalent(oracle, reopened);
                }
            }
            assertArrayEquals("Derived cache recovery must leave Program intact", committed, Files.readAllBytes(program));
            assertArrayEquals(SOURCE, Files.readAllBytes(directory.resolve("input.bin")));
        } finally {
            try (Stream<Path> files = Files.walk(directory)) {
                for (Path path : (Iterable<Path>) files.sorted(Comparator.reverseOrder())::iterator) {
                    Files.delete(path);
                }
            }
        }
    }

    private static void assertMode(MintSession session, String expected) {
        final String warnings = session.warnings();
        assertTrue(warnings, warnings.contains("mode=" + expected + " "));
    }

    private static void assertEquivalent(MintSession oracle, MintSession candidate) {
        assertEquals("process_death_entry", candidate.annotation(ENTRY, "name"));
        assertEquals(NOTE, candidate.annotation(ENTRY, "comment"));
        assertEquals("uint64_t(void)", candidate.annotation(ENTRY, "prototype"));
        assertEquals(PATCH, candidate.annotation(ENTRY, "patch"));
        assertEquals(PATCH, candidate.patchReviewBytes(ENTRY, 4));
        assertTrue(candidate.typesCHeader().contains("ProcessDeathRecord"));
        assertTrue(candidate.functionIr(ENTRY).contains("9:8"));
        assertEquals(oracle.functionCount(), candidate.functionCount());
        assertArrayEquals(oracle.functionRangeAt(ENTRY), candidate.functionRangeAt(ENTRY));
        assertEquals(oracle.cfg(ENTRY), candidate.cfg(ENTRY));
        assertEquals(oracle.functionIr(ENTRY), candidate.functionIr(ENTRY));
        assertArrayEquals(oracle.decompileView(ENTRY), candidate.decompileView(ENTRY));
        assertEquals(oracle.xrefs(ENTRY), candidate.xrefs(ENTRY));
        assertEquals(oracle.typesCHeader(), candidate.typesCHeader());
    }
}
