package com.ccs.mint;

import android.content.Context;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.ccs.mint.core.MintSession;
import com.ccs.mint.core.RawArchitecture;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.stream.Stream;

import static org.junit.Assert.*;

/** Real device/JNI tests; fixtures never touch the user's workspace/projects. */
@RunWith(AndroidJUnit4.class)
public class PlatformDeviceTest {
    private static byte[] words(int... code) {
        ByteBuffer bytes = ByteBuffer.allocate(code.length * 4).order(ByteOrder.LITTLE_ENDIAN);
        for (int word : code) bytes.putInt(word);
        return bytes.array();
    }

    private static Path temporaryDirectory() throws Exception {
        Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
        return Files.createTempDirectory(context.getCacheDir().toPath(), "platform-device-test-");
    }

    private static void removeFixture(Path directory) throws Exception {
        try (Stream<Path> files = Files.walk(directory)) {
            for (Path path : (Iterable<Path>) files.sorted(Comparator.reverseOrder())::iterator) {
                Files.delete(path);
            }
        }
    }

    @Test
    public void allSevenTargetModesRunOnAndroidHost() throws Exception {
        Path directory = temporaryDirectory();
        try {
            RawArchitecture[] registry = MintSession.rawArchitectures();
            assertTrue(registry.length >= 7);
            String[] modes = {"aarch64", "x86-64", "arm", "thumb", "x86-32", "riscv32", "riscv64"};
            byte[][] code = {words(0xd28000e0, 0xd65f03c0),
                    {(byte) 0xb8, 7, 0, 0, 0, (byte) 0xc3},
                    words(0xe3a00007, 0xe12fff1e), {7, 0x20, 0x70, 0x47},
                    {(byte) 0xb8, 7, 0, 0, 0, (byte) 0xc3},
                    words(0x00700513, 0x00008067), words(0x00700513, 0x00008067)};
            for (int i = 0; i < modes.length; ++i) {
                Path input = directory.resolve(modes[i] + ".bin");
                Files.write(input, code[i]);
                try (MintSession session = MintSession.openRaw(input.toString(), modes[i], 0x3000, 0x3000)) {
                    session.analyze();
                    assertEquals(modes[i], 1, session.functionCount());
                    assertTrue(modes[i], session.functionIr(0x3000).contains("7"));
                    assertFalse(modes[i], session.decompiledC(0x3000).isEmpty());
                    assertFalse(modes[i], session.cfg(0x3000).isEmpty());
                    assertFalse(modes[i], session.assemble(0x3000, "ret", false).isEmpty());
                    assertTrue(modes[i], session.annotation(0x3000, "patch").isEmpty());
                }
            }
        } finally {
            removeFixture(directory);
        }
    }

    @Test
    public void editableProgramReopensWithTypesScriptsAndPatches() throws Exception {
        Path directory = temporaryDirectory();
        try {
            Path input = directory.resolve("source.bin"), project = directory.resolve("program.mint");
            Path target = directory.resolve("target.bin"), targetProject = directory.resolve("target.mint");
            Path exported = directory.resolve("patched.bin");
            byte[] original = words(0xd28000e0, 0xd65f03c0);
            Files.write(input, original);
            Files.write(target, original);
            try (MintSession session = MintSession.openRaw(input.toString(), "aarch64", 0x1000, 0x1000)) {
                session.attachProject(project.toString());
                session.analyze();
                session.edit(0x1000, "name", "device_entry");
                session.edit(0x1000, "comment", "Збережений коментар");
                session.defineType("Packet=struct{length:u32;flags:u32}");
                assertTrue(session.typesCHeader().contains("Packet"));
                assertTrue(session.search("device_entry").contains("device_entry"));
                assertTrue(session.runScript("print(mint.decompile('0x1000'))", false).contains("device_entry"));
                assertEquals("00 01 80 d2", session.assemble(0x1000, "mov x0, #8", false));
                assertTrue(session.annotation(0x1000, "patch").isEmpty());
                session.assemble(0x1000, "mov x0, #8", true);
                assertFalse(session.annotation(0x1000, "patch").isEmpty());
                session.undoEdit(false);
                assertTrue(session.annotation(0x1000, "patch").isEmpty());
                session.undoEdit(true);
                session.exportPatchedCopy(exported.toString());
                assertArrayEquals(original, Files.readAllBytes(input));
                assertFalse(java.util.Arrays.equals(original, Files.readAllBytes(exported)));
                assertFalse(session.openComparison(target.toString(), targetProject.toString(), true).isEmpty());
                assertTrue(session.comparison("preview", 0, 0, "").contains("0 applicable"));
            }
            try (MintSession reopened = MintSession.openRaw(input.toString(), "aarch64", 0x1000, 0x1000)) {
                reopened.attachProject(project.toString());
                reopened.analyze();
                assertEquals("device_entry", reopened.annotation(0x1000, "name"));
                assertEquals("Збережений коментар", reopened.annotation(0x1000, "comment"));
                assertTrue(reopened.typesCHeader().contains("Packet"));
                assertFalse(reopened.annotation(0x1000, "patch").isEmpty());
                assertTrue(reopened.functionIr(0x1000).contains("8"));
            }
        } finally {
            removeFixture(directory);
        }
    }

    @Test
    public void guardedLocalEditAndAuthoritativeAbiPersistWithoutCorruption() throws Exception {
        Path directory = temporaryDirectory();
        try {
            Path input = directory.resolve("stack-local.bin"), project = directory.resolve("local-program.mint");
            // mov x1,7; stur x1,[sp,-8]; ldur x2,[sp,-8]; add x0,x0,x2; ret.
            // A real initialized nonescaping leaf slot, not a synthetic local.
            byte[] original = words(0xd28000e1, 0xf81f83e1, 0xf85f83e2, 0x8b020000, 0xd65f03c0);
            Files.write(input, original);
            String identity = null;
            try (MintSession session = MintSession.openRaw(input.toString(), "aarch64", 0x1000, 0x1000)) {
                session.attachProject(project.toString());
                session.analyze();
                for (String line : session.locals(0x1000).split("\n")) {
                    String[] row = line.split("\t", -1);
                    if (row.length >= 5 && row[0].startsWith("stack:") && row[3].equals("8") && row[4].equals("stack -8")) {
                        identity = row[0];
                        break;
                    }
                }
                assertNotNull("native guarded eight-byte entry-stack local must exist", identity);
                session.editLocal(0x1000, identity, "device_counter", "uint64_t");
                String accepted = session.locals(0x1000);
                assertTrue(accepted.contains(identity + "\tdevice_counter\tuint64_t\t8\tstack -8"));
                assertTrue("accepted local name and type must reach actual emitted declaration",
                        session.decompiledC(0x1000).contains("uint64_t device_counter;"));
                byte[] acceptedProgram = Files.readAllBytes(project);
                try {
                    session.editLocal(0x1000, identity, "incompatible_width", "u32");
                    fail("eight-byte local must reject a four-byte reinterpretation");
                } catch (IllegalStateException expected) {
                    // Width rejection comes from the native semantic guard.
                }
                assertEquals("rejected local edit must preserve live accepted override", accepted, session.locals(0x1000));
                assertArrayEquals("rejected local edit must not corrupt persistent Program", acceptedProgram, Files.readAllBytes(project));
                session.edit(0x1000, "prototype", "@aapcs64 uint64_t(uint64_t a,uint64_t b,uint64_t c,uint64_t d,uint64_t e,uint64_t f,uint64_t g,uint64_t h,uint64_t i)");
                String abi = session.abi(0x1000);
                assertTrue(abi.contains("Calling convention: aapcs64"));
                assertTrue("ninth authoritative parameter must use callee-entry stack storage", abi.contains("arg 8") && abi.contains("entry SP 0"));
            }
            try (MintSession reopened = MintSession.openRaw(input.toString(), "aarch64", 0x1000, 0x1000)) {
                reopened.attachProject(project.toString());
                reopened.analyze();
                assertTrue("cold reopen must retain the same guarded binding", reopened.locals(0x1000).contains(identity + "\tdevice_counter\tuint64_t\t8\tstack -8"));
                assertTrue("cold reopen must apply both local name and exact type", reopened.decompiledC(0x1000).contains("uint64_t device_counter;"));
                String abi = reopened.abi(0x1000);
                assertTrue(abi.contains("Calling convention: aapcs64") && abi.contains("arg 8") && abi.contains("entry SP 0"));
            }
            assertArrayEquals("local/ABI edits are overlays and never change source bytes", original, Files.readAllBytes(input));
        } finally {
            removeFixture(directory);
        }
    }
}
