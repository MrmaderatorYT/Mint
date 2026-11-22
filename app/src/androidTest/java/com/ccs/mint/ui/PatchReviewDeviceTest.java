package com.ccs.mint.ui;

import android.content.Context;
import android.text.Spanned;
import android.text.style.BackgroundColorSpan;
import android.text.style.ForegroundColorSpan;
import android.view.ContextThemeWrapper;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.ccs.mint.R;
import com.ccs.mint.core.MintSession;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.Assert.*;

@RunWith(AndroidJUnit4.class)
public final class PatchReviewDeviceTest {
    @Test public void comparisonHighlightsChangedInstructionsAndPseudoC() {
        Context context = new ContextThemeWrapper(
                InstrumentationRegistry.getInstrumentation().getTargetContext(), R.style.Theme_Mint);
        Highlighter highlighter = new Highlighter(context);
        PatchDialogCode presentation = new PatchDialogCode(context, highlighter);
        Spanned comparison = (Spanned) presentation.comparison(0x1000, "20 00 80 d2", "40 00 80 d2",
                new long[]{0x1000, 0x1000, 0x1008},
                new String[]{"1000  mov x0, #1\n1004  ret\n", "return 1;\n"},
                new String[]{"1000  mov x0, #2\n1004  ret\n", "return 2;\n"});

        assertFalse(comparison.toString().contains("1004  ret"));
        int oldInstruction = indexOf(comparison, "− 1000  mov x0, #1");
        int newInstruction = indexOf(comparison, "+ 1000  mov x0, #2");
        BackgroundColorSpan oldLine = highlightAt(comparison, oldInstruction);
        BackgroundColorSpan newLine = highlightAt(comparison, newInstruction);
        assertEquals(oldInstruction, comparison.getSpanStart(oldLine));
        assertEquals(newInstruction, comparison.getSpanStart(newLine));
        assertNotEquals(0, oldLine.getBackgroundColor());
        assertNotEquals(0, newLine.getBackgroundColor());
        assertNotEquals(oldLine.getBackgroundColor(), newLine.getBackgroundColor());
        assertEquals(newLine.getBackgroundColor(),
                highlightAt(comparison, indexOf(comparison, "+ return 2;")).getBackgroundColor());

        Spanned source = highlighter.assemblySource("mov x0, #2\nret");
        assertEquals("mov x0, #2\nret", source.toString());
        assertTrue(source.getSpans(0, source.length(), ForegroundColorSpan.class).length >= 4);
    }

    private static int indexOf(Spanned text, String line) {
        int index = text.toString().indexOf(line);
        assertTrue(line, index >= 0);
        return index;
    }

    private static BackgroundColorSpan highlightAt(Spanned text, int start) {
        BackgroundColorSpan[] spans = text.getSpans(start, start + 1, BackgroundColorSpan.class);
        assertEquals(1, spans.length);
        return spans[0];
    }

    @Test public void reviewExpiresAfterAnEditOrWorkspaceChange() throws Exception {
        final long entry = 0x1000;
        final Path cache = InstrumentationRegistry.getInstrumentation().getTargetContext().getCacheDir().toPath();
        final Path temp = Files.createTempDirectory(cache, "patch-review-");
        final Path input = temp.resolve("input.bin");
        final Path project = temp.resolve("test.mint");
        final Path analysis = temp.resolve("test.mint.analysis");
        final Path exported = temp.resolve("export.bin");
        final byte[] original = {0x20, 0, (byte) 0x80, (byte) 0xd2, (byte) 0xc0, 3, 0x5f, (byte) 0xd6};
        Files.write(input, original);
        try (MintSession session = MintSession.openRaw(input.toString(), "aarch64", entry, entry);
             MintSession other = MintSession.openRaw(input.toString(), "aarch64", entry, entry)) {
            session.attachProject(project.toString());
            session.analyze();
            assertArrayEquals(new long[]{entry, entry, entry + original.length}, session.functionRangeAt(entry + 4));
            assertNull(session.functionRangeAt(entry + original.length));
            assertEquals("20 00 80 d2", session.patchReviewBytes(entry, 4));
            long previous = session.programRevision();
            session.edit(entry, "patch", "40 00 80 d2");
            assertEquals(previous + 1, session.programRevision());
            assertEquals("40 00 80 d2", session.patchReviewBytes(entry, 4));
            var review = new WorkspaceActivity.PatchReview(session, session.programRevision(), "test", true, true,
                    "stale patch review");
            review.requireCurrent(session);
            assertThrows(IllegalStateException.class, () -> review.requireCurrent(other));
            session.exportPatchedCopy(exported.toString());
            byte[] expected = original.clone();
            expected[0] = 0x40;
            assertArrayEquals(expected, Files.readAllBytes(exported));
            assertArrayEquals(original, Files.readAllBytes(input));
            session.edit(entry, "comment", "Fixture metadata change");
            assertThrows(IllegalStateException.class, () -> review.requireCurrent(session));
            session.undoEdit(false);
            session.undoEdit(false);
            assertEquals("20 00 80 d2", session.patchReviewBytes(entry, 4));
            assertThrows(IllegalStateException.class, () -> review.requireCurrent(session));
            assertEquals("complete", PatchComparison.status(session.decompileView(entry)[0]));
            session.edit(entry + 4, "patch", "20 00 1f d6"); // br x1 leaves the branch target unknown.
            assertEquals("partial", PatchComparison.status(session.decompileView(entry)[0]));
        } finally {
            for (Path file : new Path[]{exported, analysis, project, input, temp}) Files.deleteIfExists(file);
        }
    }
}
