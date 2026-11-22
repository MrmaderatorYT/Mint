package com.ccs.mint.ui;

import org.junit.Test;
import static org.junit.Assert.*;

public class PatchComparisonTest {
    @Test public void isolatedEditsLeaveUnchangedInstructionsOut() {
        String diff = PatchComparison.diff("mov x0, #1\nkeep\nret\n", "mov x0, #2\nkeep\nbr x1\n");
        assertTrue(diff.contains("− mov x0, #1\n+ mov x0, #2"));
        assertTrue(diff.contains("− ret\n+ br x1"));
        assertFalse(diff.contains("keep"));
    }

    @Test public void missingCaptureIsDistinctFromNoChange() {
        assertEquals("No changes.\n", PatchComparison.diff("ret\n", "ret\n"));
        assertTrue(PatchComparison.diff(null, "ret\n").contains("unavailable"));
    }

    @Test public void reviewReadsStatusAndCountsRemovedPatchBytes() {
        assertEquals("partial", PatchComparison.status("/* Decompilation status: partial */\n/* unresolved */"));
        assertEquals("unavailable", PatchComparison.status(null));
        assertEquals(3, PatchComparison.byteCount(" 1f\t20\n03 "));
        assertEquals(0, PatchComparison.byteCount(" "));
    }
}
