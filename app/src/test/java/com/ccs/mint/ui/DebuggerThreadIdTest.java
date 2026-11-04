package com.ccs.mint.ui;

import org.junit.Test;
import static org.junit.Assert.*;

public final class DebuggerThreadIdTest {
    @Test public void preservesProcessAndUnsignedThreadIdentity() {
        DebuggerThreadId first = DebuggerThreadId.parse("p1.ffffffffffffffff");
        DebuggerThreadId second = DebuggerThreadId.parse("p2.ffffffffffffffff");
        assertEquals(1, first.process); assertEquals(2, second.process);
        assertEquals(-1L, first.thread); assertEquals(first.thread, second.thread);
        assertEquals(-1L, DebuggerThreadId.parse("pffffffffffffffff.1").process);
        assertEquals(42, DebuggerThreadId.parse("42").thread);
        assertEquals(0, DebuggerThreadId.parse("42").process);
    }
    @Test public void rejectsInvalidAndAmbiguousIdentities() {
        for (String value : new String[]{"", "0", "-1", "+1", "p0.1", "p1.0", "p.1", "p1.", "p1.2.3", "p-1.2", "p10000000000000000.2"}) {
            try { DebuggerThreadId.parse(value); fail(value); } catch (NumberFormatException expected) { }
        }
    }
}
