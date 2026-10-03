package com.ccs.mint;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.ccs.mint.ui.NavigationHistory;

import org.junit.Test;

/** Regression tests for the address navigation used by the real workspace UI. */
public final class NavigationHistoryTest {
    @Test public void addressZeroIsARealHistoryEntry() {
        NavigationHistory history=new NavigationHistory();history.push(0);history.push(4);
        assertTrue(history.canGoBack());assertEquals(0,history.back());history.push(0);
        assertFalse(history.canGoBack());assertTrue(history.canGoForward());assertEquals(4,history.forward());
    }
    @Test
    public void backAndForwardPreserveTargets() {
        NavigationHistory history = new NavigationHistory();
        history.push(0x1000);
        history.push(0x2000);
        history.push(0x3000);

        assertTrue(history.canGoBack());
        assertEquals(0x2000, history.back());
        assertEquals(0x1000, history.back());
        assertFalse(history.canGoBack());
        assertTrue(history.canGoForward());
        assertEquals(0x2000, history.forward());
        assertEquals(0x3000, history.forward());
    }

    @Test
    public void newTargetDropsForwardHistory() {
        NavigationHistory history = new NavigationHistory();
        history.push(1);
        history.push(2);
        history.back();
        history.push(3);
        assertFalse(history.canGoForward());
        assertEquals(3, history.current());
    }

    @Test
    public void renderingLastBackTargetDoesNotRecreateIt() {
        NavigationHistory history = new NavigationHistory();
        history.push(0x1000);
        history.push(0x2000);

        long restored = history.back();
        assertFalse(history.canGoBack());

        // WorkspaceActivity renders a history destination through jumpTo(), which
        // calls push(). That render must not manufacture another Back entry.
        history.push(restored);
        assertFalse(history.canGoBack());
        assertTrue(history.canGoForward());
        assertEquals(0x1000, history.current());
    }
}
