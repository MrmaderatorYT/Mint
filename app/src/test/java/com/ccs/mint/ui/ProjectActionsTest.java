package com.ccs.mint.ui;

import org.junit.Test;
import static org.junit.Assert.*;

public final class ProjectActionsTest {
    @Test public void allActionsAreReachableExactlyOnce() {
        assertEquals(ProjectActions.GROUPS.length, ProjectActions.ITEMS.length);
        boolean[] seen = new boolean[ProjectActions.LABELS.length];
        for (int[] group : ProjectActions.ITEMS) {
            assertTrue(group.length > 0);
            for (int action : group) {
                assertTrue(action >= 0 && action < seen.length);
                assertFalse("Duplicate action " + action, seen[action]);
                seen[action] = true;
            }
        }
        for (int i = 0; i < seen.length; ++i) assertTrue("Missing action " + i, seen[i]);
    }
}
