package com.ccs.mint.ui;

import org.junit.Test;
import static org.junit.Assert.*;

public final class WorkspaceHelpTest {
    @Test public void everyHelpTopicIsReachableOnce() {
        boolean[] seen = new boolean[20];
        for (int[] group : WorkspaceHelp.GROUPS) {
            assertTrue(group.length > 0);
            for (int topic : group) {
                assertTrue(topic >= 0 && topic < seen.length);
                assertFalse("Duplicate help topic " + topic, seen[topic]);
                seen[topic] = true;
            }
        }
        for (int i = 0; i < seen.length; ++i) assertTrue("Missing topic " + i, seen[i]);
    }
}
