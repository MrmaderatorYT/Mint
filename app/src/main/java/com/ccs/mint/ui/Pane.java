package com.ccs.mint.ui;

import com.ccs.mint.R;

/**
 * The workspace destinations, in the order the tab strip shows them.
 *
 * <p>Small integers rather than {@code R.id} values, because a pane survives in
 * saved instance state and in the ViewModel. Resource identifiers are only stable
 * within one build of the app; a value written by one build and read back by the
 * next would silently select a different pane.
 */
final class Pane {

    static final int FUNCTIONS = 0;
    static final int DISASM = 1;
    static final int IR = 2;
    static final int C = 3;
    static final int GRAPH = 4;
    static final int LOG = 5;

    /** Tab labels, indexed by pane. */
    static final int[] TITLES = {
            R.string.pane_functions,
            R.string.pane_disasm,
            R.string.pane_ir,
            R.string.pane_c,
            R.string.pane_graph,
            R.string.pane_log,
    };

    static final int COUNT = TITLES.length;

    static boolean valid(int pane) {
        return pane >= 0 && pane < COUNT;
    }

    private Pane() {}
}
