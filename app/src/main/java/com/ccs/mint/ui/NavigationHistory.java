package com.ccs.mint.ui;

import java.util.ArrayDeque;
import java.util.Deque;

/** Address history for symbol and cross-reference navigation. */
public final class NavigationHistory {
    private final Deque<Long> back = new ArrayDeque<>();
    private final Deque<Long> forward = new ArrayDeque<>();
    private long current;
    private boolean initialized;

    public void push(long address) {
        // Going Back first updates current, then the Activity renders that address
        // through the same navigation path as a fresh jump. Re-pushing the current
        // address must always be a no-op, including after the final back entry was
        // popped; otherwise that last entry immediately recreates itself.
        if (initialized && address == current) return;
        if (initialized) back.push(current);
        current = address;
        initialized = true;
        forward.clear();
    }

    public long back() {
        if (back.isEmpty()) return current;
        forward.push(current);
        current = back.pop();
        return current;
    }

    public long forward() {
        if (forward.isEmpty()) return current;
        back.push(current);
        current = forward.pop();
        return current;
    }

    public long current() { return current; }
    public boolean canGoBack() { return !back.isEmpty(); }
    public boolean canGoForward() { return !forward.isEmpty(); }
    public void clear() { back.clear(); forward.clear(); current = 0; initialized = false; }
}
