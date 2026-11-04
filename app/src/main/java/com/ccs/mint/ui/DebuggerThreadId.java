package com.ccs.mint.ui;

/** Exact RSP process/thread identity, represented as unsigned 64-bit bit patterns. */
final class DebuggerThreadId {
    final long process;
    final long thread;
    private DebuggerThreadId(long process, long thread) { this.process = process; this.thread = thread; }

    private static long number(String text, int radix) {
        if (text.isEmpty()) throw new NumberFormatException("empty ID");
        for (int i = 0; i < text.length(); ++i) {
            char c = text.charAt(i);
            if (!((c >= '0' && c <= '9') || (radix == 16 && ((c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))))
                throw new NumberFormatException("invalid ID");
        }
        long result = Long.parseUnsignedLong(text, radix);
        if (result == 0) throw new NumberFormatException("zero ID");
        return result;
    }

    static DebuggerThreadId parse(String key) {
        if (!key.startsWith("p")) return new DebuggerThreadId(0, number(key, 10));
        int dot = key.indexOf('.');
        if (dot < 0 || dot != key.lastIndexOf('.')) throw new NumberFormatException("invalid process/thread pair");
        return new DebuggerThreadId(number(key.substring(1, dot), 16), number(key.substring(dot + 1), 16));
    }
}
