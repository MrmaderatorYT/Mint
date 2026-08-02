package com.ccs.mint.ui;

import android.content.Context;
import android.text.SpannableStringBuilder;
import android.text.Spanned;
import android.text.style.ForegroundColorSpan;

import androidx.annotation.NonNull;
import androidx.core.content.ContextCompat;

import com.ccs.mint.R;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * Colours disassembly and pseudo-C.
 *
 * <p>Hand-written scanners rather than regular expressions. The pseudo-C for one
 * function runs to a few thousand lines, and a pattern applied repeatedly over text
 * that size is both slower and easier to get quadratically wrong than a single pass
 * that walks the characters once.
 *
 * <p>Colours are resolved once into an instance. Looking them up per token would put
 * a resource lookup inside the inner loop of something that runs for every visible
 * row in a list.
 */
public final class Highlighter {

    private static final Set<String> C_KEYWORDS = new HashSet<>(Arrays.asList(
            "if", "else", "goto", "return", "while", "for", "do", "switch", "case",
            "break", "continue", "default", "sizeof"));

    private static final Set<String> C_TYPES = new HashSet<>(Arrays.asList(
            "void", "bool", "float", "double", "char", "int", "unsigned", "signed",
            "uint8_t", "uint16_t", "uint32_t", "uint64_t", "int8_t", "int16_t",
            "int32_t", "int64_t", "uintptr_t", "__uint128_t"));

    /**
     * Mnemonic prefixes that change control flow. Matched by prefix because AArch64
     * spells a whole family of conditional branches as {@code b.eq}, {@code b.hi} and
     * so on, and listing them all would go stale the moment a lifter learns another.
     */
    private static final String[] FLOW_PREFIXES = {
            "b", "bl", "br", "blr", "ret", "cbz", "cbnz", "tbz", "tbnz", "j", "call",
            "jmp", "ret", "loop"};

    private final int address;
    private final int flow;
    private final int mnemonic;
    private final int register;
    private final int number;
    private final int comment;
    private final int keyword;
    private final int type;
    private final int call;

    public Highlighter(@NonNull Context context) {
        address = ContextCompat.getColor(context, R.color.syn_address);
        flow = ContextCompat.getColor(context, R.color.syn_flow);
        mnemonic = ContextCompat.getColor(context, R.color.syn_mnemonic);
        register = ContextCompat.getColor(context, R.color.syn_register);
        number = ContextCompat.getColor(context, R.color.syn_number);
        comment = ContextCompat.getColor(context, R.color.syn_comment);
        keyword = ContextCompat.getColor(context, R.color.syn_keyword);
        type = ContextCompat.getColor(context, R.color.syn_type);
        call = ContextCompat.getColor(context, R.color.syn_call);
    }

    // -------------------------------------------------------------- disassembly

    /**
     * Colours one listing line: {@code "0009c8c4  cbz x0, 0x9c8d0"}, plus an optional
     * trailing note such as a resolved branch target.
     */
    @NonNull
    public CharSequence assembly(@NonNull String line, String note) {
        SpannableStringBuilder out = new SpannableStringBuilder(line);
        int cursor = 0;
        final int length = line.length();

        // The address column: everything up to the first run of spaces.
        int end = 0;
        while (end < length && !isSpace(line.charAt(end))) end++;
        if (end > 0) {
            paint(out, 0, end, address);
            cursor = end;
        }

        // The mnemonic: the next word. Control flow gets its own colour, because
        // where a block ends is the first thing being looked for when reading a
        // listing, and it should be findable without reading the text.
        cursor = skipSpaces(line, cursor);
        int wordEnd = cursor;
        while (wordEnd < length && !isSpace(line.charAt(wordEnd))) wordEnd++;
        if (wordEnd > cursor) {
            paint(out, cursor, wordEnd, isFlow(line.substring(cursor, wordEnd))
                    ? flow : mnemonic);
            cursor = wordEnd;
        }

        paintOperands(out, line, cursor, length);

        if (note != null && !note.isEmpty()) {
            final int start = out.length();
            out.append("   ").append(note);
            paint(out, start, out.length(), comment);
        }
        return out;
    }

    private void paintOperands(SpannableStringBuilder out, String line, int from, int to) {
        int i = from;
        while (i < to) {
            final char c = line.charAt(i);
            if (isHexStart(line, i)) {
                int end = i + 2;
                while (end < to && isHexDigit(line.charAt(end))) end++;
                paint(out, i, end, number);
                i = end;
            } else if (c == '#' || Character.isDigit(c)) {
                int end = i + 1;
                while (end < to && (Character.isLetterOrDigit(line.charAt(end)))) end++;
                paint(out, i, end, number);
                i = end;
            } else if (Character.isLetter(c) || c == '_') {
                int end = i;
                while (end < to && (Character.isLetterOrDigit(line.charAt(end))
                        || line.charAt(end) == '_' || line.charAt(end) == '.')) {
                    end++;
                }
                if (isRegister(line, i, end)) paint(out, i, end, register);
                i = end;
            } else {
                i++;
            }
        }
    }

    /**
     * Whether a word looks like a machine register.
     *
     * <p>Deliberately shape-based rather than a table: the same highlighter serves
     * AArch64 and x86-64, and both name most registers as a letter or two followed by
     * a number. Getting this wrong only leaves a word uncoloured.
     */
    private static boolean isRegister(String line, int start, int end) {
        final int length = end - start;
        if (length < 2 || length > 5) return start < end && isNamedRegister(line, start, end);
        final char first = Character.toLowerCase(line.charAt(start));
        if (first != 'x' && first != 'w' && first != 'r' && first != 'v' && first != 'q'
                && first != 'd' && first != 's' && first != 'h' && first != 'b'
                && first != 'e') {
            return isNamedRegister(line, start, end);
        }
        boolean digits = false;
        for (int i = start + 1; i < end; i++) {
            if (!Character.isDigit(line.charAt(i))) return isNamedRegister(line, start, end);
            digits = true;
        }
        return digits;
    }

    private static boolean isNamedRegister(String line, int start, int end) {
        final String word = line.substring(start, end).toLowerCase();
        switch (word) {
            case "sp": case "lr": case "pc": case "fp": case "xzr": case "wzr":
            case "rax": case "rbx": case "rcx": case "rdx": case "rsi": case "rdi":
            case "rsp": case "rbp": case "rip": case "eax": case "ebx": case "ecx":
            case "edx": case "esi": case "edi": case "esp": case "ebp":
                return true;
            default:
                return false;
        }
    }

    private static boolean isFlow(String word) {
        final int dot = word.indexOf('.');
        final String base = (dot < 0 ? word : word.substring(0, dot)).toLowerCase();
        for (String prefix : FLOW_PREFIXES) {
            if (base.equals(prefix)) return true;
        }
        return base.startsWith("ret") || base.startsWith("br") || base.startsWith("cb")
                || base.startsWith("tb");
    }

    // ------------------------------------------------------------------ C and IR

    /** Colours pseudo-C or an IR listing. */
    @NonNull
    public CharSequence code(@NonNull String source) {
        SpannableStringBuilder out = new SpannableStringBuilder(source);
        final int length = source.length();
        int i = 0;
        while (i < length) {
            final char c = source.charAt(i);

            if (c == '/' && i + 1 < length && source.charAt(i + 1) == '*') {
                int end = source.indexOf("*/", i + 2);
                end = end < 0 ? length : end + 2;
                paint(out, i, end, comment);
                i = end;
                continue;
            }
            if (c == ';' && lineIsComment(source, i)) {
                int end = source.indexOf('\n', i);
                end = end < 0 ? length : end;
                paint(out, i, end, comment);
                i = end;
                continue;
            }
            if (isHexStart(source, i)) {
                int end = i + 2;
                while (end < length && isHexDigit(source.charAt(end))) end++;
                paint(out, i, end, number);
                i = end;
                continue;
            }
            if (Character.isDigit(c)) {
                int end = i;
                while (end < length && Character.isLetterOrDigit(source.charAt(end))) end++;
                paint(out, i, end, number);
                i = end;
                continue;
            }
            if (Character.isLetter(c) || c == '_') {
                int end = i;
                while (end < length && (Character.isLetterOrDigit(source.charAt(end))
                        || source.charAt(end) == '_')) {
                    end++;
                }
                final String word = source.substring(i, end);
                if (C_KEYWORDS.contains(word)) {
                    paint(out, i, end, keyword);
                } else if (C_TYPES.contains(word)) {
                    paint(out, i, end, type);
                } else if (end < length && source.charAt(end) == '(') {
                    paint(out, i, end, call);
                }
                i = end;
                continue;
            }
            i++;
        }
        return out;
    }

    /** True when the semicolon at {@code index} starts an IR-style trailing comment. */
    private static boolean lineIsComment(String source, int index) {
        for (int i = index - 1; i >= 0; i--) {
            final char c = source.charAt(i);
            if (c == '\n') return true;
            if (!isSpace(c)) return false;
        }
        return true;
    }

    // ----------------------------------------------------------------- utilities

    private static void paint(SpannableStringBuilder out, int start, int end, int colour) {
        if (start >= end || end > out.length()) return;
        out.setSpan(new ForegroundColorSpan(colour), start, end,
                Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
    }

    private static boolean isSpace(char c) { return c == ' ' || c == '\t'; }

    private static int skipSpaces(String text, int from) {
        int i = from;
        while (i < text.length() && isSpace(text.charAt(i))) i++;
        return i;
    }

    private static boolean isHexStart(String text, int index) {
        return index + 2 < text.length() && text.charAt(index) == '0'
                && (text.charAt(index + 1) == 'x' || text.charAt(index + 1) == 'X')
                && isHexDigit(text.charAt(index + 2));
    }

    private static boolean isHexDigit(char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }
}
