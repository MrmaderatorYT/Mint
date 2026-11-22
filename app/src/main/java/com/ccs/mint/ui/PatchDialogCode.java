package com.ccs.mint.ui;

import android.content.Context;
import android.graphics.Typeface;
import android.text.Editable;
import android.text.SpannableStringBuilder;
import android.text.Spanned;
import android.text.TextWatcher;
import android.text.style.BackgroundColorSpan;
import android.text.style.ForegroundColorSpan;
import android.text.style.StyleSpan;
import android.widget.EditText;
import android.widget.ScrollView;
import android.widget.TextView;

import com.ccs.mint.R;
import com.google.android.material.color.MaterialColors;

/** Formatting shared by assembly preview and patch comparison. */
final class PatchDialogCode {
    private static final int LIVE_HIGHLIGHT_LIMIT = 4096;
    private static final int DIFF_HIGHLIGHT_LIMIT = 65536;

    private final Context context;
    private final Highlighter highlighter;
    private final int removed;
    private final int added;

    PatchDialogCode(Context context, Highlighter highlighter) {
        this.context = context;
        this.highlighter = highlighter;
        removed = MaterialColors.getColor(context, com.google.android.material.R.attr.colorErrorContainer, 0);
        added = MaterialColors.getColor(context, com.google.android.material.R.attr.colorPrimaryContainer, 0);
    }

    void attachAssemblyHighlighting(EditText editor) {
        editor.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence text, int start, int count, int after) {}
            @Override public void onTextChanged(CharSequence text, int start, int before, int count) {}

            @Override public void afterTextChanged(Editable text) {
                for (ForegroundColorSpan old : text.getSpans(0, text.length(), ForegroundColorSpan.class)) {
                    text.removeSpan(old);
                }
                if (text.length() > LIVE_HIGHLIGHT_LIMIT) return;
                Spanned styled = highlighter.assemblySource(text.toString());
                for (ForegroundColorSpan color : styled.getSpans(0, styled.length(), ForegroundColorSpan.class)) {
                    text.setSpan(color, styled.getSpanStart(color), styled.getSpanEnd(color),
                            Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
                }
            }
        });
    }

    CharSequence preview(long address, String source, String before, String after) {
        SpannableStringBuilder text = new SpannableStringBuilder();
        heading(text, context.getString(R.string.patch_at_address, address));
        text.append('\n');
        heading(text, context.getString(R.string.patch_assembly_source));
        text.append(highlighter.assemblySource(source)).append("\n\n");
        appendBytes(text, before, after);
        int length = PatchComparison.byteCount(after);
        text.append('\n').append(context.getResources().getQuantityString(
                R.plurals.patch_replaced_bytes, length, length)).append('\n');
        text.append(context.getString(R.string.patch_preview_instruction));
        return text;
    }

    CharSequence comparison(long patchAddress, String before, String after, long[] function,
                            String[] oldSnapshot, String[] newSnapshot) {
        SpannableStringBuilder text = new SpannableStringBuilder();
        heading(text, context.getString(R.string.patch_at_address, patchAddress));
        appendBytes(text, before, after);
        text.append(context.getString(R.string.patch_decompilation_status,
                status(oldSnapshot[1]), status(newSnapshot[1]))).append("\n\n");
        if (function == null) {
            return text.append(context.getString(R.string.patch_no_function));
        }

        heading(text, context.getString(R.string.patch_function_span, function[0]));
        text.append('\n');
        heading(text, context.getString(R.string.pane_disasm));
        appendDiff(text, oldSnapshot[0], newSnapshot[0], true);
        text.append('\n');
        heading(text, context.getString(R.string.pane_c));
        appendDiff(text, oldSnapshot[1], newSnapshot[1], false);
        return text;
    }

    ScrollView scrollView(CharSequence result) {
        TextView code = new TextView(context);
        code.setTypeface(Typeface.MONOSPACE);
        code.setTextSize(13);
        code.setTextIsSelectable(true);
        code.setText(result);
        int pad = Math.round(24 * context.getResources().getDisplayMetrics().density);
        code.setPadding(pad, pad / 2, pad, pad / 2);
        ScrollView scroll = new ScrollView(context);
        scroll.addView(code);
        return scroll;
    }

    private void appendBytes(SpannableStringBuilder text, String before, String after) {
        appendBytesLine(text, R.string.patch_before_bytes, before, removed);
        appendBytesLine(text, R.string.patch_after_bytes, after, added);
    }

    private void appendBytesLine(SpannableStringBuilder text, int label, String bytes, int color) {
        int start = text.length();
        text.append(context.getString(label,
                bytes.isEmpty() ? context.getString(R.string.patch_status_unavailable) : bytes));
        emphasize(text, start, color);
        text.append('\n');
    }

    private void appendDiff(SpannableStringBuilder text, String before, String after, boolean assembly) {
        String legend = context.getString(R.string.patch_diff_legend);
        String diff = PatchComparison.diff(before, after, context.getString(R.string.patch_comparison_unavailable),
                context.getString(R.string.patch_no_changes), legend, context.getString(R.string.patch_diff_limit));
        int highlightBudget = DIFF_HIGHLIGHT_LIMIT;
        for (String row : diff.split("\n")) {
            boolean isRemoved = row.startsWith("− ");
            boolean isAdded = row.startsWith("+ ");
            int start = text.length();
            if (row.length() <= highlightBudget && !legend.equals(row) && (isRemoved || isAdded)) {
                highlightBudget -= row.length();
                String code = row.substring(2);
                text.append(row.substring(0, 2)).append(assembly
                        ? highlighter.assembly(code, null) : highlighter.code(code));
                emphasize(text, start, isRemoved ? removed : added);
            } else {
                text.append(row);
            }
            text.append('\n');
        }
    }

    private void heading(SpannableStringBuilder text, String value) {
        int start = text.length();
        text.append(value);
        text.setSpan(new StyleSpan(Typeface.BOLD), start, text.length(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
        text.append('\n');
    }

    private void emphasize(SpannableStringBuilder text, int start, int color) {
        text.setSpan(new BackgroundColorSpan(color), start, text.length(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
        text.setSpan(new StyleSpan(Typeface.BOLD), start, text.length(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
    }

    private String status(String report) {
        String status = PatchComparison.status(report);
        int label = switch (status) {
            case "complete" -> R.string.patch_status_complete;
            case "partial" -> R.string.patch_status_partial;
            case "unsupported" -> R.string.patch_status_unsupported;
            case "budget-exhausted" -> R.string.patch_status_budget;
            case "unavailable" -> R.string.patch_status_unavailable;
            default -> 0;
        };
        return label == 0 ? status : context.getString(label);
    }
}
