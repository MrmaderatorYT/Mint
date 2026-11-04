package com.ccs.mint.ui;

import android.content.Context;
import android.graphics.Color;
import android.graphics.Typeface;
import android.text.SpannableStringBuilder;
import android.text.Spanned;
import android.text.style.ForegroundColorSpan;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.HorizontalScrollView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import androidx.core.view.ViewCompat;
import androidx.core.content.ContextCompat;

import com.ccs.mint.R;
import com.google.android.material.bottomsheet.BottomSheetDialog;
import com.google.android.material.button.MaterialButton;
import com.google.android.material.card.MaterialCardView;
import com.google.android.material.color.MaterialColors;
import com.google.android.material.dialog.MaterialAlertDialogBuilder;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** In-app guide. Mock displays are explanatory text, not captured app data. */
final class WorkspaceHelp {
    static final int[][] GROUPS = {
            {0, 19}, {1, 2, 3, 4, 5, 6, 7, 8, 9},
            {10, 11, 12, 13, 14}, {15, 16, 17, 18}
    };
    private static final int[] GROUP_TITLES = {
            R.string.help_group_start, R.string.help_group_views,
            R.string.help_group_tools, R.string.help_group_advanced
    };
    private WorkspaceHelp() {}

    static void show(Context context) {
        String[] topics = context.getResources().getStringArray(R.array.help_topics);
        final BottomSheetDialog sheet = new BottomSheetDialog(context);
        ScrollView scroll = new ScrollView(context);
        LinearLayout content = column(context);
        int pad = dp(context, 16);
        content.setPadding(pad, pad, pad, pad);
        TextView title = new TextView(context);
        title.setText(R.string.help_title);
        title.setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_HeadlineSmall);
        content.addView(title);
        List<LinearLayout> sections = new ArrayList<>();
        List<MaterialButton> headings = new ArrayList<>();
        for (int group = 0; group < GROUPS.length; ++group) {
            LinearLayout items = column(context);
            items.setVisibility(View.GONE);
            sections.add(items);
            String label = context.getString(GROUP_TITLES[group]);
            MaterialButton heading = new MaterialButton(context, null,
                    com.google.android.material.R.attr.materialButtonOutlinedStyle);
            heading.setText(label + "  ▾");
            heading.setContentDescription(label);
            ViewCompat.setStateDescription(heading, context.getString(R.string.help_collapsed));
            headings.add(heading);
            heading.setOnClickListener(view -> {
                boolean expand = items.getVisibility() != View.VISIBLE;
                for (int index = 0; index < sections.size(); ++index) {
                    sections.get(index).setVisibility(View.GONE);
                    headings.get(index).setText(context.getString(GROUP_TITLES[index]) + "  ▾");
                    ViewCompat.setStateDescription(headings.get(index), context.getString(R.string.help_collapsed));
                }
                if (expand) {
                    items.setVisibility(View.VISIBLE);
                    heading.setText(label + "  ▴");
                    ViewCompat.setStateDescription(heading, context.getString(R.string.help_expanded));
                }
            });
            content.addView(heading, fullWidth());
            for (int topic : GROUPS[group]) {
                MaterialButton button = new MaterialButton(new android.view.ContextThemeWrapper(context,
                        com.google.android.material.R.style.Widget_Material3_Button_TextButton));
                button.setText(topics[topic]);
                button.setAllCaps(false);
                button.setSingleLine(false);
                button.setGravity(Gravity.START | Gravity.CENTER_VERTICAL);
                button.setOnClickListener(view -> showAnswer(context, topic));
                items.addView(button, fullWidth());
            }
            content.addView(items);
        }
        scroll.addView(content);
        sheet.setContentView(scroll);
        sheet.show();
    }

    private static void showAnswer(Context context, int topic) {
        String[] titles = context.getResources().getStringArray(R.array.help_topics);
        String[] bodies = context.getResources().getStringArray(R.array.help_bodies);
        String[] examples = context.getResources().getStringArray(R.array.help_examples);
        String[] explanations = context.getResources().getStringArray(R.array.help_explanations);
        ScrollView scroll = new ScrollView(context);
        LinearLayout content = column(context);
        int pad = dp(context, 20);
        content.setPadding(pad, 0, pad, pad);
        TextView body = new TextView(context);
        body.setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodyLarge);
        body.setText(bodies[topic]);
        content.addView(body, fullWidth());

        // A small native mock display makes the example visually distinct from
        // actual analysis; it does not contain a screenshot or project data.
        MaterialCardView card = new MaterialCardView(context);
        card.setRadius(dp(context, 12));
        card.setCardElevation(0);
        card.setStrokeWidth(dp(context, 1));
        card.setStrokeColor(MaterialColors.getColor(card, com.google.android.material.R.attr.colorOutlineVariant, Color.GRAY));
        card.setCardBackgroundColor(MaterialColors.getColor(card, com.google.android.material.R.attr.colorSurface, Color.WHITE));
        LinearLayout example = column(context);
        example.setPadding(pad, dp(context, 12), pad, dp(context, 12));
        TextView label = new TextView(context);
        label.setText(R.string.help_example_label);
        label.setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_LabelLarge);
        label.setTextColor(MaterialColors.getColor(label, androidx.appcompat.R.attr.colorPrimary, Color.GREEN));
        example.addView(label, fullWidth());
        HorizontalScrollView horizontal = new HorizontalScrollView(context);
        TextView mock = new TextView(context);
        mock.setTypeface(Typeface.MONOSPACE);
        mock.setTextSize(13);
        mock.setPadding(0, dp(context, 8), 0, 0);
        mock.setTextColor(MaterialColors.getColor(mock, com.google.android.material.R.attr.colorOnSurface, Color.BLACK));
        mock.setText(highlightExample(context, topic, examples[topic]));
        horizontal.addView(mock);
        example.addView(horizontal, fullWidth());
        card.addView(example);
        LinearLayout.LayoutParams cardParams = fullWidth();
        cardParams.setMargins(0, dp(context, 16), 0, dp(context, 12));
        content.addView(card, cardParams);
        TextView legend = new TextView(context);
        legend.setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodyMedium);
        legend.setText(explanations[topic]);
        content.addView(legend, fullWidth());
        scroll.addView(content);
        new MaterialAlertDialogBuilder(context).setTitle(titles[topic]).setView(scroll)
                .setPositiveButton(R.string.help_close, null).show();
    }

    /** Highlight illustrative code using the same theme roles as the workspace. */
    private static CharSequence highlightExample(Context context, int topic, String source) {
        Highlighter highlighter = new Highlighter(context);
        if (topic == 2) { // Disassembly examples include a machine-byte column.
            Pattern listing = Pattern.compile("^(\\S+)(\\s+)((?:[0-9a-fA-F]{2}\\s+)+)(.*)$");
            SpannableStringBuilder output = new SpannableStringBuilder();
            String[] lines = source.split("\\n", -1);
            for (int i = 0; i < lines.length; ++i) {
                if (i != 0) output.append('\n');
                Matcher match = listing.matcher(lines[i]);
                if (!match.matches()) { output.append(highlighter.code(lines[i])); continue; }
                SpannableStringBuilder row = new SpannableStringBuilder(
                        highlighter.assembly(match.group(1) + match.group(2) + match.group(4), null));
                row.insert(match.group(1).length() + match.group(2).length(), match.group(3));
                output.append(row);
            }
            return output;
        }
        SpannableStringBuilder output = new SpannableStringBuilder(highlighter.code(source));
        // Code highlighting colours types, literals and keywords. Add register
        // and IR operation roles to the schematic examples without altering data.
        Matcher registers = Pattern.compile("\\b(?:[xwr](?:[0-9]|[12][0-9]|30)|sp|lr|pc)\\b", Pattern.CASE_INSENSITIVE).matcher(source);
        int registerColor = ContextCompat.getColor(context, R.color.syn_register);
        while (registers.find()) output.setSpan(new ForegroundColorSpan(registerColor),
                registers.start(), registers.end(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
        if (topic == 3) {
            Matcher operations = Pattern.compile("\\b(?:block|copy|load|store|branch|cbranch|intrinsic|phi)\\b").matcher(source);
            int operationColor = ContextCompat.getColor(context, R.color.syn_mnemonic);
            while (operations.find()) output.setSpan(new ForegroundColorSpan(operationColor),
                    operations.start(), operations.end(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
        }
        return output;
    }

    private static LinearLayout column(Context context) {
        LinearLayout result = new LinearLayout(context);
        result.setOrientation(LinearLayout.VERTICAL);
        return result;
    }
    private static LinearLayout.LayoutParams fullWidth() {
        return new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
    }
    private static int dp(Context context, int value) {
        return Math.round(value * context.getResources().getDisplayMetrics().density);
    }
}
