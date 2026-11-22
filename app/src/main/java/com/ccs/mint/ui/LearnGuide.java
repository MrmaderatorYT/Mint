package com.ccs.mint.ui;

import android.content.SharedPreferences;
import android.view.ContextThemeWrapper;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import androidx.appcompat.app.AlertDialog;
import androidx.core.view.ViewCompat;

import com.ccs.mint.R;
import com.google.android.material.button.MaterialButton;
import com.google.android.material.dialog.MaterialAlertDialogBuilder;

import java.util.function.Consumer;

/** Presents lesson steps, feedback and progress while the workspace owns navigation and edits. */
final class LearnGuide {
    interface Workspace {
        void inspect(int step);
        void openPatchEditor();
        void checkPatch(Consumer<Boolean> result);
        void returnToCatalog();
    }

    private final WorkspaceActivity activity;
    private final LearnLesson lesson;
    private final Workspace workspace;
    private final SharedPreferences progress;
    private AlertDialog dialog;

    LearnGuide(WorkspaceActivity activity, LearnLesson lesson, Workspace workspace) {
        this.activity = activity;
        this.lesson = lesson;
        this.workspace = workspace;
        this.progress = LearnLesson.progress(activity);
    }

    void show() {
        if (dialog != null && dialog.isShowing()) return;
        showStep(lesson.step(progress));
    }

    void dismiss() {
        if (dialog != null) dialog.dismiss();
    }

    private void moveTo(int step) {
        lesson.saveStep(progress, step);
        dismiss();
        showStep(step);
    }

    private void showStep(int step) {
        ScrollView scroll = new ScrollView(activity);
        LinearLayout body = new LinearLayout(activity);
        body.setOrientation(LinearLayout.VERTICAL);
        int inset = dp(24);
        body.setPadding(inset, dp(12), inset, dp(8));
        scroll.addView(body);

        TextView stepLabel = text(body);
        stepLabel.setText(activity.getString(R.string.lesson_step, step + 1, LearnLesson.STEP_COUNT));
        if (step == LearnLesson.PRACTICE) {
            practice(body, stepLabel);
        } else {
            text(body).setText(lesson.explanations[step]);
            MaterialButton inspect = button(body);
            if (lesson == LearnLesson.STRINGS && step == 2) {
                inspect.setText(R.string.lesson_show_references);
            } else {
                int panel = step == 0 ? Pane.DISASM
                        : step == 2 ? Pane.GRAPH
                        : lesson == LearnLesson.STRINGS ? Pane.STRINGS : Pane.C;
                inspect.setText(activity.getString(R.string.lesson_show_panel,
                        activity.getString(Pane.TITLES[panel])));
            }
            inspect.setOnClickListener(view -> {
                dismiss();
                workspace.inspect(step);
            });
            text(body).setText(R.string.lesson_continue_hint);
        }

        MaterialAlertDialogBuilder builder = new MaterialAlertDialogBuilder(activity)
                .setTitle(lesson.title)
                .setView(scroll)
                .setPositiveButton(step < LearnLesson.PRACTICE ? R.string.lesson_next : android.R.string.ok,
                        (ignored, which) -> {
                            if (step < LearnLesson.PRACTICE) moveTo(step + 1);
                        });
        if (step > 0) {
            builder.setNegativeButton(R.string.lesson_previous, (ignored, which) -> moveTo(step - 1))
                    .setNeutralButton(android.R.string.cancel, null);
        } else {
            builder.setNegativeButton(android.R.string.cancel, null);
        }
        dialog = builder.create();
        dialog.setOnDismissListener(closed -> {
            if (dialog == closed) dialog = null;
        });
        dialog.show();
    }

    private void practice(LinearLayout body, TextView stepLabel) {
        text(body).setText(R.string.lesson_practice_title);
        text(body).setText(lesson.exercise);
        text(body).setText(R.string.lesson_choose_answer);
        TextView quizFeedback = feedback(body);
        if (lesson.quizPassed(progress)) quizFeedback.setText(lesson.correct);
        for (int i = 0; i < lesson.answers.length; ++i) {
            MaterialButton answer = button(body);
            answer.setText(lesson.answers[i]);
            final int selected = i;
            answer.setOnClickListener(view -> {
                boolean correct = selected == lesson.correctAnswer;
                if (correct) lesson.saveQuizPass(progress);
                quizFeedback.setText(correct ? lesson.correct : lesson.wrong);
                showCompletion(stepLabel);
            });
        }
        text(body).setText(lesson.hint);
        if (lesson.expectedPatch != null) {
            MaterialButton patch = button(body);
            patch.setText(R.string.lesson_open_patch);
            patch.setOnClickListener(view -> {
                dismiss();
                workspace.openPatchEditor();
            });
            MaterialButton check = button(body);
            check.setText(R.string.lesson_check_patch);
            TextView patchFeedback = feedback(body);
            if (lesson.patchPassed(progress)) patchFeedback.setText(R.string.lesson_patch_success);
            check.setOnClickListener(view -> {
                check.setEnabled(false);
                workspace.checkPatch(result -> {
                    if (Boolean.TRUE.equals(result)) lesson.savePatchPass(progress);
                    check.setEnabled(true);
                    patchFeedback.setText(result == null ? R.string.lesson_guide_unavailable
                            : result ? R.string.lesson_patch_success : R.string.lesson_patch_missing);
                    showCompletion(stepLabel);
                });
            });
        } else if (lesson == LearnLesson.STRINGS) {
            MaterialButton references = button(body);
            references.setText(R.string.lesson_show_references);
            references.setOnClickListener(view -> {
                dismiss();
                workspace.inspect(2);
            });
        }
        MaterialButton catalog = button(body);
        catalog.setText(R.string.lesson_back_to_catalog);
        catalog.setOnClickListener(view -> {
            dismiss();
            workspace.returnToCatalog();
        });
        showCompletion(stepLabel);
    }

    private void showCompletion(TextView stepLabel) {
        if (lesson.isComplete(progress)) stepLabel.setText(R.string.lesson_completed);
    }

    private TextView feedback(LinearLayout parent) {
        TextView result = text(parent);
        ViewCompat.setAccessibilityLiveRegion(result, ViewCompat.ACCESSIBILITY_LIVE_REGION_POLITE);
        return result;
    }

    private TextView text(LinearLayout parent) {
        TextView result = new TextView(activity);
        result.setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodyMedium);
        result.setPadding(0, dp(4), 0, dp(4));
        parent.addView(result, layoutParams());
        return result;
    }

    private MaterialButton button(LinearLayout parent) {
        MaterialButton result = new MaterialButton(new ContextThemeWrapper(activity,
                com.google.android.material.R.style.Widget_Material3_Button_OutlinedButton));
        parent.addView(result, layoutParams());
        return result;
    }

    private LinearLayout.LayoutParams layoutParams() {
        return new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
    }

    private int dp(int value) {
        return Math.round(value * activity.getResources().getDisplayMetrics().density);
    }
}
