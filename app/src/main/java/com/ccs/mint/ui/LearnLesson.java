package com.ccs.mint.ui;

import android.content.Context;
import android.content.SharedPreferences;

import com.ccs.mint.R;

/** Guided targets and expected encodings come from the bundled lesson binaries. */
enum LearnLesson {
    ARITHMETIC("arithmetic", "learn/arithmetic.elf", 0x4234, 0x4238, "00 14 00 11",
            R.string.lesson_arithmetic_title, R.string.lesson_arithmetic_summary,
            new int[]{R.string.lesson_arithmetic_first, R.string.lesson_arithmetic_second, R.string.lesson_arithmetic_third},
            R.string.lesson_arithmetic_exercise, R.string.lesson_arithmetic_hint,
            new int[]{R.string.lesson_arithmetic_answer_a, R.string.lesson_arithmetic_answer_b, R.string.lesson_arithmetic_answer_c}, 1,
            R.string.lesson_arithmetic_correct, R.string.lesson_arithmetic_wrong),
    BRANCH("branch", "learn/branch.elf", 0x4234, 0x4234, "1f 28 00 71",
            R.string.lesson_branch_title, R.string.lesson_branch_summary,
            new int[]{R.string.lesson_branch_first, R.string.lesson_branch_second, R.string.lesson_branch_third},
            R.string.lesson_branch_exercise, R.string.lesson_branch_hint,
            new int[]{R.string.lesson_branch_answer_a, R.string.lesson_branch_answer_b, R.string.lesson_branch_answer_c}, 0,
            R.string.lesson_branch_correct, R.string.lesson_branch_wrong),
    RECORDS("records", "learn/memory.elf", 0x4230, 0x4234, "21 00 02 4b",
            R.string.lesson_records_title, R.string.lesson_records_summary,
            new int[]{R.string.lesson_records_first, R.string.lesson_records_second, R.string.lesson_records_third},
            R.string.lesson_records_exercise, R.string.lesson_records_hint,
            new int[]{R.string.lesson_records_answer_a, R.string.lesson_records_answer_b, R.string.lesson_records_answer_c}, 2,
            R.string.lesson_records_correct, R.string.lesson_records_wrong),
    LOOP("loop", "learn/loop.elf", 0x4230, 0x4234, "a1 00 80 52",
            R.string.lesson_loop_title, R.string.lesson_loop_summary,
            new int[]{R.string.lesson_loop_first, R.string.lesson_loop_second, R.string.lesson_loop_third},
            R.string.lesson_loop_exercise, R.string.lesson_loop_hint,
            new int[]{R.string.lesson_loop_answer_a, R.string.lesson_loop_answer_b, R.string.lesson_loop_answer_c}, 1,
            R.string.lesson_loop_correct, R.string.lesson_loop_wrong),
    CALLS("calls", "learn/calls.elf", 0x4230, 0x4238, "00 10 00 11",
            R.string.lesson_calls_title, R.string.lesson_calls_summary,
            new int[]{R.string.lesson_calls_first, R.string.lesson_calls_second, R.string.lesson_calls_third},
            R.string.lesson_calls_exercise, R.string.lesson_calls_hint,
            new int[]{R.string.lesson_calls_answer_a, R.string.lesson_calls_answer_b, R.string.lesson_calls_answer_c}, 2,
            R.string.lesson_calls_correct, R.string.lesson_calls_wrong),
    STRINGS("strings", "learn/strings.elf", 0x4248, 0x0000, null,
            R.string.lesson_strings_title, R.string.lesson_strings_summary,
            new int[]{R.string.lesson_strings_first, R.string.lesson_strings_second, R.string.lesson_strings_third},
            R.string.lesson_strings_exercise, R.string.lesson_strings_hint,
            new int[]{R.string.lesson_strings_answer_a, R.string.lesson_strings_answer_b, R.string.lesson_strings_answer_c}, 0,
            R.string.lesson_strings_correct, R.string.lesson_strings_wrong);

    static final int PRACTICE = 3;
    static final int STEP_COUNT = PRACTICE + 1;
    static final long PRACTICE_LABEL_ADDRESS = 0x233;

    final String id;
    final String asset;
    final long entry;
    final long patchAddress;
    final String expectedPatch;
    final int title;
    final int summary;
    final int[] explanations;
    final int exercise;
    final int hint;
    final int[] answers;
    final int correctAnswer;
    final int correct;
    final int wrong;

    LearnLesson(String id, String asset, long entry, long patchAddress, String expectedPatch,
                int title, int summary, int[] explanations, int exercise, int hint,
                int[] answers, int correctAnswer, int correct, int wrong) {
        this.id = id;
        this.asset = asset;
        this.entry = entry;
        this.patchAddress = patchAddress;
        this.expectedPatch = expectedPatch;
        this.title = title;
        this.summary = summary;
        this.explanations = explanations;
        this.exercise = exercise;
        this.hint = hint;
        this.answers = answers;
        this.correctAnswer = correctAnswer;
        this.correct = correct;
        this.wrong = wrong;
    }

    static LearnLesson find(String id) {
        for (LearnLesson lesson : values()) {
            if (lesson.id.equals(id)) return lesson;
        }
        return null;
    }

    static SharedPreferences progress(Context context) {
        return context.getSharedPreferences("learn_progress", Context.MODE_PRIVATE);
    }

    boolean isComplete(SharedPreferences progress) {
        return quizPassed(progress) && (expectedPatch == null || patchPassed(progress));
    }

    boolean quizPassed(SharedPreferences progress) {
        return progress.getBoolean(id + ".quiz", false);
    }

    boolean patchPassed(SharedPreferences progress) {
        return progress.getBoolean(id + ".patch", false);
    }

    void saveQuizPass(SharedPreferences progress) {
        progress.edit().putBoolean(id + ".quiz", true).apply();
    }

    void savePatchPass(SharedPreferences progress) {
        progress.edit().putBoolean(id + ".patch", true).apply();
    }

    int step(SharedPreferences progress) {
        return Math.max(0, Math.min(PRACTICE, progress.getInt(id + ".step", 0)));
    }

    void saveStep(SharedPreferences progress, int step) {
        progress.edit().putInt(id + ".step", step).apply();
    }
}
