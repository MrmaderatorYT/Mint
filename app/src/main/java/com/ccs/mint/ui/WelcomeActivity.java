package com.ccs.mint.ui;

import android.content.ActivityNotFoundException;
import android.content.ContentResolver;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.Uri;
import android.os.Bundle;
import android.text.format.DateUtils;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.OnBackPressedCallback;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowCompat;
import androidx.core.view.WindowInsetsCompat;
import androidx.core.widget.NestedScrollView;
import androidx.lifecycle.Lifecycle;

import com.ccs.mint.R;
import com.google.android.material.button.MaterialButton;
import com.google.android.material.dialog.MaterialAlertDialogBuilder;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class WelcomeActivity extends MintActivity {
    private static final String SHOWING_LEARN = "showingLearn";
    private static final String EXTRA_LEARN = "com.ccs.mint.extra.LEARN";

    static Intent learnCatalogIntent(Context context) {
        return new Intent(context, WelcomeActivity.class).putExtra(EXTRA_LEARN, true);
    }

    // Separate launchers retain the intended action across recreation while the picker is open.
    private final ActivityResultLauncher<String[]> openPicker =
            registerForActivityResult(new ActivityResultContracts.OpenDocument(),
                    uri -> openPickedFile(uri, false));
    private final ActivityResultLauncher<String[]> clonePicker =
            registerForActivityResult(new ActivityResultContracts.OpenDocument(),
                    uri -> openPickedFile(uri, true));
    private final ExecutorService projectsReader = Executors.newSingleThreadExecutor();

    private NestedScrollView scroll;
    private View welcomePage;
    private View learnPage;
    private MaterialButton resumeProject;
    private MaterialButton savedProjects;
    private OnBackPressedCallback learnBack;
    private final Map<LearnLesson, TextView> lessonStatus = new EnumMap<>(LearnLesson.class);

    @Override
    protected void onCreate(@Nullable Bundle state) {
        super.onCreate(state);
        WindowCompat.setDecorFitsSystemWindows(getWindow(), false);
        setContentView(R.layout.activity_welcome);
        TextView version = findViewById(R.id.welcome_version);
        try {
            String versionName = getPackageManager().getPackageInfo(getPackageName(), 0).versionName;
            if (versionName != null && !versionName.isEmpty()) {
                version.setText(versionName);
                version.setVisibility(View.VISIBLE);
            }
        } catch (android.content.pm.PackageManager.NameNotFoundException ignored) {
            // Keep the version label hidden if package metadata is unavailable.
        }

        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.welcome_root), (view, insets) -> {
            Insets bars = insets.getInsets(WindowInsetsCompat.Type.systemBars()
                    | WindowInsetsCompat.Type.displayCutout());
            view.setPadding(bars.left, bars.top, bars.right, bars.bottom);
            return WindowInsetsCompat.CONSUMED;
        });

        scroll = findViewById(R.id.welcome_scroll);
        welcomePage = findViewById(R.id.welcome_page);
        learnPage = findViewById(R.id.learn_page);
        resumeProject = findViewById(R.id.welcome_resume);
        savedProjects = findViewById(R.id.welcome_saved_projects);

        findViewById(R.id.welcome_open).setOnClickListener(view -> pickFile(openPicker));
        findViewById(R.id.welcome_clone).setOnClickListener(view -> pickFile(clonePicker));
        findViewById(R.id.welcome_learn).setOnClickListener(view -> showLearn(true));
        MaterialButton languageButton = findViewById(R.id.welcome_language);
        boolean ukrainian = UKRAINIAN.equals(language(this));
        CharSequence[] languages = {
                getText(R.string.mint_language_english), getText(R.string.mint_language_ukrainian)
        };
        languageButton.setText(getString(R.string.mint_language_current, languages[ukrainian ? 1 : 0]));
        languageButton.setOnClickListener(view -> new MaterialAlertDialogBuilder(this)
                .setTitle(R.string.mint_language)
                .setSingleChoiceItems(languages, ukrainian ? 1 : 0, (dialog, selection) -> {
                    dialog.dismiss();
                    chooseLanguage(selection == 1 ? UKRAINIAN : ENGLISH);
                })
                .setNegativeButton(android.R.string.cancel, null)
                .show());
        findViewById(R.id.learn_workspace_reference).setOnClickListener(view -> WorkspaceHelp.showViews(this));
        findViewById(R.id.welcome_import_options).setOnClickListener(view ->
                startActivity(WorkspaceActivity.importOptionsIntent(this)));
        findViewById(R.id.learn_back).setOnClickListener(view -> showLearn(false));
        resumeProject.setOnClickListener(view -> startActivity(WorkspaceActivity.resumeIntent(this)));
        savedProjects.setOnClickListener(view -> showSavedProjects());

        ViewGroup lessons = findViewById(R.id.learn_examples);
        for (LearnLesson lesson : LearnLesson.values()) addLesson(lessons, lesson);

        learnBack = new OnBackPressedCallback(false) {
            @Override public void handleOnBackPressed() {
                showLearn(false);
            }
        };
        getOnBackPressedDispatcher().addCallback(this, learnBack);
        showPage(state != null && state.getBoolean(SHOWING_LEARN));
        if (state == null) handleIntent(getIntent());
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        handleIntent(intent);
    }

    private void handleIntent(@Nullable Intent intent) {
        if (intent == null) return;
        if (Intent.ACTION_VIEW.equals(intent.getAction())) {
            openPickedFile(intent.getData(), false);
        } else {
            showLearn(intent.getBooleanExtra(EXTRA_LEARN, false));
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        String project = WorkspaceViewModel.lastProjectName(this);
        resumeProject.setVisibility(project == null ? View.GONE : View.VISIBLE);
        if (project != null)
            resumeProject.setText(getString(R.string.welcome_resume, project));
        SharedPreferences progress = LearnLesson.progress(this);
        int completed = 0;
        for (Map.Entry<LearnLesson, TextView> status : lessonStatus.entrySet()) {
            boolean done = status.getKey().isComplete(progress);
            status.getValue().setVisibility(done ? View.VISIBLE : View.GONE);
            if (done) ++completed;
        }
        TextView total = findViewById(R.id.learn_catalog_progress);
        total.setText(getString(R.string.lesson_catalog_progress, completed, lessonStatus.size()));
    }

    @Override
    protected void onSaveInstanceState(@NonNull Bundle state) {
        state.putBoolean(SHOWING_LEARN, learnBack.isEnabled());
        super.onSaveInstanceState(state);
    }

    @Override
    protected void onDestroy() {
        projectsReader.shutdownNow();
        super.onDestroy();
    }

    private void showLearn(boolean showing) {
        showPage(showing);
        scroll.scrollTo(0, 0);
    }

    private void showPage(boolean showingLearn) {
        welcomePage.setVisibility(showingLearn ? View.GONE : View.VISIBLE);
        learnPage.setVisibility(showingLearn ? View.VISIBLE : View.GONE);
        learnBack.setEnabled(showingLearn);
        ViewCompat.setAccessibilityPaneTitle(showingLearn ? learnPage : welcomePage,
                getString(showingLearn ? R.string.learn_title : R.string.app_name));
    }

    private void pickFile(ActivityResultLauncher<String[]> picker) {
        try {
            picker.launch(new String[]{"*/*"});
        } catch (ActivityNotFoundException error) {
            Toast.makeText(this, R.string.welcome_no_picker, Toast.LENGTH_LONG).show();
        }
    }

    private void openPickedFile(@Nullable Uri uri, boolean clone) {
        if (uri == null) return;
        String scheme = uri.getScheme();
        if (!ContentResolver.SCHEME_CONTENT.equals(scheme)
                && !ContentResolver.SCHEME_FILE.equals(scheme)) return;
        Intent intent = clone ? WorkspaceActivity.cloneFileIntent(this, uri)
                : WorkspaceActivity.openFileIntent(this, uri);
        startActivity(intent);
    }

    private void addLesson(ViewGroup lessons, LearnLesson lesson) {
        View card = getLayoutInflater().inflate(R.layout.item_learn_example, lessons, false);
        ((TextView) card.findViewById(R.id.learn_example_title)).setText(lesson.title);
        ((TextView) card.findViewById(R.id.learn_example_info)).setText(lesson.summary);
        lessonStatus.put(lesson, card.findViewById(R.id.learn_example_status));
        MaterialButton open = card.findViewById(R.id.learn_example_open);
        open.setText(getString(R.string.learn_open_example, getString(lesson.title)));
        open.setOnClickListener(view -> startActivity(WorkspaceActivity.learnIntent(this, lesson.id)));
        lessons.addView(card);
    }

    private void showSavedProjects() {
        savedProjects.setEnabled(false);
        projectsReader.execute(() -> {
            List<ProjectStore.SavedProject> projects = ProjectStore.savedProjects(this);
            runOnUiThread(() -> {
                if (isFinishing() || isDestroyed()) return;
                savedProjects.setEnabled(true);
                if (welcomePage.getVisibility() != View.VISIBLE
                        || !getLifecycle().getCurrentState().isAtLeast(Lifecycle.State.RESUMED)) return;
                MaterialAlertDialogBuilder dialog = new MaterialAlertDialogBuilder(this)
                        .setTitle(R.string.welcome_saved)
                        .setNegativeButton(android.R.string.cancel, null);
                if (projects.isEmpty()) {
                    dialog.setMessage(R.string.welcome_saved_empty);
                } else {
                    CharSequence[] labels = new CharSequence[projects.size()];
                    for (int i = 0; i < projects.size(); i++) {
                        ProjectStore.SavedProject project = projects.get(i);
                        String date = DateUtils.formatDateTime(this, project.modifiedAt,
                                DateUtils.FORMAT_SHOW_DATE | DateUtils.FORMAT_SHOW_TIME);
                        labels[i] = getString(R.string.welcome_saved_entry, project.name, date);
                    }
                    dialog.setItems(labels, (ignored, selected) -> startActivity(
                            WorkspaceActivity.openProjectIntent(this, projects.get(selected).id)));
                }
                dialog.show();
            });
        });
    }
}
