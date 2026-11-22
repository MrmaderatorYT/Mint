package com.ccs.mint.ui;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Typeface;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.ParcelFileDescriptor;
import android.text.Editable;
import android.text.SpannableString;
import android.text.TextWatcher;
import android.text.style.ForegroundColorSpan;
import android.text.style.ClickableSpan;
import android.text.method.LinkMovementMethod;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.LinearLayout;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.content.IntentCompat;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowCompat;
import androidx.core.view.WindowInsetsCompat;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import androidx.lifecycle.ViewModelProvider;

import com.ccs.mint.R;
import com.ccs.mint.core.MintSession;
import com.ccs.mint.ui.components.GraphView;
import com.google.android.material.chip.Chip;
import com.google.android.material.chip.ChipGroup;
import com.google.android.material.progressindicator.LinearProgressIndicator;
import com.google.android.material.tabs.TabLayout;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;

/**
 * The whole workspace: pick a binary, browse its functions, read one as
 * disassembly, IR or pseudo-C.
 *
 * <p>One pane is visible at a time. A desktop reverse engineering tool puts the
 * function list, the listing and the decompiler side by side, and that layout does
 * not survive being scaled to a phone: at this width four panes leave the listing
 * about twenty characters wide, which cannot show an instruction's operands — the
 * part that carries the meaning. So the panes became destinations, and each gets
 * the full width.
 *
 * <p>Everything shown comes from {@link MintSession}. There is deliberately no
 * sample data: a screen that renders a plausible function the engine never produced
 * is worse than an empty one, because nothing distinguishes it from a working tool.
 */
public final class WorkspaceActivity extends MintActivity {

    private static final String ACTION_CLONE = "com.ccs.mint.action.CLONE_BINARY";
    private static final String ACTION_LEARN = "com.ccs.mint.action.OPEN_LESSON";
    private static final String ACTION_PROJECT = "com.ccs.mint.action.OPEN_PROJECT";
    private static final String ACTION_IMPORT_OPTIONS = "com.ccs.mint.action.IMPORT_OPTIONS";
    private static final String EXTRA_INPUT = "input_uri";
    private static final String EXTRA_ID = "project_id";
    private static final String STATE_PROJECT = "opened_project_id";

    static Intent openFileIntent(Context context, Uri uri) {
        return inputIntent(context, Intent.ACTION_VIEW, uri);
    }

    static Intent cloneFileIntent(Context context, Uri uri) {
        return inputIntent(context, ACTION_CLONE, uri);
    }

    private static Intent inputIntent(Context context, String action, Uri uri) {
        Intent intent = new Intent(context, WorkspaceActivity.class).setAction(action);
        // Keep a file: URI inside this app; content: URIs carry their read grant.
        if ("content".equals(uri.getScheme())) {
            return intent.setData(uri).addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
        }
        return intent.putExtra(EXTRA_INPUT, uri);
    }

    static Intent learnIntent(Context context, String exampleId) {
        return new Intent(context, WorkspaceActivity.class).setAction(ACTION_LEARN).putExtra(EXTRA_ID, exampleId);
    }

    static Intent openProjectIntent(Context context, String projectId) {
        return new Intent(context, WorkspaceActivity.class).setAction(ACTION_PROJECT).putExtra(EXTRA_ID, projectId);
    }

    static Intent resumeIntent(Context context) {
        return openProjectIntent(context, WorkspaceViewModel.lastProjectId(context));
    }

    static Intent importOptionsIntent(Context context) {
        return new Intent(context, WorkspaceActivity.class).setAction(ACTION_IMPORT_OPTIONS);
    }

    private static final int PAGE = 512;
    private static final int LISTING_LIMIT = 4096;
    private static final int MAX_LISTING_PAGES = 16384;
    private static final int OPEN_REQUEST = 1;
    private static final int EXPORT_REQUEST = 2;
    private static final int SCRIPT_REQUEST = 3;
    private static final int COMPARISON_REQUEST = 4;
    private static final int PLUGIN_REQUEST = 5;
    private static final int LIBRARY_REQUEST = 6;
    private static final int TRACKING_SAVE_REQUEST = 7;
    private static final int TRACKING_LOAD_REQUEST = 8;
    private static final int PROJECT_SAVE_REQUEST = 9;
    private static final int PROJECT_OPEN_REQUEST = 10;
    private static final int DEBUG_IMPORT_REQUEST = 11;
    private static final int SANDBOX_PLUGIN_REQUEST = 12;
    private static final int PSEUDO_C_EXPORT_REQUEST = 13;
    private static final int REVIEWED_PATCH_EXPORT_REQUEST = 14;
    private com.ccs.mint.plugin.SandboxPluginClient sandboxPlugin;
    private boolean sandboxPreparing;
    private java.util.concurrent.atomic.AtomicBoolean sandboxCopyCancelled;
    private RawImportConfig pendingRawImport;
    private long viewGeneration;

    /**
     * How much of the image the program-wide listing will render before stopping.
     * A large library holds hundreds of thousands of instructions, and formatting
     * every one costs seconds and hundreds of megabytes to show a view nobody
     * scrolls to the end of. The Functions pane is how you reach a specific place.
     */
    private static final int PROGRAM_LISTING_LIMIT = 20_000;

    /**
     * Largest call graph that gets drawn. Beyond this the highest-degree functions
     * are kept and the rest dropped — with a line in the log saying so, because a
     * silently truncated graph reads as a complete one.
     */
    private static final int CALL_GRAPH_LIMIT = 6_000;

    private ExecutorService worker;
    private WorkspaceViewModel model;

    private MintSession session;
    private final List<FunctionRow> functions = new ArrayList<>();
    private final List<FunctionRow> visible = new ArrayList<>();
    private FunctionRow selected;
    /// Functions the user has open, in the order they were opened. `selected` is
    /// always one of these, or null when none are.
    private final List<FunctionRow> openFunctions = new ArrayList<>();
    private String log = "";

    private View empty;
    private View content;
    private LinearProgressIndicator progress;
    private TextView title;
    private TextView subtitle;
    private EditText filter;
    private RecyclerView list;
    private TextView text;
    private View textScroll;
    private GraphView graph;
    private View cancel;
    private View returnToWelcome;
    private View learnGuideButton;
    private LearnLesson lesson;
    private LearnGuide learnGuide;
    private boolean showGuideOnOpen;
    private TabLayout nav;
    private ViewGroup openChips;
    private View openScroll;

    private final LineAdapter adapter = new LineAdapter();
    private Highlighter highlighter;
    private PatchDialogCode patchDialogCode;
    private androidx.appcompat.app.AlertDialog betaNotice;
    private int dimColour;
    private int pane = Pane.FUNCTIONS;
    private long listingAddress;
    private long pendingAddress = -1;
    private NavigationHistory history;
    private SourceListing sourceListing;
    private SourceListing restoreSourceScroll;
    private Long pseudoCAnchor;
    private ListingOrigin reverseListing;
    private android.os.Parcelable restoreListingScroll;

    private static final class ListingOrigin {
        final FunctionRow function;
        final long address;
        final SourceListing source;
        final android.os.Parcelable scroll;

        ListingOrigin(FunctionRow function, long address, SourceListing source, android.os.Parcelable scroll) {
            this.function = function;
            this.address = address;
            this.source = source;
            this.scroll = scroll;
        }
    }

    private static final class SourceListing {
        final long entry, previousAddress, start, end;
        final int scrollX, scrollY;

        SourceListing(long entry, long previousAddress, long start, long end, int scrollX, int scrollY) {
            this.entry = entry;
            this.previousAddress = previousAddress;
            this.start = start;
            this.end = end;
            this.scrollX = scrollX;
            this.scrollY = scrollY;
        }
    }
    private final Handler main = new Handler(Looper.getMainLooper());
    private final Runnable progressPoll = new Runnable() {
        @Override public void run() {
            if (progress.getVisibility() != View.VISIBLE) return;
            progress.setProgress(model == null ? 0 : model.progress());
            main.postDelayed(this, 200);
        }
    };

    /** One row of the function table, kept flat so the list can hold thousands. */
    private static final class FunctionRow {
        long entry;
        int size;
        int instructions;
        String name;

        String label() {
            return name == null || name.isEmpty()
                    ? String.format(Locale.US, "sub_%x", entry) : name;
        }
    }

    @Override
    protected void onCreate(@Nullable Bundle state) {
        super.onCreate(state);
        getOnBackPressedDispatcher().addCallback(this, new androidx.activity.OnBackPressedCallback(true) {
            @Override public void handleOnBackPressed() {
                if (navigateBack()) return;
                setEnabled(false);
                try {
                    getOnBackPressedDispatcher().onBackPressed();
                } finally {
                    setEnabled(true);
                }
            }
        });
        model = new ViewModelProvider(this).get(WorkspaceViewModel.class);
        worker = model.worker();
        history = model.navigationHistory();
        pane = model.pane();
        pendingAddress = model.selectedAddress();
        listingAddress = model.listingAddress();
        if (state != null) {
            pane = state.getInt("pane", pane);
            pendingAddress = state.getLong("selected", pendingAddress);
            listingAddress = state.getLong("listing", listingAddress);
            model.rememberWorkspace(pendingAddress, listingAddress, pane);
            String rawArch = state.getString("pendingRawArch");
            if (rawArch != null) {
                try{pendingRawImport = new RawImportConfig(rawArch,state.getLong("pendingRawBase"),state.getLong("pendingRawEntry"));}
                catch(IllegalArgumentException e){main.post(()->{if(!isDestroyed())showProjectError(getString(R.string.ws_decoder_pending));});}
            }
        }
        // Edge to edge, then pad the content back by hand. Without this the title is
        // drawn underneath the status bar clock, which is what the old layout did.
        WindowCompat.setDecorFitsSystemWindows(getWindow(), false);
        setContentView(R.layout.activity_workspace);
        highlighter = new Highlighter(this);
        patchDialogCode = new PatchDialogCode(this, highlighter);
        dimColour = androidx.core.content.ContextCompat.getColor(
                this, R.color.syn_address);

        empty = findViewById(R.id.empty);
        content = findViewById(R.id.content);
        progress = findViewById(R.id.progress);
        title = findViewById(R.id.title);
        subtitle = findViewById(R.id.subtitle);
        filter = findViewById(R.id.filter);
        list = findViewById(R.id.list);
        text = findViewById(R.id.text);
        text.setMovementMethod(LinkMovementMethod.getInstance());
        textScroll = findViewById(R.id.text_scroll);
        graph = findViewById(R.id.graph);
        cancel = findViewById(R.id.cancel_analysis);
        returnToWelcome = findViewById(R.id.return_to_welcome);
        learnGuideButton = findViewById(R.id.learn_guide);
        configureLesson(state == null);
        nav = findViewById(R.id.nav);
        openChips = findViewById(R.id.open_functions);
        openScroll = findViewById(R.id.open_scroll);
        if (!Pane.valid(pane)) pane = Pane.FUNCTIONS;

        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.root), (view, insets) -> {
            Insets bars = insets.getInsets(WindowInsetsCompat.Type.systemBars()
                    | WindowInsetsCompat.Type.displayCutout());
            view.setPadding(bars.left, bars.top, bars.right, bars.bottom);
            return WindowInsetsCompat.CONSUMED;
        });

        list.setLayoutManager(new LinearLayoutManager(this));
        list.setAdapter(adapter);

        findViewById(R.id.open).setOnClickListener(v -> pickFile());
        findViewById(R.id.open_another).setOnClickListener(v -> pickFile());
        returnToWelcome.setOnClickListener(v -> returnToWelcome(false));
        findViewById(R.id.help).setOnClickListener(v -> WorkspaceHelp.show(this));
        findViewById(R.id.about).setOnClickListener(v -> showLicences());
        findViewById(R.id.project_actions).setOnClickListener(v -> showProjectActions());
        showBetaNoticeOnce();
        if (betaNotice != null) {
            betaNotice.setOnDismissListener(dialog -> main.post(this::showInitialLessonGuide));
        }
        findViewById(R.id.try_example).setOnClickListener(v -> returnToWelcome(true));
        cancel.setOnClickListener(v -> {
            if(sandboxPlugin!=null)sandboxPlugin.close();
            else if(sandboxPreparing && sandboxCopyCancelled!=null)sandboxCopyCancelled.set(true);
            else model.cancel();
        });

        filter.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int a, int b, int c) {}
            @Override public void onTextChanged(CharSequence s, int a, int b, int c) {}
            @Override public void afterTextChanged(Editable s) { applyFilter(); }
        });

        for (int title : Pane.TITLES) nav.addTab(nav.newTab().setText(title));
        nav.addOnTabSelectedListener(new TabLayout.OnTabSelectedListener() {
            @Override public void onTabSelected(@NonNull TabLayout.Tab tab) {
                pane = tab.getPosition();
                model.rememberPane(pane);
                showPane();
            }

            @Override public void onTabUnselected(@NonNull TabLayout.Tab tab) {}

            // Tapping the current tab reloads it. The panes are views over analysis
            // that the rest of the app can change underneath them — clearing the
            // selection, for one — so a re-tap has to mean something.
            @Override public void onTabReselected(@NonNull TabLayout.Tab tab) { showPane(); }
        });

        graph.setOnNodeClickListener(node -> {
            if (node.address != -1) jumpTo(node.address,Pane.GRAPH);
        });

        model.state().observe(this, current -> {
            busy(current.phase == WorkspaceViewModel.Phase.OPENING);
            if (current.phase != WorkspaceViewModel.Phase.EMPTY) {
                // Restore the shell for a pending open, results, or a failure log.
                empty.setVisibility(View.GONE);
                content.setVisibility(View.VISIBLE);
            }
            if (current.phase == WorkspaceViewModel.Phase.READY) {
                session = model.session();
                onOpened(current.name);
            } else if (current.phase == WorkspaceViewModel.Phase.FAILED) {
                appendLog(getString(R.string.ws_open_failed, current.message));
                selectPane(Pane.LOG);
            } else if (current.phase == WorkspaceViewModel.Phase.CANCELED) {
                appendLog(current.message == null ? getString(R.string.ws_analysis_cancelled) : current.message);
                if (session == null) selectPane(Pane.LOG);
            }
        });

        if (model.claimInitialLaunch()) {
            String savedProject = state == null ? null : state.getString(STATE_PROJECT);
            if (savedProject != null) model.openSavedProject(this, savedProject);
            else handleLaunchIntent(getIntent(), state == null);
        }
    }

    private void handleLaunchIntent(@Nullable Intent intent, boolean newActivity) {
        if (intent == null || intent.getAction() == null) return;
        switch (intent.getAction()) {
            case Intent.ACTION_VIEW:
            case ACTION_CLONE:
                Uri uri = intent.getData();
                if (uri == null) uri = IntentCompat.getParcelableExtra(intent, EXTRA_INPUT, Uri.class);
                if (uri == null) return;
                if (ACTION_CLONE.equals(intent.getAction())) {
                    resetOpeningView(uri);
                    model.openClone(this, uri);
                } else open(uri, null);
                break;
            case ACTION_PROJECT:
                String id = intent.getStringExtra(EXTRA_ID);
                if (id != null) model.openSavedProject(this, id);
                break;
            case ACTION_LEARN:
                if (lesson != null) model.openLesson(this, lesson.id, lesson.asset);
                break;
            case ACTION_IMPORT_OPTIONS:
                if (newActivity) pickFile();
                break;
            default:
                break;
        }
    }

    @Override
    protected void onDestroy() {
        showGuideOnOpen = false;
        if (learnGuide != null) learnGuide.dismiss();
        if (betaNotice != null && betaNotice.isShowing()) betaNotice.dismiss();
        betaNotice = null;
        super.onDestroy();
        if(sandboxCopyCancelled!=null)sandboxCopyCancelled.set(true);
        if(sandboxPlugin!=null){sandboxPlugin.close();sandboxPlugin=null;}
        // The ViewModel owns both the worker and native handle. onDestroy is also
        // the normal rotation callback, so closing either here loses the analysis.
    }

    @Override
    protected void onSaveInstanceState(@NonNull Bundle out) {
        out.putInt("pane", pane);
        out.putLong("selected", selected == null ? -1 : selected.entry);
        out.putLong("listing", listingAddress);
        out.putString(STATE_PROJECT, model.openedProjectId());
        if(pendingRawImport!=null){out.putString("pendingRawArch",pendingRawImport.architecture);out.putLong("pendingRawBase",pendingRawImport.baseAddress);out.putLong("pendingRawEntry",pendingRawImport.entryAddress);}
        model.rememberWorkspace(selected == null ? -1 : selected.entry, listingAddress, pane);
        super.onSaveInstanceState(out);
    }

    private void returnToWelcome(boolean learn) {
        Intent intent = learn ? WelcomeActivity.learnCatalogIntent(this) : new Intent(this, WelcomeActivity.class);
        intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_SINGLE_TOP);
        startActivity(intent);
        finish();
    }

    private void configureLesson(boolean firstOpen) {
        Intent launch = getIntent();
        if (launch == null || !ACTION_LEARN.equals(launch.getAction())) return;
        lesson = LearnLesson.find(launch.getStringExtra(EXTRA_ID));
        if (lesson == null) return;
        showGuideOnOpen = firstOpen && !lesson.isComplete(LearnLesson.progress(this));
        learnGuide = new LearnGuide(this, lesson, new LearnGuide.Workspace() {
            @Override public void inspect(int step) {
                if (!isLessonActive()) return;
                switch (step) {
                    case 0:
                        jumpTo(lesson.entry, Pane.DISASM);
                        break;
                    case 1:
                        jumpTo(lesson.entry, lesson == LearnLesson.STRINGS ? Pane.STRINGS : Pane.C);
                        break;
                    case 2:
                        if (lesson == LearnLesson.STRINGS) {
                            showReferences(LearnLesson.PRACTICE_LABEL_ADDRESS);
                        } else if (lesson == LearnLesson.CALLS) {
                            clearSelection();
                            if (pane != Pane.GRAPH) selectPane(Pane.GRAPH);
                        } else {
                            jumpTo(lesson.entry, Pane.GRAPH);
                        }
                        break;
                    default:
                        break;
                }
            }

            @Override public void openPatchEditor() {
                if (!isLessonActive() || lesson.expectedPatch == null) return;
                jumpTo(lesson.patchAddress, Pane.DISASM);
                promptAssembly(lesson.patchAddress);
            }

            @Override public void checkPatch(java.util.function.Consumer<Boolean> result) {
                if (!isLessonActive() || lesson.expectedPatch == null) {
                    result.accept(null);
                    return;
                }
                MintSession active = session;
                worker.execute(() -> {
                    Boolean matches;
                    try {
                        matches = lesson.expectedPatch.equals(active.patchReviewBytes(lesson.patchAddress, 4));
                    } catch (RuntimeException error) {
                        matches = null;
                    }
                    Boolean checked = matches;
                    main.post(() -> {
                        if (!isFinishing() && !isDestroyed()) {
                            result.accept(active == session && isLessonActive() ? checked : null);
                        }
                    });
                });
            }

            @Override public void returnToCatalog() {
                returnToWelcome(true);
            }
        });
        learnGuideButton.setOnClickListener(view -> {
            if (isLessonActive()) learnGuide.show();
        });
    }

    private boolean isLessonActive() {
        java.io.File binary = model.binaryFile();
        return lesson != null && session != null && session == model.session() && binary != null
                && ProjectStore.lessonProjectId(lesson.id).equals(binary.getParentFile().getName());
    }

    private void showInitialLessonGuide() {
        if (!showGuideOnOpen || isFinishing() || isDestroyed() || !isLessonActive()
                || learnGuideButton.getVisibility() != View.VISIBLE
                || (betaNotice != null && betaNotice.isShowing())) return;
        showGuideOnOpen = false;
        learnGuide.show();
    }

    private static final String FEEDBACK_EMAIL = "cybercraftstudiopro@gmail.com";

    /**
     * Tells the user this build is a beta, once per version.
     *
     * <p>Keyed on the version name rather than a plain flag, so the notice comes
     * back after an update — what is and is not working changes between builds, and
     * a notice shown once ever would go stale immediately.
     *
     * <p>Marked as seen only when the user actually acts on it. A dialog dismissed
     * because the activity was recreated — a rotation — has not been read, so it is
     * shown again; that is why this listens for cancel rather than dismiss.
     */
    private void showBetaNoticeOnce() {
        final String version = versionName();
        final SharedPreferences prefs = getSharedPreferences("mint", MODE_PRIVATE);
        if (version.equals(prefs.getString("beta_notice_seen", null))) return;

        final Runnable remember = () ->
                prefs.edit().putString("beta_notice_seen", version).apply();

        betaNotice = new com.google.android.material.dialog.MaterialAlertDialogBuilder(this)
                .setTitle(R.string.beta_title)
                .setMessage(getString(R.string.beta_message, FEEDBACK_EMAIL))
                .setPositiveButton(R.string.beta_ok, (d, which) -> remember.run())
                .setNeutralButton(R.string.beta_feedback, (d, which) -> {
                    remember.run();
                    composeFeedback(version);
                })
                .setOnCancelListener(d -> remember.run())
                .show();
    }

    /**
     * Opens an email draft. Deliberately a draft and not a send: the message is the
     * user's, so they get to see and change it before it goes anywhere.
     */
    private void composeFeedback(@NonNull String version) {
        Intent mail = new Intent(Intent.ACTION_SENDTO, Uri.parse("mailto:"));
        mail.putExtra(Intent.EXTRA_EMAIL, new String[]{FEEDBACK_EMAIL});
        mail.putExtra(Intent.EXTRA_SUBJECT, getString(R.string.beta_subject, version));
        try {
            startActivity(mail);
        } catch (android.content.ActivityNotFoundException e) {
            // A device with no mail client still needs the address, so it goes to the
            // log pane where it can be read and copied.
            appendLog(getString(R.string.beta_no_mail, FEEDBACK_EMAIL));
            selectPane(Pane.LOG);
        }
    }

    @NonNull
    private String versionName() {
        try {
            return String.valueOf(getPackageManager()
                    .getPackageInfo(getPackageName(), 0).versionName);
        } catch (android.content.pm.PackageManager.NameNotFoundException e) {
            return "unknown";
        }
    }

    /**
     * Shows the bundled third-party notices.
     *
     * <p>Not decoration. Capstone is BSD-3-Clause, which requires its copyright
     * notice and disclaimer to be reproduced in the materials distributed with a
     * binary form. Shipping the compiled disassembler with the notice only present
     * in the source tree would not satisfy that, because nobody receiving the app
     * ever sees the source tree.
     */
    private void showLicences() {
        String text;
        try (java.io.InputStream in =
                     getResources().openRawResource(R.raw.third_party_licenses)) {
            java.io.ByteArrayOutputStream buffer = new java.io.ByteArrayOutputStream();
            byte[] chunk = new byte[8192];
            int read;
            while ((read = in.read(chunk)) > 0) buffer.write(chunk, 0, read);
            text = buffer.toString("UTF-8");
        } catch (java.io.IOException e) {
            text = "Could not read the bundled licences: " + e.getMessage();
        }
        TextView view = new TextView(this);
        view.setText(text);
        view.setTypeface(Typeface.MONOSPACE);
        view.setTextSize(11);
        view.setTextIsSelectable(true);
        final int padding = Math.round(16 * getResources().getDisplayMetrics().density);
        view.setPadding(padding, padding, padding, padding);
        android.widget.ScrollView scroll = new android.widget.ScrollView(this);
        scroll.addView(view);
        new com.google.android.material.dialog.MaterialAlertDialogBuilder(this)
                .setTitle(R.string.licences)
                .setView(scroll)
                .setPositiveButton(android.R.string.ok, null)
                .show();
    }

    // ------------------------------------------------------------------ opening

    private void pickFile() {
        new com.google.android.material.dialog.MaterialAlertDialogBuilder(this).setTitle(R.string.ws_import_title)
                .setItems(new String[]{getString(R.string.ws_import_auto), getString(R.string.ws_import_raw), getString(R.string.ws_import_archive), getString(R.string.ws_import_macho)},(d,which) -> {
                    if(which==0){pendingRawImport=null;launchFilePicker();}
                    else if(which==1)promptRawImport();
                    else if(which==2)pickDocument(PROJECT_OPEN_REQUEST);
                    else new com.google.android.material.dialog.MaterialAlertDialogBuilder(this).setTitle(R.string.ws_macho_arch).setItems(new String[]{"AArch64", "x86-64", "x86-32", "ARM"},(dialog,index)->{
                        pendingRawImport=RawImportConfig.machOSlice(new String[]{"aarch64","x86-64","x86-32","arm"}[index]);launchFilePicker();
                    }).show();
                }).show();
    }

    private void promptRawImport() {
        final com.ccs.mint.core.RawArchitecture[] architectures;
        try { architectures = MintSession.rawArchitectures(); RawImportConfig.installArchitectures(architectures); }
        catch (RuntimeException | LinkageError error) { showProjectError(getString(R.string.ws_decoder_error, error.getMessage())); return; }
        final String[] labels = new String[architectures.length];
        for (int i = 0; i < labels.length; ++i) labels[i] = architectures[i].name + " — " + (architectures[i].pointerSize * 8) + "-bit" +
                (architectures[i].numericId >= 128 ? (architectures[i].hasLifter?" (plugin decoder + semantic lifter)":" (plugin decoder; no lifter)") : "");
        new com.google.android.material.dialog.MaterialAlertDialogBuilder(this).setTitle(R.string.ws_raw_arch)
                .setItems(labels,(d,which) -> {
                    LinearLayout form=new LinearLayout(this);form.setOrientation(LinearLayout.VERTICAL);
                    EditText base=new EditText(this),entry=new EditText(this);
                    base.setHint(R.string.ws_base_hex);base.setText("0x1000");entry.setHint(R.string.ws_entry_hex);entry.setText("0x1000");form.addView(base);form.addView(entry);
                    android.widget.CheckBox bigEndian=new android.widget.CheckBox(this);bigEndian.setText(R.string.ws_big_endian);bigEndian.setVisibility(architectures[which].id.equals("aarch64")?android.view.View.VISIBLE:android.view.View.GONE);form.addView(bigEndian);
                    new com.google.android.material.dialog.MaterialAlertDialogBuilder(this).setTitle(R.string.ws_raw_mapping).setView(form)
                            .setPositiveButton(R.string.ws_choose_file,(dialog,w) -> {
                                try{pendingRawImport=RawImportConfig.fromHex(architectures[which].id+(bigEndian.isChecked()?":be":""),base.getText().toString(),entry.getText().toString());launchFilePicker();}
                                catch(IllegalArgumentException e){showProjectError(e.getMessage());}
                            }).setNegativeButton(android.R.string.cancel,null).show();
                }).show();
    }

    private void launchFilePicker() {
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("*/*");
        startActivityForResult(intent, OPEN_REQUEST);
    }

    @Override
    protected void onActivityResult(int request, int result, @Nullable Intent data) {
        super.onActivityResult(request, result, data);
        if (request == OPEN_REQUEST && result == Activity.RESULT_OK
                && data != null && data.getData() != null) {
            open(data.getData(),pendingRawImport);
            pendingRawImport=null;
        }
        if(request==EXPORT_REQUEST && result==Activity.RESULT_OK && data!=null && data.getData()!=null)exportPatchedTo(data.getData());
        if (request == REVIEWED_PATCH_EXPORT_REQUEST) {
            PatchReview review = model.pendingReviewedExport;
            model.pendingReviewedExport = null;
            if (result == Activity.RESULT_OK && data != null && data.getData() != null) {
                if (review == null) showProjectError(getString(R.string.patch_review_expired));
                else exportPatchedTo(data.getData(), review);
            }
        }
        if (request == PSEUDO_C_EXPORT_REQUEST) {
            final String report = model.pendingPseudoCExport;
            model.pendingPseudoCExport = null;
            if (result == Activity.RESULT_OK && data != null && data.getData() != null)
                writePseudoCReport(data.getData(), report);
        }
        if(request==SCRIPT_REQUEST && result==Activity.RESULT_OK && data!=null && data.getData()!=null)openScript(data.getData());
        if(request==COMPARISON_REQUEST && result==Activity.RESULT_OK && data!=null && data.getData()!=null)openComparison(data.getData());
        if(request==PLUGIN_REQUEST && result==Activity.RESULT_OK && data!=null && data.getData()!=null)openNativePlugin(data.getData());
        if(request==SANDBOX_PLUGIN_REQUEST && result==Activity.RESULT_OK && data!=null && data.getData()!=null)openIsolatedPlugin(data.getData());
        if(request==LIBRARY_REQUEST && result==Activity.RESULT_OK && data!=null && data.getData()!=null)openLibrary(data.getData());
        if(request==TRACKING_SAVE_REQUEST && result==Activity.RESULT_OK && data!=null && data.getData()!=null)trackingDocument(data.getData(),true);
        if(request==TRACKING_LOAD_REQUEST && result==Activity.RESULT_OK && data!=null && data.getData()!=null)trackingDocument(data.getData(),false);
        if(request==PROJECT_SAVE_REQUEST && result==Activity.RESULT_OK && data!=null && data.getData()!=null)exportProjectTo(data.getData());
        if(request==PROJECT_OPEN_REQUEST && result==Activity.RESULT_OK && data!=null && data.getData()!=null) {
            resetOpeningView(data.getData()); model.importProjectArchive(this, data.getData());
        }
        if(request==DEBUG_IMPORT_REQUEST && result==Activity.RESULT_OK && data!=null && data.getData()!=null)importExternalDebug(data.getData());
    }

    private void open(@NonNull Uri uri,@Nullable RawImportConfig config) {
        resetOpeningView(uri);
        model.open(this, uri,config);
    }

    private void resetOpeningView(@NonNull Uri uri) {
        ++viewGeneration;
        learnGuideButton.setVisibility(View.GONE);
        sourceListing = null;
        restoreSourceScroll = null;
        reverseListing = null;
        restoreListingScroll = null;
        session = null;
        empty.setVisibility(View.GONE);
        content.setVisibility(View.VISIBLE);
        appendLog(getString(R.string.ws_opening, uri.getLastPathSegment()));
        selected = null;
        pendingAddress = -1;
        functions.clear();
        visible.clear();
        adapter.submit(new ArrayList<>());
        graph.setNodes(new ArrayList<>());
        openFunctions.clear();
        history.clear();
        updateSelectionChip();
    }

    private void onOpened(@Nullable String name) {
        session = model.session();
        if (session == null) return;
        pendingAddress = model.selectedAddress();
        listingAddress = model.listingAddress();
        pane = Pane.valid(model.pane()) ? model.pane() : Pane.FUNCTIONS;
        // Also runs after rotation, when the new view hierarchy was inflated with
        // content=gone and no click has happened in this Activity instance.
        empty.setVisibility(View.GONE);
        content.setVisibility(View.VISIBLE);
        title.setText(name == null ? getString(R.string.ws_binary) : name.substring(name.lastIndexOf('/') + 1));
        appendLog(session.imageSummary());
        appendLog(session.warnings());
        loadFunctions();
    }

    private void loadFunctions() {
        busy(true);
        MintSession active = session;
        worker.execute(() -> {
            final List<FunctionRow> rows = new ArrayList<>();
            String error = null;
            try {
                if (active == null) return;
                int total = active.functionCount();
                long[] entry = new long[PAGE];
                int[] size = new int[PAGE];
                int[] blocks = new int[PAGE];
                int[] instructions = new int[PAGE];
                int[] flags = new int[PAGE];
                String[] names = new String[PAGE];
                for (int offset = 0; offset < total; offset += PAGE) {
                    int got = active.functions(offset, PAGE, entry, size, blocks,
                            instructions, flags, names);
                    if (got <= 0) break;
                    for (int i = 0; i < got; i++) {
                        FunctionRow row = new FunctionRow();
                        row.entry = entry[i];
                        row.size = size[i];
                        row.instructions = instructions[i];
                        row.name = names[i];
                        rows.add(row);
                    }
                }
            } catch (RuntimeException e) {
                error = getString(R.string.ws_functions_failed, e.getMessage());
            }
            final String failure = error;
            runOnUiThread(() -> {
                if (isFinishing() || isDestroyed() || session == null || active != session) return;
                busy(false);
                appendLog(failure);
                functions.clear();
                functions.addAll(rows);
                applyFilter();
                selected = null;
                if (pendingAddress != -1) {
                    FunctionRow restored = findFunction(pendingAddress);
                    if (restored != null) {
                        selected = restored;
                        if (!openFunctions.contains(restored)) openFunctions.add(restored);
                        if (listingAddress == 0) listingAddress = restored.entry;
                    }
                }
                model.rememberSelection(selected==null?-1:selected.entry,listingAddress);
                updateSelectionChip();
                selectPane(pane);
                learnGuideButton.setVisibility(isLessonActive() ? View.VISIBLE : View.GONE);
                showInitialLessonGuide();
            });
        });
    }

    // -------------------------------------------------------------------- panes

    /**
     * Moves to a pane. Selecting the tab is what normally drives this, so the
     * already-selected case has to be handled by hand: {@code Tab.select()} is a
     * no-op when the tab is current, and callers use this to mean "show me that
     * pane's content now", not "change tabs if it happens to be a different one".
     */
    private void selectPane(int target) {
        if (!Pane.valid(target)) return;
        final TabLayout.Tab tab = nav.getTabAt(target);
        if (tab == null) return;
        if (nav.getSelectedTabPosition() == target) {
            pane = target;
            model.rememberPane(pane);
            showPane();
        } else {
            tab.select();
        }
    }

    /**
     * Leaves the function and goes back to the program.
     *
     * <p>Without this the only way out of a function is to pick a different one, so
     * the whole-program views become unreachable the moment anything is opened.
     */
    private void clearSelection() {
        openFunctions.clear();
        selected = null;
        pendingAddress = -1;
        listingAddress = 0;
        model.rememberWorkspace(-1, 0, pane);
        history.clear();
        updateSelectionChip();
        showPane();
    }

    /**
     * Rebuilds the row of open functions.
     *
     * <p>Rebuilt wholesale rather than diffed: the row holds a handful of chips, and
     * a diff would be more code than the thing it saves.
     */
    private void updateSelectionChip() {
        openScroll.setVisibility(openFunctions.isEmpty() ? View.GONE : View.VISIBLE);
        ((ChipGroup) openChips).removeAllViews();
        for (final FunctionRow row : new ArrayList<>(openFunctions)) {
            final Chip chip = new Chip(this);
            chip.setText(row.label());
            chip.setCheckable(true);
            chip.setChecked(row == selected);
            chip.setCloseIconVisible(true);
            chip.setCloseIconContentDescription(getString(R.string.clear_function));
            chip.setOnClickListener(v -> switchTo(row));
            chip.setOnCloseIconClickListener(v -> closeFunction(row));
            ((ChipGroup) openChips).addView(chip);
        }
        subtitle.setText(functions.isEmpty() ? "" : getResources().getQuantityString(R.plurals.ws_function_count, functions.size(), functions.size()));
    }

    /** Makes an already-open function the current one, keeping the pane. */
    private void switchTo(@NonNull FunctionRow row) {
        if (row == selected) return;
        selected = row;
        listingAddress = row.entry;
        pendingAddress = row.entry;
        model.rememberSelection(row.entry, listingAddress);
        updateSelectionChip();
        showPane();
    }

    /**
     * Closes one function. The neighbour takes over rather than dropping to the
     * program view, because closing one of several open functions is not a request
     * to stop looking at functions.
     */
    private void closeFunction(@NonNull FunctionRow row) {
        final int at = openFunctions.indexOf(row);
        if (at < 0) return;
        openFunctions.remove(at);
        if (selected == row) {
            selected = openFunctions.isEmpty()
                    ? null
                    : openFunctions.get(Math.min(at, openFunctions.size() - 1));
            listingAddress = selected == null ? 0 : selected.entry;
            pendingAddress = selected == null ? -1 : selected.entry;
            model.rememberSelection(pendingAddress, listingAddress);
            if (selected == null) history.clear();
        }
        updateSelectionChip();
        showPane();
    }

    /**
     * Renders the pane.
     *
     * <p>Every pane has a whole-program form and a per-function form, and which one
     * runs is decided by whether anything is selected. It used to say "Pick a
     * function first" instead, which is a dead end: the program has plenty to show
     * before a function is chosen, and refusing to show it makes the app look
     * broken rather than unselected.
     */
    private void showPane() {
        ++viewGeneration;
        if (pane != Pane.DISASM || selected == null ||
                (sourceListing != null && selected.entry != sourceListing.entry)) sourceListing = null;
        if (pane != Pane.C) restoreSourceScroll = null;
        if (pane != Pane.C && (pane != Pane.DISASM || sourceListing == null)) reverseListing = null;
        if (pane != Pane.DISASM) restoreListingScroll = null;
        if(session!=null)busy(false);
        final boolean isList = pane == Pane.FUNCTIONS || pane == Pane.DISASM;
        list.setVisibility(isList ? View.VISIBLE : View.GONE);
        textScroll.setVisibility(isList || pane == Pane.GRAPH ? View.GONE : View.VISIBLE);
        graph.setVisibility(pane == Pane.GRAPH ? View.VISIBLE : View.GONE);
        filter.setVisibility(pane == Pane.FUNCTIONS ? View.VISIBLE : View.GONE);

        if (pane == Pane.LOG) {
            text.setText(log.isEmpty() ? getString(R.string.ws_log_empty) : log);
            return;
        }
        if (session == null) {
            adapter.submit(new ArrayList<>());
            graph.setNodes(new ArrayList<>());
            text.setText("");
            return;
        }
        switch (pane) {
            case Pane.FUNCTIONS:
                applyFilter();
                break;
            case Pane.DISASM:
                loadListing(selected);
                break;
            case Pane.GRAPH:
                if (selected == null) loadCallGraph(); else loadGraph(selected);
                break;
            // Each pane's whole-program form has to be its own view. Routing three of
            // them to one overview meant three tabs showing byte-identical text,
            // which reads as broken for the same reason "Pick a function first" did.
            case Pane.IR:
                if (selected == null) loadProgramText(Program.COVERAGE);
                else loadText(selected, true);
                break;
            case Pane.C:
                if (selected == null) loadProgramText(Program.PROTOTYPES);
                else loadText(selected, false);
                break;
            case Pane.WRITES:
                if (selected == null) loadProgramText(Program.WRITES);
                else loadWriteMap(selected);
                break;
            // Strings work either way: the whole image, or narrowed to what one
            // function refers to. Making them resolvable inside pseudo-C is not the
            // same as making them readable, and reading the strings is the first
            // thing anyone does to a binary they do not know.
            case Pane.STRINGS:
                loadStrings(selected);
                break;
            // Xrefs are inherently about one function, so this is the one pane with
            // no whole-program form — the call graph in the CFG pane already is it.
            case Pane.XREFS:
                if (selected == null) {
                    text.setText(getString(R.string.xrefs_hint));
                } else {
                    loadXrefs(selected);
                }
                break;
            default:
                break;
        }
    }

    private void applyFilter() {
        String query = filter.getText().toString().trim().toLowerCase(Locale.US);
        visible.clear();
        for (FunctionRow row : functions) {
            if (query.isEmpty() || row.label().toLowerCase(Locale.US).contains(query)
                    || Long.toHexString(row.entry).contains(query)) {
                visible.add(row);
            }
        }
        List<Line> lines = new ArrayList<>(visible.size());
        for (FunctionRow row : visible) {
            lines.add(new Line(String.format(Locale.US, "%08x  %s", row.entry, row.label()),
                    getResources().getQuantityString(R.plurals.ws_instruction_count, row.instructions, row.instructions), -1, row));
        }
        adapter.submit(lines);
        subtitle.setText(query.isEmpty()
                ? getResources().getQuantityString(R.plurals.ws_function_count, functions.size(), functions.size())
                : getString(R.string.ws_function_filter, visible.size(), functions.size()));
    }

    /**
     * Disassembles into the list pane: one function, or the whole image when
     * {@code function} is null.
     *
     * <p>The two differ only in where they stop. A function stops at its own end; the
     * program stops at {@link #PROGRAM_LISTING_LIMIT} instructions, because a large
     * library holds far more than anyone scrolls through and formatting all of them
     * costs seconds before the first line appears.
     */
    private void loadListing(@Nullable FunctionRow function) {
        busy(true);
        final android.os.Parcelable scroll = restoreListingScroll;
        restoreListingScroll = null;
        final MintSession active = session;
        final long requestGeneration = viewGeneration;
        final long start;
        final long stop;
        final int cap;
        final SourceListing range = sourceListing;
        if (range != null) {
            start = range.start;
            stop = range.end;
            cap = PROGRAM_LISTING_LIMIT;
        } else if (function == null) {
            // listingAddress survives a jump out of a function, so a program listing
            // resumes where the user was rather than at the top of the image.
            start = listingAddress;
            stop = -1; // unsigned address-space limit, not signed Long.MAX_VALUE
            cap = PROGRAM_LISTING_LIMIT;
        } else {
            final long end = function.entry + Math.max(1, function.size);
            start = Long.compareUnsigned(listingAddress,function.entry)>=0 && Long.compareUnsigned(listingAddress,end)<0
                    ? listingAddress : function.entry;
            stop = end;
            cap = Integer.MAX_VALUE;
        }

        worker.execute(() -> {
            final List<Line> lines = new ArrayList<>();
            try {
                if (active == null) return;
                if (range != null) {
                    lines.add(new Line(getString(R.string.ws_pseudo_source_range, range.start, range.end), null, -1, null));
                }
                long[] address = new long[LISTING_LIMIT];
                int[] size = new int[LISTING_LIMIT];
                int[] flow = new int[LISTING_LIMIT];
                long[] target = new long[LISTING_LIMIT];
                String[] body = new String[LISTING_LIMIT];
                String[] comment = new String[LISTING_LIMIT];
                long cursor = start;
                boolean done = false;
                boolean complete = false;
                for (int page = 0; page < MAX_LISTING_PAGES && !done; ++page) {
                    int got = active.listing(cursor, LISTING_LIMIT, address, size, flow,
                            target, body, comment);
                    if (got <= 0) {
                        complete = true;
                        break;
                    }
                    long last = cursor;
                    for (int i = 0; i < got; i++) {
                        if (Long.compareUnsigned(address[i],stop)>=0 || lines.size() >= cap) {
                            done = true;
                            break;
                        }
                        lines.add(new Line(
                                String.format(Locale.US, "%08x  %s", address[i],
                                        body[i] == null ? "" : body[i].trim()),
                                comment[i] == null || comment[i].isEmpty()
                                        ? null : "; " + comment[i],
                                target[i], null));
                        last = address[i] + Math.max(1, size[i]);
                    }
                    if (done || got < LISTING_LIMIT || Long.compareUnsigned(last,cursor)<=0) {
                        complete = complete || lines.size() < cap;
                        break;
                    }
                    cursor = last;
                }
                if (lines.size() >= cap) {
                    lines.add(new Line(getString(R.string.ws_listing_limit, cap), null, -1, null));
                } else if (!complete) {
                    lines.add(new Line(getString(R.string.ws_listing_page_limit), null,
                            -1, null));
                }
            } catch (RuntimeException e) {
                lines.add(new Line("listing failed: " + e.getMessage(), null, -1, null));
            }
            runOnUiThread(() -> {
                if (isFinishing() || isDestroyed() || active != session || requestGeneration != viewGeneration) return;
                busy(false);
                adapter.submit(lines);
                if (scroll != null && list.getLayoutManager() != null)
                    list.getLayoutManager().onRestoreInstanceState(scroll);
            });
        });
    }

    /** Who calls the selected function, and what it calls. */
    private void loadXrefs(@NonNull FunctionRow function) {
        adapter.submit(new ArrayList<>());
        text.setText("");
        busy(true);
        final MintSession active = session;
        final long requestGeneration = viewGeneration;
        worker.execute(() -> {
            String body;
            try {
                if (active == null) throw new IllegalStateException("session is closed");
                body = active.xrefs(function.entry);
            } catch (RuntimeException e) {
                body = getString(R.string.ws_xrefs_failed, e.getMessage());
            }
            final CharSequence result = highlighter.code(
                    body == null || body.isEmpty() ? getString(R.string.ws_no_output) : body);
            runOnUiThread(() -> {
                if (isFinishing() || isDestroyed() || active != session || requestGeneration != viewGeneration) return;
                busy(false);
                text.setText(linkedCode(result));
            });
        });
    }

    /** The image's strings, or just the ones {@code function} refers to. */
    private void loadStrings(@Nullable FunctionRow function) {
        adapter.submit(new ArrayList<>());
        text.setText("");
        busy(true);
        final MintSession active = session;
        final long requestGeneration = viewGeneration;
        final long scope = function == null ? 0 : function.entry;
        worker.execute(() -> {
            String body;
            try {
                if (active == null) throw new IllegalStateException("session is closed");
                body = active.strings(scope);
            } catch (RuntimeException e) {
                body = getString(R.string.ws_strings_failed, e.getMessage());
            }
            final CharSequence result = highlighter.code(
                    body == null || body.isEmpty() ? getString(R.string.ws_no_output) : body);
            runOnUiThread(() -> {
                if (isFinishing() || isDestroyed() || active != session || requestGeneration != viewGeneration) return;
                busy(false);
                text.setText(result);
            });
        });
    }

    /** Which whole-program report a pane asks for when nothing is selected. */
    private enum Program { COVERAGE, PROTOTYPES, WRITES }

    /**
     * The whole-program view for the IR, pseudo-C and Writes panes.
     *
     * <p>Three reports rather than one, because a pane that shows what two other
     * panes already show may as well be empty. Coverage answers how much of the
     * program became real IR, prototypes are the program as a C header, and the
     * write summary is what it modifies.
     *
     * <p>Coverage and the write summary share one native pass, so whichever is
     * opened first pays for it. Prototypes have their own, because a signature costs
     * a full decompilation and folding that in would make the cheap two wait.
     */
    private void loadProgramText(@NonNull Program report) {
        adapter.submit(new ArrayList<>());
        text.setText("");
        busy(true);
        final MintSession active = session;
        final long requestGeneration = viewGeneration;
        worker.execute(() -> {
            String body;
            try {
                if (active == null) throw new IllegalStateException("session is closed");
                switch (report) {
                    case PROTOTYPES: body = active.programPrototypes(); break;
                    case WRITES: body = active.programWrites(); break;
                    default: body = active.programCoverage(); break;
                }
            } catch (RuntimeException e) {
                body = getString(R.string.ws_general_report_failed, e.getMessage());
            }
            final CharSequence result = highlighter.code(
                    body == null || body.isEmpty() ? getString(R.string.ws_no_output) : body);
            runOnUiThread(() -> {
                if (isFinishing() || isDestroyed() || active != session || requestGeneration != viewGeneration) return;
                busy(false);
                text.setText(result);
            });
        });
    }

    /**
     * The program's call graph: one node per function, one edge per direct call.
     *
     * <p>Capped, and loudly. Past a few thousand nodes the layout is slower than the
     * view is useful, so the highest-degree functions are kept — those are the ones
     * a call graph is read for — and the log says how many were dropped. A graph
     * that quietly shows two thirds of a program is worse than one that admits it.
     */
    private void loadCallGraph() {
        busy(true);
        final MintSession active = session;
        final long requestGeneration = viewGeneration;
        final List<FunctionRow> snapshot = new ArrayList<>(functions);
        worker.execute(() -> {
            final List<GraphView.Node> nodes = new ArrayList<>();
            String failure = null;
            int dropped = 0;
            try {
                if (active == null) return;
                for (String row : active.callGraph().split("\\R")) {
                    final String[] fields = row.trim().split("\\s+");
                    if (fields.length < 2) continue;
                    final int index = Integer.parseInt(fields[0]);
                    final long entry = Long.parseUnsignedLong(fields[1]);
                    final GraphView.Node node = new GraphView.Node(index,
                            index < snapshot.size() ? snapshot.get(index).label()
                                    : String.format(Locale.US, "sub_%x", entry));
                    node.address = entry;
                    for (int i = 2; i < fields.length; i++) {
                        node.successors.add(Integer.parseInt(fields[i]));
                    }
                    nodes.add(node);
                }
                dropped = capCallGraph(nodes);
            } catch (RuntimeException e) {
                failure = getString(R.string.ws_calls_failed, e.getMessage());
            }
            final String error = failure;
            final int removed = dropped;
            runOnUiThread(() -> {
                if (isFinishing() || isDestroyed() || active != session || requestGeneration != viewGeneration) return;
                busy(false);
                appendLog(error);
                if (removed > 0) {
                    appendLog(getString(R.string.ws_calls_limit, CALL_GRAPH_LIMIT, removed));
                }
                if (nodes.isEmpty() && error == null) {
                    appendLog(getString(R.string.call_graph_empty));
                }
                graph.setNodes(nodes);
            });
        });
    }

    /**
     * Trims the graph to {@link #CALL_GRAPH_LIMIT} nodes, keeping the best connected
     * ones, and returns how many were removed. Edges into removed nodes go with
     * them, so what is left is a real subgraph rather than one with dangling arrows.
     */
    private static int capCallGraph(List<GraphView.Node> nodes) {
        if (nodes.size() <= CALL_GRAPH_LIMIT) return 0;

        final java.util.Map<Integer, Integer> degree = new java.util.HashMap<>();
        for (GraphView.Node node : nodes) {
            degree.merge(node.id, node.successors.size(), Integer::sum);
            for (Integer target : node.successors) degree.merge(target, 1, Integer::sum);
        }
        final List<GraphView.Node> ranked = new ArrayList<>(nodes);
        Collections.sort(ranked, (a, b) -> Integer.compare(
                degree.getOrDefault(b.id, 0), degree.getOrDefault(a.id, 0)));

        final java.util.Set<Integer> keep = new java.util.HashSet<>();
        for (int i = 0; i < CALL_GRAPH_LIMIT; i++) keep.add(ranked.get(i).id);

        final int removed = nodes.size() - keep.size();
        for (java.util.Iterator<GraphView.Node> it = nodes.iterator(); it.hasNext(); ) {
            final GraphView.Node node = it.next();
            if (!keep.contains(node.id)) {
                it.remove();
                continue;
            }
            node.successors.removeIf(target -> !keep.contains(target));
        }
        return removed;
    }

    private void loadGraph(@Nullable FunctionRow function) {
        if (function == null) {
            graph.setNodes(new ArrayList<>());
            return;
        }
        busy(true);
        MintSession active = session;
        final long requestGeneration = viewGeneration;
        worker.execute(() -> {
            final List<GraphView.Node> nodes = new ArrayList<>();
            String graphError = null;
            try {
                String cfg = active == null ? "" : active.cfg(function.entry);
                String[] rows = cfg.split("\\R");
                for (String row : rows) {
                    String[] fields = row.trim().split("\\s+");
                    if (fields.length < 3) continue;
                    int id = Integer.parseInt(fields[0]);
                    long start = Long.parseUnsignedLong(fields[1]);
                    long end = Long.parseUnsignedLong(fields[2]);
                    GraphView.Node node = new GraphView.Node(id,
                            String.format(Locale.US, "B%d  %x-%x", id, start, end));
                    node.address = start;
                    for (int i = 3; i < fields.length; ++i) {
                        node.successors.add(Integer.parseInt(fields[i]));
                    }
                    nodes.add(node);
                }
            } catch (RuntimeException e) {
                graphError = getString(R.string.ws_cfg_failed, e.getMessage());
            }
            final String failure = graphError;
            runOnUiThread(() -> {
                if (isFinishing() || isDestroyed() || active != session || requestGeneration != viewGeneration) return;
                busy(false);
                appendLog(failure);
                graph.setNodes(nodes);
            });
        });
    }

    private void loadText(@NonNull FunctionRow function, boolean ir) {
        final Long requestedAnchor = ir ? null : pseudoCAnchor;
        pseudoCAnchor = null;
        busy(true);
        text.setText("");
        MintSession active = session;
        final long requestGeneration = viewGeneration;
        worker.execute(() -> {
            String body;
            String anchors = "";
            try {
                if (active == null) throw new IllegalStateException("session is closed");
                if (ir) body = active.functionIr(function.entry);
                else {
                    final String[] view = active.decompileView(function.entry);
                    body = view[0];
                    anchors = view[1];
                }
            } catch (RuntimeException e) {
                body = getString(R.string.ws_decompile_failed, e.getMessage());
            }
            final CharSequence result = highlighter.code(
                    body == null || body.isEmpty() ? getString(R.string.ws_no_output) : body);
            final String sourceAnchors = anchors;
            runOnUiThread(() -> {
                if (isFinishing() || isDestroyed() || active != session || requestGeneration != viewGeneration) return;
                busy(false);
                final CharSequence linked = linkedCode(result);
                text.setText(ir ? linked : linkedSourceRanges(linked, sourceAnchors, function.entry));
                if (requestedAnchor != null) revealPseudoCRanges(requestedAnchor, sourceAnchors, requestGeneration);
                final SourceListing restore = restoreSourceScroll;
                restoreSourceScroll = null;
                if (!ir && restore != null && restore.entry == function.entry) {
                    text.getViewTreeObserver().addOnPreDrawListener(new android.view.ViewTreeObserver.OnPreDrawListener() {
                        @Override public boolean onPreDraw() {
                            text.getViewTreeObserver().removeOnPreDrawListener(this);
                            if (requestGeneration == viewGeneration && active == session) {
                                ((View) text.getParent()).scrollTo(restore.scrollX, 0);
                                textScroll.scrollTo(0, restore.scrollY);
                            }
                            return true;
                        }
                    });
                }
            });
        });
    }

    /**
     * What memory the selected function writes.
     *
     * <p>The engine builds the whole map, density bars included, and this pane just
     * shows it. Formatting it here would mean sending the slot table across JNI to
     * lay out text that has no other reader.
     */
    private void loadWriteMap(@NonNull FunctionRow function) {
        busy(true);
        text.setText("");
        final MintSession active = session;
        final long requestGeneration = viewGeneration;
        worker.execute(() -> {
            String body;
            try {
                if (active == null) throw new IllegalStateException("session is closed");
                body = active.writeMap(function.entry);
            } catch (RuntimeException e) {
                body = getString(R.string.ws_writes_failed, e.getMessage());
            }
            final CharSequence result = highlighter.code(
                    body == null || body.isEmpty() ? getString(R.string.ws_no_output) : body);
            runOnUiThread(() -> {
                if (isFinishing() || isDestroyed() || active != session || requestGeneration != viewGeneration) return;
                busy(false);
                text.setText(result);
            });
        });
    }

    private void select(@NonNull FunctionRow row) {
        sourceListing = null;
        selected = row;
        listingAddress = row.entry;
        pendingAddress = row.entry;
        model.rememberSelection(row.entry, listingAddress);
        history.push(row.entry);
        if (!openFunctions.contains(row)) openFunctions.add(row);
        updateSelectionChip();
        selectPane(Pane.DISASM);
    }

    private FunctionRow findFunction(long address) {
        for (FunctionRow row : functions) {
            if (Long.compareUnsigned(address,row.entry)>=0 && Long.compareUnsigned(address,row.entry+Math.max(1,row.size))<0) return row;
        }
        for (FunctionRow row : functions) if (row.entry == address) return row;
        return null;
    }

    private void jumpTo(long address) {
        jumpTo(address,Pane.DISASM);
    }
    private void jumpTo(long address,int destinationPane) {
        sourceListing = null;
        reverseListing = null;
        FunctionRow row = findFunction(address);
        if (row == null) {
            selected = null;
            listingAddress = address;
            pendingAddress = -1;
            model.rememberSelection(-1,address);
            history.push(address);
            updateSelectionChip();
            selectPane(destinationPane);
            return;
        }
        selected = row;
        listingAddress = address;
        pendingAddress = row.entry;
        model.rememberSelection(row.entry, listingAddress);
        history.push(address);
        if (!openFunctions.contains(row)) openFunctions.add(row);
        updateSelectionChip();
        selectPane(destinationPane);
    }

    private boolean navigateBack() {
        if (pane == Pane.DISASM && sourceListing != null && selected != null
                && selected.entry == sourceListing.entry) {
            restoreSourceScroll = sourceListing;
            listingAddress = sourceListing.previousAddress;
            sourceListing = null;
            model.rememberSelection(selected.entry, listingAddress);
            selectPane(Pane.C);
            return true;
        }
        if (pane == Pane.C && reverseListing != null) {
            final ListingOrigin origin = reverseListing;
            reverseListing = null;
            selected = origin.function;
            sourceListing = origin.source;
            restoreListingScroll = origin.scroll;
            listingAddress = origin.address;
            pendingAddress = selected == null ? -1 : selected.entry;
            if (selected != null && !openFunctions.contains(selected)) openFunctions.add(selected);
            model.rememberSelection(pendingAddress, listingAddress);
            updateSelectionChip();
            selectPane(Pane.DISASM);
            return true;
        }
        if (history.canGoBack()) {
            jumpTo(history.back());
            return true;
        }
        // Out of history but still inside a function: back should surface the whole
        // program before it leaves the app. Otherwise following a call chain to its
        // end and pressing back closes Mint, which is never what was meant.
        if (selected != null) {
            clearSelection();
            return true;
        }
        return false;
    }

    private void busy(boolean value) {
        returnToWelcome.setEnabled(!value);
        learnGuideButton.setEnabled(!value);
        if (value) {
            progress.setIndeterminate(false);
            progress.setMax(100);
            progress.setVisibility(View.VISIBLE);
            main.removeCallbacks(progressPoll);
            main.post(progressPoll);
        } else {
            main.removeCallbacks(progressPoll);
            progress.setVisibility(View.INVISIBLE);
        }
        cancel.setVisibility(value ? View.VISIBLE : View.GONE);
    }

    private void appendLog(@Nullable String message) {
        if (message == null || message.isEmpty()) return;
        log = log.isEmpty() ? message : log + "\n" + message;
        if (pane == Pane.LOG) text.setText(log);
    }

    private void showProjectActions() {
        if (session == null) return;
        final com.google.android.material.bottomsheet.BottomSheetDialog sheet =
                new com.google.android.material.bottomsheet.BottomSheetDialog(this);
        android.widget.ScrollView scroll = new android.widget.ScrollView(this);
        LinearLayout content = new LinearLayout(this);content.setOrientation(LinearLayout.VERTICAL);
        int padding = Math.round(16 * getResources().getDisplayMetrics().density);
        content.setPadding(padding,padding,padding,padding);
        TextView title = new TextView(this);title.setText(R.string.ws_tools);
        title.setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_HeadlineSmall);
        content.addView(title);
        final List<LinearLayout> sections = new ArrayList<>();
        final List<com.google.android.material.button.MaterialButton> headings = new ArrayList<>();
        for(int group=0;group<ProjectActions.GROUPS.length;++group) {
            final LinearLayout items = new LinearLayout(this);items.setOrientation(LinearLayout.VERTICAL);
            items.setVisibility(View.GONE);sections.add(items);
            com.google.android.material.button.MaterialButton heading = new com.google.android.material.button.MaterialButton(this, null,
                    com.google.android.material.R.attr.materialButtonOutlinedStyle);
            final String groupName=getString(ProjectActions.GROUPS[group]);
            heading.setText(groupName+"  ▾");heading.setAllCaps(false);
            heading.setContentDescription(groupName);ViewCompat.setStateDescription(heading,getString(R.string.help_collapsed));headings.add(heading);
            heading.setOnClickListener(view->{boolean expand=items.getVisibility()!=View.VISIBLE;
                for(int index=0;index<sections.size();++index){sections.get(index).setVisibility(View.GONE);
                    headings.get(index).setText(getString(ProjectActions.GROUPS[index])+"  ▾");ViewCompat.setStateDescription(headings.get(index),getString(R.string.help_collapsed));}
                items.setVisibility(expand?View.VISIBLE:View.GONE);
                if(expand){heading.setText(groupName+"  ▴");ViewCompat.setStateDescription(heading,getString(R.string.help_expanded));}});
            content.addView(heading,new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT,ViewGroup.LayoutParams.WRAP_CONTENT));
            for(int action:ProjectActions.ITEMS[group]) {
                com.google.android.material.button.MaterialButton button = new com.google.android.material.button.MaterialButton(new android.view.ContextThemeWrapper(this,
                        com.google.android.material.R.style.Widget_Material3_Button_TextButton));
                button.setText(ProjectActions.LABELS[action]);button.setAllCaps(false);button.setSingleLine(false);button.setMaxLines(3);button.setGravity(android.view.Gravity.START | android.view.Gravity.CENTER_VERTICAL);
                button.setOnClickListener(view->{sheet.dismiss();runProjectAction(action);});
                items.addView(button,new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT,ViewGroup.LayoutParams.WRAP_CONTENT));
            }
            content.addView(items);
        }
        scroll.setFillViewport(false);scroll.addView(content);sheet.setContentView(scroll);sheet.show();
    }

    private void runProjectAction(int which) {
        if(session==null)return;
        if (which == 0) promptSearch();
        else if (which == 1) {
            EditText input = new EditText(this); input.setHint(R.string.ws_go_to_hint);
            new com.google.android.material.dialog.MaterialAlertDialogBuilder(this).setTitle(R.string.ws_go_to).setView(input)
                    .setPositiveButton(R.string.ws_go,(d,w) -> {
                        try { jumpTo(Long.parseUnsignedLong(input.getText().toString().trim().replaceFirst("^(0x|0X)",""),16)); }
                        catch (NumberFormatException e) { showProjectError(getString(R.string.ws_hex_error)); }
                    }).setNegativeButton(android.R.string.cancel,null).show();
        } else if (which == 2) editAddress(listingAddress);
        else if (which == 3) showReferences(listingAddress);
        else if(which==4 || which==5) { MintSession active = session; mutateProject(() -> active.undoEdit(which == 5)); }
        else if(which==6)showMemoryBlocks();
        else if(which==7)showTypeManager();
        else if(which==8)showReport(getString(R.string.ws_provenance),active -> active.provenance(listingAddress));
        else if(which==9)showReport(getString(R.string.ws_cxx),MintSession::cxxMetadata);
        else if(which==10){MintSession active=session;mutateProject(active::reanalyze);}
        else if(which==11){Intent intent=new Intent(Intent.ACTION_CREATE_DOCUMENT);intent.setType("application/octet-stream");intent.addCategory(Intent.CATEGORY_OPENABLE);intent.putExtra(Intent.EXTRA_TITLE,"mint-patched.bin");startActivityForResult(intent,EXPORT_REQUEST);}
        else if(which==12 && history.canGoForward())jumpTo(history.forward());
        else if(which==13)showReport(getString(R.string.ws_dwarf_debug),MintSession::debugInfo);
        else if(which==14)promptAssembly(listingAddress);
        else if(which==15)promptScript("for _, f in ipairs(mint.functions()) do\n  print(f.entry, f.name, f.origin)\nend");
        else if(which==16){Intent intent=new Intent(Intent.ACTION_OPEN_DOCUMENT);intent.setType("*/*");intent.addCategory(Intent.CATEGORY_OPENABLE);startActivityForResult(intent,SCRIPT_REQUEST);}
        else if(which==17)showVersionTracking();
        else if(which==18)showDebugger();
        else if(which==19)showNativePlugins();
        else if(which==20)showReport(getString(R.string.ws_call_prototypes),MintSession::interproceduralPrototypes);
        else if(which==21) {
            Intent intent=new Intent(Intent.ACTION_CREATE_DOCUMENT);intent.setType("application/zip");
            intent.addCategory(Intent.CATEGORY_OPENABLE);intent.putExtra(Intent.EXTRA_TITLE,"mint-project.mintproj");
            startActivityForResult(intent,PROJECT_SAVE_REQUEST);
        } else if(which==22)pickDocument(PROJECT_OPEN_REQUEST);
        else if(which==23)showLocalVariables();
        else if(which==24){final long function=selected==null?listingAddress:selected.entry;showReport(getString(R.string.ws_abi_storage),s->s.abi(function));}
        else if(which==25)pickDocument(DEBUG_IMPORT_REQUEST);
        else if(which==26)preparePseudoCExport();
    }

    private void pickDocument(int request) {
        Intent intent=new Intent(Intent.ACTION_OPEN_DOCUMENT);intent.setType("*/*");intent.addCategory(Intent.CATEGORY_OPENABLE);startActivityForResult(intent,request);
    }
    private void importExternalDebug(Uri uri) {
        final MintSession active=session;if(active==null)return;
        android.widget.CheckBox unverified=new android.widget.CheckBox(this);unverified.setText(R.string.ws_debug_accept);
        new com.google.android.material.dialog.MaterialAlertDialogBuilder(this).setTitle(R.string.ws_debug_import_title)
                .setMessage(R.string.ws_debug_import_explanation)
                .setView(unverified).setNegativeButton(android.R.string.cancel,null).setPositiveButton(R.string.ws_import,(dialog,button)->{
                    final boolean allow=unverified.isChecked();mutateProject(()->{java.io.File temporary=null;
                        try{temporary=java.io.File.createTempFile("mint-debug-",".bin",getCacheDir());
                            try(java.io.InputStream input=getContentResolver().openInputStream(uri);java.io.FileOutputStream output=new java.io.FileOutputStream(temporary)) {
                                if(input==null)throw new java.io.IOException(getString(R.string.ws_debug_open_failed));byte[] buffer=new byte[65536];long size=0;int count;
                                while((count=input.read(buffer))!=-1){size+=count;if(size>ProjectArchive.MAX_DEBUG)throw new java.io.IOException(getString(R.string.ws_debug_size));output.write(buffer,0,count);}output.getFD().sync();
                            }
                            active.importDebug(temporary.getAbsolutePath(),allow);
                        }catch(java.io.IOException error){throw new IllegalStateException(error.getMessage(),error);}
                        finally{if(temporary!=null)temporary.delete();}
                    });
                }).show();
    }
    private void showVersionTracking() {
        new com.google.android.material.dialog.MaterialAlertDialogBuilder(this).setTitle(R.string.ws_tracking_title)
                .setItems(new String[]{getString(R.string.ws_tracking_open), getString(R.string.ws_tracking_function_diff), getString(R.string.ws_tracking_confirm_pair), getString(R.string.ws_tracking_confirmed_pairs), getString(R.string.ws_tracking_transfer_preview), getString(R.string.ws_tracking_transfer_apply), getString(R.string.ws_tracking_save_pairs), getString(R.string.ws_tracking_load_pairs)},(d,which) -> {
                    if(which==0) {
                        if(model.rawConfig()!=null)new com.google.android.material.dialog.MaterialAlertDialogBuilder(this).setTitle(R.string.ws_tracking_format)
                                .setMessage(model.rawConfig().machOSlice?getString(R.string.ws_tracking_macho):getString(R.string.ws_tracking_raw))
                                .setPositiveButton(R.string.ws_choose_binary,(a,b)->pickDocument(COMPARISON_REQUEST)).setNegativeButton(android.R.string.cancel,null).show();
                        else pickDocument(COMPARISON_REQUEST);
                    } else if(which==1)showReport(getString(R.string.ws_tracking_semantic_diff),active->active.comparison("diff",0,0,""));
                    else if(which==2)promptFunctionPair();
                    else if(which==3)showReport(getString(R.string.ws_tracking_confirmed_pairs),active->active.comparison("tracking",0,0,""));
                    else if(which==4)previewTransfer(false);
                    else if(which==5)previewTransfer(true);
                    else if(which==6){Intent intent=new Intent(Intent.ACTION_CREATE_DOCUMENT);intent.setType("application/octet-stream");intent.addCategory(Intent.CATEGORY_OPENABLE);intent.putExtra(Intent.EXTRA_TITLE,"mint-version-tracking.minttracking");startActivityForResult(intent,TRACKING_SAVE_REQUEST);}
                    else if(which==7)pickDocument(TRACKING_LOAD_REQUEST);
                }).show();
    }
    private void trackingDocument(Uri document,boolean save) {
        final MintSession active=session;if(active==null)return;busy(true);
        worker.execute(()->{
            java.io.File temporary=new java.io.File(getCacheDir(),"mint-tracking-"+java.util.UUID.randomUUID()+".bin");String result;
            try {
                if(save) {
                    active.comparison("save",0,0,temporary.getAbsolutePath());
                    try(java.io.InputStream input=new java.io.FileInputStream(temporary);java.io.OutputStream output=getContentResolver().openOutputStream(document,"wt")) {
                        if(output==null)throw new java.io.IOException(getString(R.string.ws_tracking_open_destination));
                        byte[] buffer=new byte[8192];int count;while((count=input.read(buffer))!=-1)output.write(buffer,0,count);
                    }
                    result=getString(R.string.ws_tracking_saved);
                } else {
                    try(java.io.InputStream input=getContentResolver().openInputStream(document);java.io.FileOutputStream output=new java.io.FileOutputStream(temporary)) {
                        if(input==null)throw new java.io.IOException(getString(R.string.ws_tracking_open_source));
                        byte[] buffer=new byte[8192];int count;long size=0;while((count=input.read(buffer))!=-1){if((size+=count)>16*1024*1024)throw new java.io.IOException(getString(R.string.ws_tracking_size));output.write(buffer,0,count);}output.getFD().sync();
                    }
                    result=active.comparison("load",0,0,temporary.getAbsolutePath());
                }
            }catch(Exception e){result=getString(save ? R.string.ws_tracking_save_failed : R.string.ws_tracking_load_failed, e.getMessage());}
            finally{if(temporary.exists())temporary.delete();}
            final String body=result;main.post(()->{if(isDestroyed() || active!=session)return;busy(false);displayReport(getString(R.string.ws_tracking_short),body);});
        });
    }
    private void openComparison(Uri uri) {
        final MintSession active=session;if(active==null)return;final RawImportConfig raw=model.rawConfig();busy(true);
        worker.execute(()->{
            String result;try {
                java.io.File input=ProjectStore.importBinary(this,uri,new java.util.concurrent.atomic.AtomicBoolean(false),raw);
                String project=new java.io.File(input.getParentFile(),"program.mint").getAbsolutePath();
                result=raw!=null && raw.machOSlice?active.openComparisonMachO(input.getAbsolutePath(),project):active.openComparison(input.getAbsolutePath(),project,raw!=null);
            }catch(Exception e){result=e.getMessage();}
            final String body=result;main.post(()->{if(isDestroyed() || active!=session)return;busy(false);displayReport(getString(R.string.ws_tracking_comparison_program),body);});
        });
    }
    private void promptFunctionPair() {
        LinearLayout fields=new LinearLayout(this);fields.setOrientation(LinearLayout.VERTICAL);
        EditText source=new EditText(this);source.setHint(R.string.ws_tracking_source_address);source.setText("0x"+Long.toUnsignedString(listingAddress,16));fields.addView(source);
        EditText target=new EditText(this);target.setHint(R.string.ws_tracking_target_address);fields.addView(target);
        new com.google.android.material.dialog.MaterialAlertDialogBuilder(this).setTitle(R.string.ws_tracking_confirm_title)
                .setMessage(R.string.ws_tracking_confirm_details)
                .setView(fields).setNegativeButton(android.R.string.cancel,null).setPositiveButton(R.string.ws_tracking_confirm_button,(d,w)->{
                    try {long from=parseHexAddress(source.getText().toString()),to=parseHexAddress(target.getText().toString());showReport(getString(R.string.ws_tracking_confirmed_pair),active->active.comparison("confirm",from,to,""));}
                    catch(NumberFormatException e){showProjectError(getString(R.string.ws_tracking_bad_addresses));}
                }).show();
    }
    private static long parseHexAddress(String value) {return Long.parseUnsignedLong(value.trim().replaceFirst("^(0x|0X)",""),16);}
    private void previewTransfer(boolean apply) {
        final MintSession active=session;if(active==null)return;busy(true);
        worker.execute(()->{
            String result=null,error=null;try{result=active.comparison("preview",0,0,"");}catch(RuntimeException e){error=e.getMessage();}
            final String body=result,failure=error;main.post(()->{
                if(isDestroyed() || active!=session)return;busy(false);if(failure!=null){showProjectError(failure);return;}
                if(!apply){displayReport(getString(R.string.ws_tracking_transfer_preview_title),body);return;}
                new com.google.android.material.dialog.MaterialAlertDialogBuilder(this).setTitle(R.string.ws_tracking_transfer_confirm)
                        .setMessage(body+"\n"+getString(R.string.ws_tracking_transfer_details))
                        .setNegativeButton(android.R.string.cancel,null).setPositiveButton(R.string.ws_tracking_transfer_button,(d,w)->showReport(getString(R.string.ws_tracking_transfer_result),s->s.comparison("apply",0,0,""))).show();
            });
        });
    }
    private void showDebugger() {
        String[] actions={getString(R.string.advanced_debug_connect_title), getString(R.string.advanced_debug_status), getString(R.string.advanced_debug_attach_action), getString(R.string.advanced_debug_registers), getString(R.string.advanced_debug_read_memory), getString(R.string.advanced_debug_set_break), getString(R.string.advanced_debug_remove_break), getString(R.string.advanced_debug_step), getString(R.string.advanced_debug_continue), getString(R.string.advanced_debug_interrupt), getString(R.string.advanced_debug_wait), getString(R.string.advanced_debug_disconnect), getString(R.string.advanced_debug_threads_select), getString(R.string.advanced_debug_frames), getString(R.string.advanced_debug_modules), getString(R.string.advanced_debug_map), getString(R.string.advanced_debug_jump), getString(R.string.advanced_debug_rsp_layout), getString(R.string.advanced_debug_unmap)};
        new com.google.android.material.dialog.MaterialAlertDialogBuilder(this).setTitle(R.string.ws_debugger)
                .setItems(actions,(d,which)->{
                    if(which==0){promptDebuggerConnection();return;}
                    if(which==12){showDebuggerThreads();return;}
                    if(which==13){showDebuggerFrames();return;}
                    if(which==15){promptDebuggerMapping();return;}
                    if(which==16){runDebuggerAndFollowPc("pc-image");return;}
                    if(which==2){EditText pid=new EditText(this);pid.setHint(getString(R.string.advanced_debug_pid_hint));pid.setInputType(android.text.InputType.TYPE_CLASS_NUMBER);
                        new com.google.android.material.dialog.MaterialAlertDialogBuilder(this).setTitle(getString(R.string.advanced_debug_attach_title))
                                .setMessage(getString(R.string.advanced_debug_attach_help))
                                .setView(pid).setNegativeButton(android.R.string.cancel,null).setPositiveButton(getString(R.string.advanced_debug_attach),(a,b)->{
                                    try{long id=Long.parseLong(pid.getText().toString().trim());if(id<=0)throw new NumberFormatException();showReport(getString(R.string.advanced_debug_attach_report),s->s.debugger("attach",0,id));}
                                    catch(NumberFormatException e){showProjectError(getString(R.string.advanced_debug_bad_pid));}
                                }).show();return;
                    }
                    String[] ops={"","status","","registers","memory-image","break-image","unbreak-image","step","continue","interrupt","wait","disconnect","threads","stack","modules","map-image","pc-image","layout","unmap"};
                    final long at=listingAddress;
                    if(which>=5 && which<=9)new com.google.android.material.dialog.MaterialAlertDialogBuilder(this).setTitle(actions[which])
                            .setMessage(getString(R.string.advanced_debug_confirm))
                            .setNegativeButton(android.R.string.cancel,null).setPositiveButton(getString(R.string.advanced_debug_execute),(a,b)->{if(which==7 || which==9)runDebuggerAndFollowPc(ops[which]);else showReport(getString(R.string.advanced_debug_report),s->s.debugger(ops[which],at,0));}).show();
                    else if(which==10)runDebuggerAndFollowPc("wait");
                    else showReport(getString(R.string.advanced_debug_report),s->s.debugger(ops[which],at,which==4?256:0));
                }).show();
    }
    private void promptDebuggerMapping() {
        EditText runtime=new EditText(this);runtime.setHint(getString(R.string.advanced_debug_runtime_base));
        new com.google.android.material.dialog.MaterialAlertDialogBuilder(this).setTitle(getString(R.string.advanced_debug_aslr_title))
                .setMessage(getString(R.string.advanced_debug_aslr_help))
                .setView(runtime).setNegativeButton(android.R.string.cancel,null).setPositiveButton(getString(R.string.advanced_debug_map_apply),(d,w)->{
                    try{String text=runtime.getText().toString().trim();if(text.startsWith("0x"))text=text.substring(2);long base=Long.parseUnsignedLong(text,16);showReport(getString(R.string.advanced_debug_map_report),s->s.debugger("map-image",base,0));}
                    catch(NumberFormatException e){showProjectError(getString(R.string.advanced_debug_bad_base));}
                }).show();
    }
    private void showDebuggerThreads() {
        final MintSession active=session;if(active==null)return;busy(true);
        worker.execute(()->{String result;try{result=active.debugger("threads",0,0);}catch(Exception e){result=e.getMessage();}final String body=result;
            main.post(()->{if(isDestroyed() || active!=session)return;busy(false);
                java.util.ArrayList<String> rows=new java.util.ArrayList<>();java.util.ArrayList<Long> ids=new java.util.ArrayList<>(),processes=new java.util.ArrayList<>();
                for(String line:body.split("\\n")){int tab=line.indexOf('\t');if(tab<1)continue;try{
                    DebuggerThreadId identity=DebuggerThreadId.parse(line.substring(0,tab));
                    ids.add(identity.thread);processes.add(identity.process);rows.add(line);
                }catch(NumberFormatException ignored){}}
                if(rows.isEmpty()){displayReport(getString(R.string.advanced_debug_threads),body);return;}
                new com.google.android.material.dialog.MaterialAlertDialogBuilder(this).setTitle(getString(R.string.advanced_debug_select_thread)).setItems(rows.toArray(new String[0]),(d,index)->showReport(getString(R.string.advanced_debug_selected_thread),s->s.debugger("thread",processes.get(index),ids.get(index)))).setNegativeButton(getString(R.string.advanced_close),null).show();
            });});
    }
    private void showDebuggerFrames() {
        final MintSession active=session;if(active==null)return;busy(true);
        worker.execute(()->{String result;try{result=active.debugger("stack",0,64);}catch(Exception error){result=error.getMessage();}final String body=result;
            main.post(()->{if(isDestroyed() || active!=session)return;busy(false);java.util.ArrayList<String> labels=new java.util.ArrayList<>();java.util.ArrayList<Long> addresses=new java.util.ArrayList<>();
                for(String line:body.split("\n")){String[] fields=line.split("\t",-1);if(fields.length<4 || !fields[2].startsWith("image 0x"))continue;
                    try{addresses.add(Long.parseUnsignedLong(fields[2].substring(8),16));labels.add(fields[3]+" — "+fields[2]+(fields.length>4?" — "+fields[4]:""));}catch(NumberFormatException ignored){}}
                if(labels.isEmpty()){displayReport(getString(R.string.advanced_debug_unmapped_frames),body);return;}
                new com.google.android.material.dialog.MaterialAlertDialogBuilder(this).setTitle(getString(R.string.advanced_debug_mapped_frames)).setItems(labels.toArray(new String[0]),(d,index)->jumpTo(addresses.get(index))).setNeutralButton(getString(R.string.advanced_debug_full_report),(d,w)->displayReport(getString(R.string.advanced_debug_frames),body)).setNegativeButton(getString(R.string.advanced_close),null).show();
            });});
    }
    private void runDebuggerAndFollowPc(String operation) {
        final MintSession active=session;if(active==null)return;busy(true);
        worker.execute(()->{String result,pc=null;try{result=active.debugger(operation,0,0);try{pc=operation.equals("pc-image")?result:active.debugger("pc-image",0,0);}catch(Exception e){result+="\n" + getString(R.string.advanced_debug_pc_not_synced, e.getMessage());}}catch(Exception e){result=e.getMessage();}
            final String body=result,position=pc;main.post(()->{if(isDestroyed() || active!=session)return;busy(false);
                if(position!=null){int tab=position.indexOf('\t');if(tab>2 && position.startsWith("0x"))try{jumpTo(Long.parseUnsignedLong(position.substring(2,tab),16));}catch(NumberFormatException ignored){}}
                displayReport(getString(R.string.advanced_debug_report),body);
            });});
    }
    private void promptDebuggerConnection() {
        LinearLayout fields=new LinearLayout(this);fields.setOrientation(LinearLayout.VERTICAL);
        android.widget.Spinner backend=new android.widget.Spinner(this);backend.setAdapter(new android.widget.ArrayAdapter<>(this,android.R.layout.simple_spinner_dropdown_item,new String[]{getString(R.string.advanced_debug_rsp_backend), getString(R.string.advanced_debug_dap_backend)}));fields.addView(backend);
        EditText host=new EditText(this);host.setHint(getString(R.string.advanced_debug_host_hint));host.setText("127.0.0.1");fields.addView(host);
        EditText port=new EditText(this);port.setHint(getString(R.string.advanced_debug_port_hint));port.setInputType(android.text.InputType.TYPE_CLASS_NUMBER);fields.addView(port);
        android.widget.CheckBox remote=new android.widget.CheckBox(this);remote.setText(getString(R.string.advanced_debug_remote_enable));fields.addView(remote);
        new com.google.android.material.dialog.MaterialAlertDialogBuilder(this).setTitle(getString(R.string.advanced_debug_connect_external))
                .setMessage(getString(R.string.advanced_debug_connect_help))
                .setView(fields).setNegativeButton(android.R.string.cancel,null).setPositiveButton(getString(R.string.advanced_debug_connect),(d,w)->{
                    try{int number=Integer.parseInt(port.getText().toString().trim());String address=host.getText().toString().trim();boolean dap=backend.getSelectedItemPosition()==1,allow=remote.isChecked();showReport(getString(R.string.advanced_debug_connection_report),s->s.connectDebugger(address,number,dap,allow));}
                    catch(NumberFormatException e){showProjectError(getString(R.string.advanced_debug_bad_port));}
                }).show();
    }
    private void showNativePlugins() {
        new com.google.android.material.dialog.MaterialAlertDialogBuilder(this).setTitle(R.string.ws_plugins)
                .setItems(new String[]{getString(R.string.ws_plugin_load_trusted), getString(R.string.ws_plugin_list_commands), getString(R.string.ws_plugin_run_command), getString(R.string.ws_plugin_run_isolated)},(d,which)->{
                    if(which==0)pickDocument(PLUGIN_REQUEST);
                    else if(which==1)showReport(getString(R.string.ws_plugin_commands),MintSession::pluginCommands);
                    else if(which==3)pickDocument(SANDBOX_PLUGIN_REQUEST);
                    else {
                        LinearLayout fields=new LinearLayout(this);fields.setOrientation(LinearLayout.VERTICAL);
                        EditText command=new EditText(this);command.setHint("plugin-id/command-id");fields.addView(command);
                        EditText arguments=new EditText(this);arguments.setHint(R.string.ws_plugin_arguments);fields.addView(arguments);
                        android.widget.CheckBox edits=new android.widget.CheckBox(this);edits.setText(R.string.ws_plugin_allow_edits);fields.addView(edits);
                        new com.google.android.material.dialog.MaterialAlertDialogBuilder(this).setTitle(R.string.ws_plugin_run_trusted)
                                .setMessage(R.string.ws_plugin_trusted_explanation)
                                .setView(fields).setNegativeButton(android.R.string.cancel,null).setPositiveButton(R.string.ws_run,(a,b)->{
                                    String id=command.getText().toString(),args=arguments.getText().toString();boolean allow=edits.isChecked();
                                    if(allow){++viewGeneration;pendingAddress=selected==null?-1:selected.entry;}
                                    showReport(getString(R.string.ws_plugin_output),s->s.runPlugin(id,args,allow));
                                    if(allow){openFunctions.clear();loadFunctions();}
                                }).show();
                    }
                }).show();
    }
    private void openIsolatedPlugin(Uri uri) {
        final MintSession active=session;final java.io.File binary=model.binaryFile();final RawImportConfig config=model.rawConfig();
        if(active==null || binary==null)return;
        if(android.os.Build.VERSION.SDK_INT<29){showProjectError(getString(R.string.ws_plugin_requires_android));return;}
        if(sandboxPlugin!=null || sandboxPreparing){showProjectError(getString(R.string.ws_plugin_running));return;}
        LinearLayout fields=new LinearLayout(this);fields.setOrientation(LinearLayout.VERTICAL);
        EditText command=new EditText(this);command.setHint("plugin-id/command-id");fields.addView(command);
        EditText arguments=new EditText(this);arguments.setHint(R.string.ws_plugin_arguments);fields.addView(arguments);
        new com.google.android.material.dialog.MaterialAlertDialogBuilder(this).setTitle(R.string.ws_plugin_isolated_title)
                .setMessage(R.string.ws_plugin_isolated_explanation)
                .setView(fields).setNegativeButton(android.R.string.cancel,null).setPositiveButton(R.string.ws_run,(d,w)->{
                    if(sandboxPlugin!=null || sandboxPreparing)return;
                    final String id=command.getText().toString(),args=arguments.getText().toString();
                    if(id.isEmpty() || id.length()>160 || args.length()>4096){showProjectError(getString(R.string.ws_plugin_bad_args));return;}
                    sandboxPreparing=true;sandboxCopyCancelled=new java.util.concurrent.atomic.AtomicBoolean();
                    final java.util.concurrent.atomic.AtomicBoolean cancelled=sandboxCopyCancelled;busy(true);
                    worker.execute(()->{
                        java.io.File file=null;String failure=null;
                        try {
                            java.io.File root=new java.io.File(getCodeCacheDir(),"mint-isolated-plugins");
                            if(!root.isDirectory() && !root.mkdirs())throw new java.io.IOException(getString(R.string.ws_plugin_copy_directory));
                            file=java.io.File.createTempFile("plugin-",".so",root);
                            try(java.io.InputStream input=getContentResolver().openInputStream(uri);java.io.FileOutputStream output=new java.io.FileOutputStream(file)) {
                                if(input==null || !file.setReadOnly())throw new java.io.IOException(getString(R.string.ws_plugin_copy_protection));
                                byte[] buffer=new byte[65536];int n;long size=0;
                                while((n=input.read(buffer))!=-1){if(cancelled.get())throw new java.io.IOException(getString(R.string.ws_plugin_cancelled));if((size+=n)>16*1024*1024)throw new java.io.IOException(getString(R.string.ws_plugin_size));output.write(buffer,0,n);}
                                if(size==0)throw new java.io.IOException(getString(R.string.ws_plugin_empty));output.getFD().sync();
                            }
                        }catch(Exception error){failure=error.getMessage();}
                        final java.io.File copied=file;final String problem=failure;
                        main.post(()->{
                            sandboxPreparing=false;
                            if(isDestroyed() || active!=session || cancelled.get() || problem!=null){
                                if(copied!=null)copied.delete();
                                if(!isDestroyed() && active==session){busy(false);displayReport(getString(R.string.ws_plugin_isolated_report),cancelled.get()?getString(R.string.ws_plugin_cancelled):problem);}
                                return;
                            }
                            try {
                                sandboxPlugin=new com.ccs.mint.plugin.SandboxPluginClient(this,binary,copied,id,args,
                                        config==null?"":config.architecture,config==null?0:config.baseAddress,config==null?0:config.entryAddress,config!=null&&config.machOSlice,60000,
                                        (success,output,uid,pid)->{sandboxPlugin=null;if(!isDestroyed() && active==session){busy(false);displayReport(getString(R.string.ws_plugin_isolated_report),output);}});
                                sandboxPlugin.start();
                            }catch(Exception error){sandboxPlugin=null;copied.delete();busy(false);showProjectError(error.getMessage());}
                        });
                    });
                }).show();
    }

    private void openNativePlugin(Uri uri) {
        final MintSession active=session;if(active==null)return;
        new com.google.android.material.dialog.MaterialAlertDialogBuilder(this).setTitle(R.string.ws_plugin_trust_title)
                .setMessage(R.string.ws_plugin_trust_details)
                .setNegativeButton(android.R.string.cancel,null).setPositiveButton(R.string.ws_plugin_trust_button,(d,w)->{
                    busy(true);worker.execute(()->{
                        java.io.File file=null;String result;
                        try {
                            java.io.File root=new java.io.File(getCodeCacheDir(),"mint-plugins");if(!root.isDirectory() && !root.mkdirs())throw new java.io.IOException(getString(R.string.ws_plugin_directory));
                            file=java.io.File.createTempFile("plugin-",".so",root);
                            // Set read-only before loading executable code on modern Android.
                            try(java.io.InputStream input=getContentResolver().openInputStream(uri);java.io.FileOutputStream output=new java.io.FileOutputStream(file)) {
                                if(input==null)throw new java.io.IOException(getString(R.string.ws_plugin_open_failed));if(!file.setReadOnly())throw new java.io.IOException(getString(R.string.ws_plugin_protect_failed));
                                byte[] buffer=new byte[65536];int n;long size=0;
                                while((n=input.read(buffer))!=-1){if((size+=n)>16*1024*1024)throw new java.io.IOException(getString(R.string.ws_plugin_size));output.write(buffer,0,n);}output.getFD().sync();
                            }
                            result=active.loadPlugin(file.getAbsolutePath(),true);
                        }catch(Exception e){if(file!=null && file.exists())file.delete();result=e.getMessage();}
                        final String body=result;main.post(()->{if(isDestroyed() || active!=session)return;busy(false);displayReport(getString(R.string.ws_plugin_load_report),body);});
                    });
                }).show();
    }

    private void showProjectError(String message) {
        new com.google.android.material.dialog.MaterialAlertDialogBuilder(this).setTitle(R.string.ws_project_title).setMessage(message)
                .setPositiveButton(android.R.string.ok,null).show();
    }

    private void showLocalVariables() {
        final MintSession active=session;if(active==null)return;
        final long function=selected==null?listingAddress:selected.entry;busy(true);
        worker.execute(() -> {
            String result;try{result=active.locals(function);}catch(RuntimeException error){result=error.getMessage();}
            final String report=result;
            main.post(() -> {
                if(isDestroyed() || active!=session)return;busy(false);
                List<String[]> rows=new ArrayList<>();List<String> labels=new ArrayList<>();
                if(report!=null)for(String line:report.split("\n")) {
                    String[] fields=line.split("\t",-1);
                    if(fields.length!=5 || fields[0].equals("identity"))continue;
                    rows.add(fields);labels.add(getString(R.string.ws_local_row, fields[1], fields[3], fields[4], fields[2].isEmpty() ? "" : " : " + fields[2]));
                }
                if(rows.isEmpty()){displayReport(getString(R.string.ws_locals_report),report);return;}
                new com.google.android.material.dialog.MaterialAlertDialogBuilder(this).setTitle(R.string.ws_locals_title)
                        .setItems(labels.toArray(new String[0]),(dialog,which) -> {
                            String[] row=rows.get(which);LinearLayout fields=new LinearLayout(this);fields.setOrientation(LinearLayout.VERTICAL);
                            EditText name=new EditText(this),type=new EditText(this);
                            name.setHint(R.string.ws_local_name);name.setText(row[1]);
                            type.setHint(R.string.ws_local_type);type.setText(row[2]);fields.addView(name);fields.addView(type);
                            new com.google.android.material.dialog.MaterialAlertDialogBuilder(this).setTitle(getString(R.string.ws_local_edit, row[1]))
                                    .setMessage(R.string.ws_locals_help)
                                    .setView(fields).setNegativeButton(android.R.string.cancel,null)
                                    .setNeutralButton(R.string.ws_local_remove,(d,w)->mutateProject(()->active.editLocal(function,row[0],"","")))
                                    .setPositiveButton(R.string.ws_save,(d,w)->{String edited=name.getText().toString().trim(),declared=type.getText().toString().trim();mutateProject(()->active.editLocal(function,row[0],edited,declared));}).show();
                        }).setNegativeButton(R.string.ws_close,null).show();
            });
        });
    }

    private void promptAssembly(long address) {
        final MintSession active=session;if(active==null)return;
        EditText input=new EditText(this);input.setTypeface(Typeface.MONOSPACE);input.setMinLines(4);input.setHint("nop\nret");
        patchDialogCode.attachAssemblyHighlighting(input);
        new com.google.android.material.dialog.MaterialAlertDialogBuilder(this)
                .setTitle(getString(R.string.patch_assemble_at, address))
                .setMessage(R.string.patch_assemble_help)
                .setView(input).setNegativeButton(android.R.string.cancel,null)
                .setPositiveButton(R.string.patch_preview,(d,w) -> {
                    final String source=input.getText().toString();busy(true);
                    worker.execute(() -> {
                        String bytes=null,original="",error=null;
                        try {
                            bytes=active.assemble(address,source,false);
                            original=active.patchReviewBytes(active.canonicalAddress(address), PatchComparison.byteCount(bytes));
                        } catch(RuntimeException e) {
                            error=e.getMessage();
                        }
                        final String encoded=bytes,failure=error;
                        final String before = original;
                        main.post(() -> {
                            if(isDestroyed() || active!=session)return;busy(false);
                            if(failure!=null){showProjectError(failure);return;}
                            new com.google.android.material.dialog.MaterialAlertDialogBuilder(this)
                                    .setTitle(R.string.patch_confirm_title)
                                    .setView(patchDialogCode.scrollView(
                                            patchDialogCode.preview(address, source, before, encoded)))
                                    .setNegativeButton(android.R.string.cancel,null)
                                    .setPositiveButton(R.string.patch_apply,(confirm,button) ->
                                            applyPatchWithComparison(active, address, encoded, true, () -> {
                                                if (!encoded.equals(active.assemble(address, source, false)))
                                                    throw new IllegalStateException(getString(R.string.patch_encoding_changed));
                                                active.assemble(address, source, true);
                                            })).show();
                        });
                    });
                }).show();
    }

    private void promptScript(String source) {
        final MintSession active=session;if(active==null)return;
        LinearLayout fields=new LinearLayout(this);fields.setOrientation(LinearLayout.VERTICAL);
        EditText input=new EditText(this);input.setTypeface(Typeface.MONOSPACE);input.setText(source);input.setMinLines(5);input.setMaxLines(14);fields.addView(input);
        android.widget.CheckBox edits=new android.widget.CheckBox(this);edits.setText(getString(R.string.advanced_script_allow_edits));fields.addView(edits);
        new com.google.android.material.dialog.MaterialAlertDialogBuilder(this).setTitle(getString(R.string.advanced_script_title))
                .setMessage(getString(R.string.advanced_script_help))
                .setView(fields).setNegativeButton(android.R.string.cancel,null).setPositiveButton(getString(R.string.advanced_run),(dialog,which) -> {
                    final String text=input.getText().toString();final boolean allow=edits.isChecked();++viewGeneration;busy(true);
                    worker.execute(() -> {
                        String result;try{result=active.runScript(text,allow);}catch(RuntimeException e){result=e.getMessage();}
                        final String output=result;
                        main.post(() -> {
                            if(isDestroyed() || active!=session)return;busy(false);
                            displayReport(getString(R.string.advanced_script_output),output);
                            if(allow){pendingAddress=selected==null?-1:selected.entry;openFunctions.clear();loadFunctions();}
                        });
                    });
                }).show();
    }

    private void openScript(Uri uri) {
        final MintSession active=session;if(active==null)return;busy(true);
        worker.execute(() -> {
            String source=null,error=null;
            try(java.io.InputStream input=getContentResolver().openInputStream(uri);java.io.ByteArrayOutputStream bytes=new java.io.ByteArrayOutputStream()) {
                if(input==null)throw new java.io.IOException(getString(R.string.advanced_script_open_error));
                byte[] buffer=new byte[4096];int count;
                while((count=input.read(buffer))!=-1){if(bytes.size()+count>256*1024)throw new java.io.IOException(getString(R.string.advanced_script_size_error));bytes.write(buffer,0,count);}
                source=new String(bytes.toByteArray(),java.nio.charset.StandardCharsets.UTF_8);
            }catch(Exception e){error=e.getMessage();}
            final String text=source,failure=error;
            main.post(() -> {if(isDestroyed() || active!=session)return;busy(false);if(failure!=null)showProjectError(failure);else promptScript(text);});
        });
    }

    private void editAddress(long address) {
        final MintSession active = session;
        if (active == null) return;
        String[] kinds = {"name","comment","bookmark","data","prototype","function","patch"};
        int[] actions = {R.string.address_rename_symbol, R.string.address_comment,
                R.string.address_bookmark, R.string.address_define_data,
                R.string.address_prototype, R.string.address_define_function,
                R.string.address_patch_hex, R.string.address_references,
                R.string.address_show_pseudo_c, R.string.assemble_patch_here};
        String[] labels = new String[actions.length];
        for (int index = 0; index < actions.length; index++) labels[index] = getString(actions[index]);
        new com.google.android.material.dialog.MaterialAlertDialogBuilder(this).setTitle(String.format(Locale.US,"0x%x",address))
                .setItems(labels,(dialog,which) -> {
                    if (which == 7) { showReferences(address); return; }
                    if (which == 8) { showAddressInPseudoC(active, address); return; }
                    if (which == 9) { promptAssembly(address); return; }
                    String kind = kinds[which];
                    worker.execute(() -> {
                        String value;
                        try { value = active.annotation(address,kind); }
                        catch (RuntimeException e) { main.post(() -> showProjectError(e.getMessage())); return; }
                        final String initial = value;
                        main.post(() -> {
                            if (isDestroyed() || active != session) return;
                            EditText input = new EditText(this); input.setText(initial);
                            input.setHint(R.string.address_empty_override);
                            if ("patch".equals(kind)) input.setTypeface(Typeface.MONOSPACE);
                            new com.google.android.material.dialog.MaterialAlertDialogBuilder(this).setTitle(labels[which]).setView(input)
                                    .setPositiveButton(R.string.address_save,(d,w) -> {
                                        String edited = input.getText().toString();
                                        if ("patch".equals(kind))
                                            applyPatchWithComparison(active, address, edited, false,
                                                    () -> active.edit(address,kind,edited));
                                        else mutateProject(() -> active.edit(address,kind,edited));
                                    }).setNegativeButton(android.R.string.cancel,null).show();
                        });
                    });
                }).show();
    }

    private void mutateProject(Runnable operation) {
        mutateProject(operation, null);
    }

    private void mutateProject(Runnable operation, @Nullable java.util.function.Supplier<PatchReview> comparison) {
        ++viewGeneration;
        reverseListing = null;
        sourceListing = null;
        busy(true);
        final MintSession active = session;
        worker.execute(() -> {
            String failure = null;
            PatchReview report = null;
            try {
                if (active == null || active != model.session()) return;
                if (comparison == null) operation.run();
                else report = comparison.get();
            }
            catch (RuntimeException e) { failure = e.getMessage(); }
            final String error = failure;
            final PatchReview completedReport = report;
            main.post(() -> {
                if (isDestroyed() || active != session) return;
                busy(false);
                if (error != null) showProjectError(error);
                else {
                    pendingAddress = selected == null ? -1 : selected.entry;
                    openFunctions.clear();
                    loadFunctions();
                    if (completedReport != null) showPatchReview(completedReport);
                }
            });
        });
    }

    static final class PatchReview {
        final MintSession session;
        final long revision;
        final CharSequence report;
        final String staleMessage;
        final boolean canUndo, canExport;

        PatchReview(MintSession session, long revision, CharSequence report, boolean canUndo, boolean canExport,
                    String staleMessage) {
            this.session = session;
            this.revision = revision;
            this.report = report;
            this.canUndo = canUndo;
            this.canExport = canExport;
            this.staleMessage = staleMessage;
        }

        void requireCurrent(MintSession active) {
            if (active != session || active.programRevision() != revision)
                throw new IllegalStateException(staleMessage);
        }
    }

    private void applyPatchWithComparison(MintSession active, long address, String replacement,
                                          boolean assembly, Runnable patch) {
        if (active != session) {
            showProjectError(getString(R.string.patch_workspace_changed));
            return;
        }
        mutateProject(patch, () -> {
            final long patchAddress = assembly ? active.canonicalAddress(address) : address;
            final long[] function = active.functionRangeAt(patchAddress);
            final long originalRevision = active.programRevision();
            final int length = Math.max(PatchComparison.byteCount(replacement),
                    PatchComparison.byteCount(active.annotation(patchAddress, "patch")));
            final String oldBytes = active.patchReviewBytes(patchAddress, length);
            final String[] before = function == null ? new String[2] : patchSnapshot(active, function);
            patch.run();
            final long revision = active.programRevision();
            final String newBytes = active.patchReviewBytes(patchAddress, length);
            final String[] after = function == null ? new String[2] : patchSnapshot(active, function);
            final boolean undoable = revision == originalRevision + 1;
            final CharSequence report = patchDialogCode.comparison(patchAddress, oldBytes, newBytes,
                    function, before, after);
            return new PatchReview(active, revision, report, undoable,
                    undoable && !oldBytes.isEmpty() && !newBytes.isEmpty(),
                    getString(R.string.patch_review_stale));
        });
    }

    private void showPatchReview(PatchReview review) {
        var dialog = new com.google.android.material.dialog.MaterialAlertDialogBuilder(this)
                .setTitle(R.string.patch_comparison_title).setView(patchDialogCode.scrollView(review.report))
                .setNegativeButton(R.string.patch_close, null);
        if (review.canUndo) dialog.setNeutralButton(R.string.patch_undo, (d, which) -> mutateProject(() -> {
            review.requireCurrent(model.session());
            review.session.undoEdit(false);
        }));
        if (review.canExport) dialog.setPositiveButton(R.string.patch_export_copy, (d, which) -> {
            Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT);
            intent.addCategory(Intent.CATEGORY_OPENABLE);
            intent.setType("application/octet-stream");
            intent.putExtra(Intent.EXTRA_TITLE, "mint-patched.bin");
            model.pendingReviewedExport = review;
            try {
                startActivityForResult(intent, REVIEWED_PATCH_EXPORT_REQUEST);
            } catch (android.content.ActivityNotFoundException e) {
                model.pendingReviewedExport = null;
                showProjectError(getString(R.string.patch_no_picker));
            }
        });
        dialog.show();
    }

    private String[] patchSnapshot(MintSession active, long[] function) {
        final String listing;
        try {
            StringBuilder rows = new StringBuilder();
            long[] addresses = new long[PAGE];
            int[] sizes = new int[PAGE], flows = new int[PAGE];
            long[] targets = new long[PAGE];
            String[] lines = new String[PAGE];
            long cursor = function[1];
            long end = function[2];
            boolean complete = false;
            for (int page = 0; page < 16 && !complete; ++page) {
                int count = active.listing(cursor, PAGE, addresses, sizes, flows, targets, lines, null);
                for (int i = 0; i < count; ++i) {
                    if (Long.compareUnsigned(addresses[i], end) >= 0) {
                        complete = true;
                        break;
                    }
                    rows.append(Long.toUnsignedString(addresses[i], 16)).append("  ").append(lines[i]).append('\n');
                    cursor = addresses[i] + Math.max(1, sizes[i]);
                }
                complete |= count < PAGE || Long.compareUnsigned(cursor, end) >= 0;
            }
            listing = complete ? rows.toString() : null;
        } catch (RuntimeException e) {
            return new String[]{null, null};
        }
        try {
            return new String[]{listing, active.decompileView(function[0])[0]};
        } catch (RuntimeException e) {
            return new String[]{listing, null};
        }
    }

    private void promptSearch() {
        EditText input = new EditText(this);
        input.setHint(R.string.ws_search_hint);
        new com.google.android.material.dialog.MaterialAlertDialogBuilder(this).setTitle(R.string.ws_search_title).setView(input)
                .setPositiveButton(R.string.ws_search_button,(dialog,which) -> {
                    String query = input.getText().toString();
                    showAddressResults(getString(R.string.ws_search_button),active -> active.search(query));
                }).setNegativeButton(android.R.string.cancel,null).show();
    }

    private CharSequence linkedCode(CharSequence source) {
        SpannableString result=new SpannableString(source);
        java.util.Map<String,Long> names=new java.util.HashMap<>();
        for(FunctionRow function:functions)if(function.name!=null && function.name.matches("[A-Za-z_][A-Za-z0-9_]*"))names.put(function.name,function.entry);
        java.util.regex.Matcher identifiers=java.util.regex.Pattern.compile("\\b[A-Za-z_][A-Za-z0-9_]*\\b").matcher(source);
        while(identifiers.find()) {
            final Long target=names.get(identifiers.group());
            if(target!=null)result.setSpan(new ClickableSpan(){@Override public void onClick(@NonNull View widget){jumpTo(target);}},identifiers.start(),identifiers.end(),android.text.Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
        }
        java.util.regex.Matcher matcher=java.util.regex.Pattern.compile("\\b0x[0-9a-fA-F]+\\b").matcher(source);
        while(matcher.find()) {
            try {
                final long target=Long.parseUnsignedLong(matcher.group().substring(2),16);
                result.setSpan(new ClickableSpan(){@Override public void onClick(@NonNull View widget){jumpTo(target);}},matcher.start(),matcher.end(),android.text.Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
            }catch(NumberFormatException ignored){}
        }
        return result;
    }

    private CharSequence linkedSourceRanges(CharSequence code, String anchors, long entry) {
        if (anchors.isEmpty()) return code;
        final android.text.SpannableStringBuilder linked = new android.text.SpannableStringBuilder(code);
        final String plain = code.toString();
        int line = 0;
        int offset = 0;
        for (String row : anchors.split("\n")) {
            final String[] fields = row.split(" ");
            if (fields.length != 4) continue;
            final int first = Integer.parseInt(fields[0]);
            final int last = Integer.parseInt(fields[1]);
            final long start = Long.parseUnsignedLong(fields[2], 16);
            final long end = Long.parseUnsignedLong(fields[3], 16);
            if (first < line) continue;
            while (line <= last && offset < plain.length()) {
                final int newline = plain.indexOf('\n', offset);
                final int lineEnd = newline == -1 ? plain.length() : newline;
                if (line >= first && offset < lineEnd && !plain.substring(offset, lineEnd).trim().isEmpty()) {
                    // Preserve existing call/constant links. The rest of the
                    // statement opens the machine range that contributed to it.
                    int cursor = offset;
                    while (cursor < lineEnd) {
                        final int next = linked.nextSpanTransition(cursor, lineEnd, ClickableSpan.class);
                        if (linked.getSpans(cursor, next, ClickableSpan.class).length == 0) {
                            linked.setSpan(new ClickableSpan() {
                                @Override public void onClick(@NonNull View widget) {
                                    if (pane != Pane.C || selected == null || selected.entry != entry) return;
                                    sourceListing = new SourceListing(entry, listingAddress, start, end,
                                            ((View) text.getParent()).getScrollX(), textScroll.getScrollY());
                                    selectPane(Pane.DISASM);
                                }

                                @Override public void updateDrawState(@NonNull android.text.TextPaint paint) {
                                    // Keep syntax colours and existing symbol-link emphasis.
                                }
                            }, cursor, next, android.text.Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
                        }
                        cursor = next;
                    }
                }
                offset = lineEnd + 1;
                ++line;
            }
        }
        return linked;
    }

    private void revealPseudoCRanges(long address, String anchors, long generation) {
        CharSequence rendered = text.getText();
        java.util.BitSet lines = new java.util.BitSet();
        for (String row : anchors.split("\n")) {
            String[] fields = row.split(" ");
            if (fields.length != 4) continue;
            int first = Integer.parseInt(fields[0]);
            int last = Integer.parseInt(fields[1]);
            long from = Long.parseUnsignedLong(fields[2], 16);
            long to = Long.parseUnsignedLong(fields[3], 16);
            if (Long.compareUnsigned(address, from) >= 0 && Long.compareUnsigned(address, to) < 0)
                lines.set(first, last + 1);
        }
        int first = lines.nextSetBit(0);
        if (first < 0) {
            android.widget.Toast.makeText(this, getString(R.string.ws_pseudo_no_mapping),
                    android.widget.Toast.LENGTH_SHORT).show();
            return;
        }
        SpannableString marked = new SpannableString(rendered);
        String source = rendered.toString();
        int firstOffset = -1;
        for (int line = 0, start = 0; start < source.length(); ++line) {
            int newline = source.indexOf('\n', start);
            int end = newline < 0 ? source.length() : newline;
            if (lines.get(line)) {
                if (firstOffset < 0) firstOffset = start;
                if (start < end) marked.setSpan(new android.text.style.BackgroundColorSpan(
                        (dimColour & 0x00ffffff) | 0x33000000), start, end, android.text.Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
            }
            start = end + 1;
        }
        if (firstOffset < 0) return;
        text.setText(marked);
        final int target = firstOffset;
        text.getViewTreeObserver().addOnPreDrawListener(new android.view.ViewTreeObserver.OnPreDrawListener() {
            @Override public boolean onPreDraw() {
                text.getViewTreeObserver().removeOnPreDrawListener(this);
                if (generation == viewGeneration && text.getLayout() != null) {
                    int visualLine = text.getLayout().getLineForOffset(target);
                    textScroll.scrollTo(0, text.getLayout().getLineTop(visualLine));
                }
                return true;
            }
        });
        int last = lines.length();
        String label = first + 1 == last
                ? getString(R.string.ws_pseudo_line, last)
                : getString(R.string.ws_pseudo_lines, first + 1, last);
        android.widget.Toast.makeText(this, label, android.widget.Toast.LENGTH_SHORT).show();
    }

    private void showAddressInPseudoC(MintSession active, long address) {
        final long generation = viewGeneration;
        final RecyclerView.LayoutManager layout = list.getLayoutManager();
        final ListingOrigin origin = pane == Pane.DISASM
                ? new ListingOrigin(selected, listingAddress, sourceListing,
                        layout == null ? null : layout.onSaveInstanceState())
                : null;
        worker.execute(() -> {
            final long[] function;
            try { function = active.functionRangeAt(address); }
            catch (RuntimeException e) {
                main.post(() -> {
                    if (!isDestroyed() && active == session && generation == viewGeneration)
                        showProjectError(getString(R.string.ws_pseudo_locate_error, e.getMessage()));
                });
                return;
            }
            main.post(() -> {
                if (isDestroyed() || active != session || generation != viewGeneration) return;
                FunctionRow row = null;
                if (function != null) {
                    for (FunctionRow candidate : functions)
                        if (candidate.entry == function[0]) { row = candidate; break; }
                }
                if (row == null) {
                    showProjectError(getString(R.string.ws_pseudo_no_function));
                    return;
                }
                reverseListing = origin;
                pseudoCAnchor = address;
                selected = row;
                listingAddress = address;
                pendingAddress = row.entry;
                if (!openFunctions.contains(row)) openFunctions.add(row);
                model.rememberSelection(row.entry, listingAddress);
                updateSelectionChip();
                selectPane(Pane.C);
            });
        });
    }

    private void showTypeManager() {
        final MintSession active=session;if(active==null)return;
        new com.google.android.material.dialog.MaterialAlertDialogBuilder(this).setTitle(R.string.ws_type_manager)
                .setItems(new String[]{getString(R.string.advanced_types_view), getString(R.string.advanced_types_add), getString(R.string.advanced_types_remove), getString(R.string.advanced_types_header), getString(R.string.advanced_types_import), getString(R.string.advanced_types_signatures)},(d,which) -> {
                    if(which==0){showReport(getString(R.string.advanced_types_report),MintSession::types);return;}
                    if(which==3){showReport(getString(R.string.advanced_types_header_report),MintSession::typesCHeader);return;}
                    if(which==4){pickDocument(LIBRARY_REQUEST);return;}
                    if(which==5){showReport(getString(R.string.advanced_types_signature_report),MintSession::signatureLibrary);return;}
                    EditText input=new EditText(this);
                    input.setHint(which==1?"Packet=struct{length:u32;bytes:u8[16];next:Packet*}":getString(R.string.advanced_types_name));
                    new com.google.android.material.dialog.MaterialAlertDialogBuilder(this).setTitle(which==1?getString(R.string.advanced_types_define):getString(R.string.advanced_types_remove_title)).setView(input)
                            .setPositiveButton(getString(R.string.advanced_save),(dialog,w) -> {String declaration=input.getText().toString();mutateProject(() -> {if(which==1)active.defineType(declaration);else active.eraseType(declaration);});})
                            .setNegativeButton(android.R.string.cancel,null).show();
                }).show();
    }

    private void openLibrary(Uri uri) {
        final MintSession active=session;if(active==null)return;busy(true);
        worker.execute(()->{
            String result=null,error=null;
            try(java.io.InputStream input=getContentResolver().openInputStream(uri);java.io.ByteArrayOutputStream bytes=new java.io.ByteArrayOutputStream()) {
                if(input==null)throw new java.io.IOException(getString(R.string.advanced_types_open_error));byte[] buffer=new byte[8192];int n;
                while((n=input.read(buffer))!=-1){if(bytes.size()+n>1024*1024)throw new java.io.IOException(getString(R.string.advanced_types_size_error));bytes.write(buffer,0,n);}
                result=new String(bytes.toByteArray(),java.nio.charset.StandardCharsets.UTF_8);
                if(!result.startsWith("MINT_TYPES 1 ") && !result.startsWith("MINTSIG 1\n"))throw new java.io.IOException(getString(R.string.advanced_types_format_error));
            }catch(Exception e){error=e.getMessage();}
            final String source=result,failure=error;main.post(()->{
                if(isDestroyed() || active!=session)return;busy(false);if(failure!=null){showProjectError(failure);return;}
                boolean signatures=source.startsWith("MINTSIG ");String preview=source.length()>8192?source.substring(0,8192)+"\n" + getString(R.string.advanced_types_preview_truncated):source;
                new com.google.android.material.dialog.MaterialAlertDialogBuilder(this).setTitle(signatures?getString(R.string.advanced_types_signatures_confirm):getString(R.string.advanced_types_merge_confirm))
                        .setMessage(new android.text.SpannableStringBuilder(highlighter.code(preview))
                                .append("\n\n").append(getText(R.string.advanced_types_merge_help)))
                        .setNegativeButton(android.R.string.cancel,null).setPositiveButton(getString(R.string.advanced_import),(d,w)->mutateProject(()->active.importLibrary(source,signatures))).show();
            });
        });
    }
    private void showReport(String title,AddressQuery query) {
        final MintSession active=session;if(active==null)return;busy(true);
        worker.execute(() -> {
            String body;try{body=query.run(active);}catch(RuntimeException e){body=e.getMessage();}
            final String result=body;
            main.post(() -> {
                if(isDestroyed() || active!=session)return;busy(false);
                displayReport(title,result);
            });
        });
    }
    private void displayReport(String title,String result) {
        new com.google.android.material.dialog.MaterialAlertDialogBuilder(this).setTitle(title)
                .setView(reportView(result)).setPositiveButton(R.string.ws_close,null).show();
    }

    private View reportView(String result) {
        TextView view=new TextView(this);view.setTypeface(Typeface.MONOSPACE);view.setTextSize(12);view.setTextIsSelectable(true);view.setText(result==null || result.isEmpty()?getString(R.string.ws_report_empty):result);
        android.widget.ScrollView scroll=new android.widget.ScrollView(this);scroll.addView(view);
        return scroll;
    }

    private void preparePseudoCExport() {
        if (selected == null) {
            showProjectError(getString(R.string.ws_pseudo_pick_function));
            return;
        }
        final MintSession active = session;
        final long entry = selected.entry;
        final long generation = viewGeneration;
        busy(true);
        worker.execute(() -> {
            try {
                final String report = active.decompileView(entry)[0];
                if (report.isEmpty()) throw new IllegalStateException(getString(R.string.ws_no_pseudo_report));
                main.post(() -> {
                    if (isDestroyed() || active != session || generation != viewGeneration) return;
                    busy(false);
                    final Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT);
                    intent.addCategory(Intent.CATEGORY_OPENABLE);
                    intent.setType("text/plain");
                    intent.putExtra(Intent.EXTRA_TITLE, String.format(Locale.US, "mint-%x-pseudo-c.txt", entry));
                    model.pendingPseudoCExport = report;
                    try {
                        startActivityForResult(intent, PSEUDO_C_EXPORT_REQUEST);
                    } catch (android.content.ActivityNotFoundException e) {
                        model.pendingPseudoCExport = null;
                        showProjectError(getString(R.string.welcome_no_picker));
                    }
                });
            } catch (RuntimeException e) {
                main.post(() -> {
                    if (isDestroyed() || active != session || generation != viewGeneration) return;
                    busy(false);
                    showProjectError(getString(R.string.ws_pseudo_export_failed, e.getMessage()));
                });
            }
        });
    }

    private void writePseudoCReport(Uri destination, @Nullable String report) {
        if (report == null) {
            showProjectError(getString(R.string.ws_pseudo_export_interrupted));
            return;
        }
        worker.execute(() -> {
            String message;
            try (java.io.OutputStream output = getContentResolver().openOutputStream(destination, "wt")) {
                if (output == null) throw new java.io.IOException(getString(R.string.ws_export_dest_failed));
                output.write(report.getBytes(java.nio.charset.StandardCharsets.UTF_8));
                message = getString(R.string.ws_pseudo_exported);
            } catch (Exception e) {
                message = getString(R.string.ws_export_failed, e.getMessage());
            }
            final String outcome = message;
            main.post(() -> { if (!isDestroyed()) showProjectError(outcome); });
        });
    }

    private void exportPatchedTo(Uri destination) {
        exportPatchedTo(destination, null);
    }

    private void exportPatchedTo(Uri destination, @Nullable PatchReview review) {
        final MintSession active=session;if(active==null)return;busy(true);
        worker.execute(() -> {
            java.io.File temporary=new java.io.File(getCacheDir(),"mint-export-"+java.util.UUID.randomUUID()+".bin");
            String failure=null;
            try {
                if (review != null) {
                    if (active != model.session()) throw new IllegalStateException(getString(R.string.ws_workspace_changed_export));
                    review.requireCurrent(active);
                }
                active.exportPatchedCopy(temporary.getAbsolutePath());
                try(java.io.InputStream input=new java.io.FileInputStream(temporary);java.io.OutputStream output=getContentResolver().openOutputStream(destination,"wt")) {
                    if(output==null)throw new java.io.IOException(getString(R.string.ws_export_dest_failed));
                    byte[] buffer=new byte[65536];int count;while((count=input.read(buffer))!=-1)output.write(buffer,0,count);
                }
            }catch(Exception e){failure=e.getMessage();}
            finally {if(temporary.exists())temporary.delete();}
            final String error=failure;
            main.post(() -> {if(isDestroyed() || active!=session)return;busy(false);showProjectError(error==null?getString(R.string.ws_patched_exported):getString(R.string.ws_export_failed, error));});
        });
    }

    private void exportProjectTo(Uri destination) {
        final MintSession active=session;
        final java.io.File binary=model.binaryFile();
        if(active==null || binary==null)return;
        final ProjectArchive.Metadata metadata=new ProjectArchive.Metadata(model.name()==null?getString(R.string.ws_binary):model.name(),
                model.rawConfig(),model.selectedAddress(),model.listingAddress(),model.pane());
        busy(true);
        worker.execute(() -> {
            java.io.File temporary=null;String failure=null;
            try {
                if(active!=model.session())throw new java.io.IOException(getString(R.string.ws_workspace_changed_backup));
                temporary=java.io.File.createTempFile("mint-project-", ".mintproj",getCacheDir());
                ProjectArchive.write(new java.io.FileOutputStream(temporary),binary.getParentFile(),metadata,
                        new java.util.concurrent.atomic.AtomicBoolean());
                try(java.io.InputStream input=new java.io.FileInputStream(temporary);
                    java.io.OutputStream output=getContentResolver().openOutputStream(destination,"wt")) {
                    if(output==null)throw new java.io.IOException(getString(R.string.ws_backup_destination_failed));
                    byte[] buffer=new byte[65536];int count;
                    while((count=input.read(buffer))!=-1)if(count!=0)output.write(buffer,0,count);
                }
            }catch(Exception error){failure=error.getMessage();}
            finally {if(temporary!=null && temporary.exists())temporary.delete();}
            final String error=failure;
            main.post(() -> {
                if(isDestroyed() || active!=session)return;busy(false);
                showProjectError(error==null?getString(R.string.ws_backup_ok):
                        getString(R.string.ws_backup_failed, error));
            });
        });
    }

    private interface AddressQuery { String run(MintSession active); }

    private void showReferences(long address) {
        showAddressResults(getString(R.string.ws_references_for, Long.toHexString(address)),active -> active.references(address));
    }

    private void showMemoryBlocks() {
        final MintSession active=session;if(active==null)return;busy(true);
        worker.execute(()->{
            String body;try{body=active.memoryBlocks();}catch(RuntimeException error){body=error.getMessage();}
            final String report=body;
            main.post(()->{if(isDestroyed()||active!=session)return;busy(false);
                new com.google.android.material.dialog.MaterialAlertDialogBuilder(this)
                    .setTitle(R.string.ws_memory_blocks).setMessage(report)
                    .setNeutralButton(R.string.ws_jump_to_block,(dialog,which)->showAddressResults(getString(R.string.ws_memory_blocks),MintSession::memoryBlocks))
                    .setPositiveButton(R.string.ws_close,null).show();});
        });
    }

    private void showAddressResults(String title,AddressQuery query) {
        final MintSession active = session;
        if (active == null) return;
        busy(true);
        worker.execute(() -> {
            List<String> labels = new ArrayList<>(); List<Long> addresses = new ArrayList<>();
            String diagnostic = getString(R.string.ws_no_results);
            try {
                String body = query.run(active);
                for (String line : body.split("\n")) {
                    String[] parts = line.split("\t",2);
                    if (parts.length != 2) { if (!line.isEmpty()) diagnostic = line; continue; }
                    labels.add("0x"+parts[0]+"  "+parts[1]); addresses.add(Long.parseUnsignedLong(parts[0],16));
                }
            } catch (RuntimeException e) { diagnostic = e.getMessage(); }
            final String message = diagnostic;
            main.post(() -> {
                if (isDestroyed() || active != session) return;
                busy(false);
                androidx.appcompat.app.AlertDialog.Builder dialog = new com.google.android.material.dialog.MaterialAlertDialogBuilder(this).setTitle(title);
                if (labels.isEmpty()) dialog.setMessage(message);
                else dialog.setItems(labels.toArray(new String[0]),(d,which) -> jumpTo(addresses.get(which)));
                dialog.setNegativeButton(R.string.ws_close,null).show();
            });
        });
    }

    // ------------------------------------------------------------------ adapter

    /** A row: a monospace body and an optional dimmed trailing note. */
    private static final class Line {
        final String body;
        final String note;
        final long target;
        final FunctionRow function;

        Line(String body, String note, long target, FunctionRow function) {
            this.body = body;
            this.note = note;
            this.target = target;
            this.function = function;
        }
    }

    private final class LineAdapter extends RecyclerView.Adapter<LineHolder> {

        private final List<Line> rows = new ArrayList<>();

        void submit(List<Line> next) {
            rows.clear();
            rows.addAll(next);
            notifyDataSetChanged();
        }

        @NonNull
        @Override
        public LineHolder onCreateViewHolder(@NonNull ViewGroup parent, int type) {
            return new LineHolder(
                    getLayoutInflater().inflate(R.layout.item_line, parent, false));
        }

        @Override
        public void onBindViewHolder(@NonNull LineHolder holder, int position) {
            Line line = rows.get(position);
            if (line.function != null) {
                // A function row is an address and a name; only the address and the
                // instruction count want dimming, and running the instruction
                // highlighter over a symbol would colour parts of it at random.
                SpannableString span = new SpannableString(
                        line.note == null ? line.body : line.body + "   " + line.note);
                span.setSpan(new ForegroundColorSpan(dimColour), 0, 8, 0);
                if (line.note != null) {
                    span.setSpan(new ForegroundColorSpan(dimColour),
                            line.body.length(), span.length(), 0);
                }
                holder.text.setText(span);
            } else {
                holder.text.setText(highlighter.assembly(line.body, line.note));
            }
            holder.itemView.setOnClickListener(line.function != null
                    ? v -> select(line.function)
                    : line.target != -1 ? v -> jumpTo(line.target) : null);
            holder.itemView.setClickable(line.function != null || line.target != -1);
            holder.itemView.setOnLongClickListener(v -> {
                long address;
                try { address = line.function != null ? line.function.entry
                        : Long.parseUnsignedLong(line.body.split("\\s+",2)[0],16); }
                catch (NumberFormatException e) { return false; }
                editAddress(address);
                return true;
            });
        }

        @Override
        public int getItemCount() { return rows.size(); }
    }

    private static final class LineHolder extends RecyclerView.ViewHolder {
        final TextView text;

        LineHolder(@NonNull View view) {
            super(view);
            text = view.findViewById(R.id.line);
            text.setTypeface(Typeface.MONOSPACE);
        }
    }
}
