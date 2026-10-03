package com.ccs.mint.ui;

import android.app.Activity;
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
import androidx.appcompat.app.AppCompatActivity;
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
public final class WorkspaceActivity extends AppCompatActivity {

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
    private TabLayout nav;
    private ViewGroup openChips;
    private View openScroll;

    private final LineAdapter adapter = new LineAdapter();
    private Highlighter highlighter;
    private androidx.appcompat.app.AlertDialog betaNotice;
    private int dimColour;
    private int pane = Pane.FUNCTIONS;
    private long listingAddress;
    private long pendingAddress = -1;
    private NavigationHistory history;
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
                catch(IllegalArgumentException e){main.post(()->{if(!isDestroyed())showProjectError("The pending raw import requires a decoder that is not loaded. Reload the trusted decoder plugin and select the raw mapping again.");});}
            }
        }
        // Edge to edge, then pad the content back by hand. Without this the title is
        // drawn underneath the status bar clock, which is what the old layout did.
        WindowCompat.setDecorFitsSystemWindows(getWindow(), false);
        setContentView(R.layout.activity_workspace);
        highlighter = new Highlighter(this);
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
        findViewById(R.id.about).setOnClickListener(v -> showLicences());
        findViewById(R.id.project_actions).setOnClickListener(v -> showProjectActions());
        showBetaNoticeOnce();
        findViewById(R.id.try_example).setOnClickListener(v -> openExample());
        cancel.setOnClickListener(v -> model.cancel());

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
            if (current.phase == WorkspaceViewModel.Phase.OPENING) {
                // A recreated Activity starts from the XML's empty state. The
                // ViewModel may still be analysing the same descriptor, so restore
                // the workspace shell while the determinate progress bar runs.
                empty.setVisibility(View.GONE);
                content.setVisibility(View.VISIBLE);
            } else if (current.phase == WorkspaceViewModel.Phase.READY) {
                session = model.session();
                onOpened(current.name);
            } else if (current.phase == WorkspaceViewModel.Phase.FAILED) {
                appendLog("failed: " + current.message);
                selectPane(Pane.LOG);
            } else if (current.phase == WorkspaceViewModel.Phase.CANCELED) {
                appendLog(current.message == null ? "analysis cancelled" : current.message);
                if (session == null) selectPane(Pane.LOG);
            }
        });

        handleViewIntent(getIntent());
        if (getIntent() == null || !Intent.ACTION_VIEW.equals(getIntent().getAction())) model.restoreLast(this);
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        handleViewIntent(intent);
    }

    /** Opens the file another app handed over, when launched that way. */
    private void handleViewIntent(@Nullable Intent intent) {
        if (intent == null || !Intent.ACTION_VIEW.equals(intent.getAction())) return;
        Uri uri = intent.getData();
        if (uri != null && model.claimViewIntent(uri)) open(uri);
    }

    @Override
    protected void onDestroy() {
        if (betaNotice != null && betaNotice.isShowing()) betaNotice.dismiss();
        betaNotice = null;
        super.onDestroy();
        // The ViewModel owns both the worker and native handle. onDestroy is also
        // the normal rotation callback, so closing either here loses the analysis.
    }

    @Override
    protected void onSaveInstanceState(@NonNull Bundle out) {
        out.putInt("pane", pane);
        out.putLong("selected", selected == null ? -1 : selected.entry);
        out.putLong("listing", listingAddress);
        if(pendingRawImport!=null){out.putString("pendingRawArch",pendingRawImport.architecture);out.putLong("pendingRawBase",pendingRawImport.baseAddress);out.putLong("pendingRawEntry",pendingRawImport.entryAddress);}
        model.rememberWorkspace(selected == null ? -1 : selected.entry, listingAddress, pane);
        super.onSaveInstanceState(out);
    }

    /**
     * Copies the bundled example out of the APK and opens it.
     *
     * <p>Copied rather than read in place because the engine maps the file, and an
     * asset inside the APK is not a standalone mappable file. Written once and
     * reused, so a second visit costs nothing.
     */
    private void openExample() {
        busy(true);
        worker.execute(() -> {
            java.io.File target = new java.io.File(getFilesDir(), "libmintdemo.so");
            String failure = null;
            if (!target.exists() || target.length() == 0) {
                try (java.io.InputStream in = getAssets().open("libmintdemo.so");
                     java.io.OutputStream out = new java.io.FileOutputStream(target)) {
                    byte[] chunk = new byte[16384];
                    int read;
                    while ((read = in.read(chunk)) > 0) out.write(chunk, 0, read);
                } catch (java.io.IOException e) {
                    failure = String.valueOf(e.getMessage());
                }
            }
            final String error = failure;
            main.post(() -> {
                busy(false);
                if (error != null) {
                    appendLog("could not unpack the example: " + error);
                    selectPane(Pane.LOG);
                    return;
                }
                open(Uri.fromFile(target));
            });
        });
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
        new androidx.appcompat.app.AlertDialog.Builder(this).setTitle("Import binary")
                .setItems(new String[]{"Auto-detect native ELF / PE / Mach-O", "Raw binary — built-in or loaded plugin decoder", "Restore Mint project archive", "Mach-O — select CPU slice explicitly"},(d,which) -> {
                    if(which==0){pendingRawImport=null;launchFilePicker();}
                    else if(which==1)promptRawImport();
                    else if(which==2)pickDocument(PROJECT_OPEN_REQUEST);
                    else new androidx.appcompat.app.AlertDialog.Builder(this).setTitle("Mach-O architecture").setItems(new String[]{"AArch64", "x86-64", "x86-32", "ARM"},(dialog,index)->{
                        pendingRawImport=RawImportConfig.machOSlice(new String[]{"aarch64","x86-64","x86-32","arm"}[index]);launchFilePicker();
                    }).show();
                }).show();
    }

    private void promptRawImport() {
        final com.ccs.mint.core.RawArchitecture[] architectures;
        try { architectures = MintSession.rawArchitectures(); RawImportConfig.installArchitectures(architectures); }
        catch (RuntimeException | LinkageError error) { showProjectError("Cannot read decoder registry: " + error.getMessage()); return; }
        final String[] labels = new String[architectures.length];
        for (int i = 0; i < labels.length; ++i) labels[i] = architectures[i].name + " — " + (architectures[i].pointerSize * 8) + "-bit" +
                (architectures[i].numericId >= 128 ? (architectures[i].hasLifter?" (plugin decoder + semantic lifter)":" (plugin decoder; no lifter)") : "");
        new androidx.appcompat.app.AlertDialog.Builder(this).setTitle("Raw architecture")
                .setItems(labels,(d,which) -> {
                    LinearLayout form=new LinearLayout(this);form.setOrientation(LinearLayout.VERTICAL);
                    EditText base=new EditText(this),entry=new EditText(this);
                    base.setHint("Base address (hex)");base.setText("0x1000");entry.setHint("Entry address (hex)");entry.setText("0x1000");form.addView(base);form.addView(entry);
                    new androidx.appcompat.app.AlertDialog.Builder(this).setTitle("Raw memory mapping").setView(form)
                            .setPositiveButton("Choose file",(dialog,w) -> {
                                try{pendingRawImport=RawImportConfig.fromHex(architectures[which].id,base.getText().toString(),entry.getText().toString());launchFilePicker();}
                                catch(IllegalArgumentException e){showProjectError(e.getMessage());}
                            }).setNegativeButton("Cancel",null).show();
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
        if(request==SCRIPT_REQUEST && result==Activity.RESULT_OK && data!=null && data.getData()!=null)openScript(data.getData());
        if(request==COMPARISON_REQUEST && result==Activity.RESULT_OK && data!=null && data.getData()!=null)openComparison(data.getData());
        if(request==PLUGIN_REQUEST && result==Activity.RESULT_OK && data!=null && data.getData()!=null)openNativePlugin(data.getData());
        if(request==LIBRARY_REQUEST && result==Activity.RESULT_OK && data!=null && data.getData()!=null)openLibrary(data.getData());
        if(request==TRACKING_SAVE_REQUEST && result==Activity.RESULT_OK && data!=null && data.getData()!=null)trackingDocument(data.getData(),true);
        if(request==TRACKING_LOAD_REQUEST && result==Activity.RESULT_OK && data!=null && data.getData()!=null)trackingDocument(data.getData(),false);
        if(request==PROJECT_SAVE_REQUEST && result==Activity.RESULT_OK && data!=null && data.getData()!=null)exportProjectTo(data.getData());
        if(request==PROJECT_OPEN_REQUEST && result==Activity.RESULT_OK && data!=null && data.getData()!=null) {
            resetOpeningView(data.getData()); model.importProjectArchive(this, data.getData());
        }
        if(request==DEBUG_IMPORT_REQUEST && result==Activity.RESULT_OK && data!=null && data.getData()!=null)importExternalDebug(data.getData());
    }

    private void open(@NonNull Uri uri) {
        open(uri,null);
    }
    private void open(@NonNull Uri uri,@Nullable RawImportConfig config) {
        resetOpeningView(uri);
        model.open(this, uri,config);
    }

    private void resetOpeningView(@NonNull Uri uri) {
        ++viewGeneration;
        session = null;
        empty.setVisibility(View.GONE);
        content.setVisibility(View.VISIBLE);
        appendLog("opening " + uri.getLastPathSegment());
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
        title.setText(name == null ? "binary" : name.substring(name.lastIndexOf('/') + 1));
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
                error = "function list failed: " + e.getMessage();
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
        subtitle.setText(functions.isEmpty() ? "" : String.format(Locale.US,
                "%,d functions", functions.size()));
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
        if(session!=null)busy(false);
        final boolean isList = pane == Pane.FUNCTIONS || pane == Pane.DISASM;
        list.setVisibility(isList ? View.VISIBLE : View.GONE);
        textScroll.setVisibility(isList || pane == Pane.GRAPH ? View.GONE : View.VISIBLE);
        graph.setVisibility(pane == Pane.GRAPH ? View.VISIBLE : View.GONE);
        filter.setVisibility(pane == Pane.FUNCTIONS ? View.VISIBLE : View.GONE);

        if (pane == Pane.LOG) {
            text.setText(log.isEmpty() ? "Nothing logged yet." : log);
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
                    row.instructions + " insn", -1, row));
        }
        adapter.submit(lines);
        subtitle.setText(query.isEmpty()
                ? String.format(Locale.US, "%,d functions", functions.size())
                : String.format(Locale.US, "%,d of %,d", visible.size(), functions.size()));
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
        final MintSession active = session;
        final long requestGeneration = viewGeneration;
        final long start;
        final long stop;
        final int cap;
        if (function == null) {
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
                    lines.add(new Line(String.format(Locale.US,
                            "listing stops after %,d instructions — open a function to see"
                                    + " all of it", cap), null, -1, null));
                } else if (!complete) {
                    lines.add(new Line("listing truncated: page safety limit reached", null,
                            -1, null));
                }
            } catch (RuntimeException e) {
                lines.add(new Line("listing failed: " + e.getMessage(), null, -1, null));
            }
            runOnUiThread(() -> {
                if (isFinishing() || isDestroyed() || active != session || requestGeneration != viewGeneration) return;
                busy(false);
                adapter.submit(lines);
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
                body = "xrefs failed: " + e.getMessage();
            }
            final CharSequence result = highlighter.code(
                    body == null || body.isEmpty() ? "(nothing)" : body);
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
                body = "strings failed: " + e.getMessage();
            }
            final CharSequence result = highlighter.code(
                    body == null || body.isEmpty() ? "(nothing)" : body);
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
                body = report.name().toLowerCase(Locale.US) + " failed: " + e.getMessage();
            }
            final CharSequence result = highlighter.code(
                    body == null || body.isEmpty() ? "(nothing)" : body);
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
                failure = "call graph failed: " + e.getMessage();
            }
            final String error = failure;
            final int removed = dropped;
            runOnUiThread(() -> {
                if (isFinishing() || isDestroyed() || active != session || requestGeneration != viewGeneration) return;
                busy(false);
                appendLog(error);
                if (removed > 0) {
                    appendLog(String.format(Locale.US,
                            "call graph capped at %,d functions; %,d with the fewest calls"
                                    + " were left out", CALL_GRAPH_LIMIT, removed));
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
                graphError = "CFG failed: " + e.getMessage();
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
        busy(true);
        text.setText("");
        MintSession active = session;
        final long requestGeneration = viewGeneration;
        worker.execute(() -> {
            String body;
            try {
                if (active == null) throw new IllegalStateException("session is closed");
                body = ir ? active.functionIr(function.entry)
                        : active.decompiledC(function.entry);
            } catch (RuntimeException e) {
                body = (ir ? "IR" : "decompilation") + " failed: " + e.getMessage();
            }
            final CharSequence result = highlighter.code(
                    body == null || body.isEmpty() ? "(empty)" : body);
            runOnUiThread(() -> {
                if (isFinishing() || isDestroyed() || active != session || requestGeneration != viewGeneration) return;
                busy(false);
                text.setText(linkedCode(result));
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
                body = "write map failed: " + e.getMessage();
            }
            final CharSequence result = highlighter.code(
                    body == null || body.isEmpty() ? "(nothing)" : body);
            runOnUiThread(() -> {
                if (isFinishing() || isDestroyed() || active != session || requestGeneration != viewGeneration) return;
                busy(false);
                text.setText(result);
            });
        });
    }

    private void select(@NonNull FunctionRow row) {
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

    @Override
    public void onBackPressed() {
        if (history.canGoBack()) {
            jumpTo(history.back());
            return;
        }
        // Out of history but still inside a function: back should surface the whole
        // program before it leaves the app. Otherwise following a call chain to its
        // end and pressing back closes Mint, which is never what was meant.
        if (selected != null) {
            clearSelection();
            return;
        }
        super.onBackPressed();
    }

    private void busy(boolean value) {
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
        String[] actions = {"Global search", "Go to address", "Edit current address", "References at current address", "Undo edit", "Redo edit", "Memory blocks", "Data Type Manager", "Function provenance", "C++ RTTI / vtables", "Reanalyze", "Export patched copy", "Navigate forward", "DWARF / source information", "Assemble patch at current address", "Lua script editor", "Open Lua script", "Compare another binary / version tracking", "External debugger", "Native plugins", "Interprocedural prototype constraints", "Back up complete project", "Restore project archive", "Edit local variables", "Function ABI storage", "Import external / split DWARF"};
        new androidx.appcompat.app.AlertDialog.Builder(this).setTitle("Project")
                .setItems(actions,(dialog,which) -> {
                    if (which == 0) promptSearch();
                    else if (which == 1) {
                        EditText input = new EditText(this); input.setHint("Hex address, e.g. 0x1000");
                        new androidx.appcompat.app.AlertDialog.Builder(this).setTitle("Go to address").setView(input)
                                .setPositiveButton("Go",(d,w) -> {
                                    try { jumpTo(Long.parseUnsignedLong(input.getText().toString().trim().replaceFirst("^(0x|0X)",""),16)); }
                                    catch (NumberFormatException e) { showProjectError("Invalid hexadecimal address"); }
                                }).setNegativeButton("Cancel",null).show();
                    } else if (which == 2) editAddress(listingAddress);
                    else if (which == 3) showReferences(listingAddress);
                    else if(which==4 || which==5) { MintSession active = session; mutateProject(() -> active.undoEdit(which == 5)); }
                    else if(which==6)showAddressResults("Memory blocks",MintSession::memoryBlocks);
                    else if(which==7)showTypeManager();
                    else if(which==8)showReport("Function provenance",active -> active.provenance(listingAddress));
                    else if(which==9)showReport("C++ metadata",MintSession::cxxMetadata);
                    else if(which==10){MintSession active=session;mutateProject(active::reanalyze);}
                    else if(which==11){Intent intent=new Intent(Intent.ACTION_CREATE_DOCUMENT);intent.setType("application/octet-stream");intent.addCategory(Intent.CATEGORY_OPENABLE);intent.putExtra(Intent.EXTRA_TITLE,"mint-patched.bin");startActivityForResult(intent,EXPORT_REQUEST);}
                    else if(which==12 && history.canGoForward())jumpTo(history.forward());
                    else if(which==13)showReport("DWARF debug information",MintSession::debugInfo);
                    else if(which==14)promptAssembly(listingAddress);
                    else if(which==15)promptScript("for _, f in ipairs(mint.functions()) do\n  print(f.entry, f.name, f.origin)\nend");
                    else if(which==16){Intent intent=new Intent(Intent.ACTION_OPEN_DOCUMENT);intent.setType("*/*");intent.addCategory(Intent.CATEGORY_OPENABLE);startActivityForResult(intent,SCRIPT_REQUEST);}
                    else if(which==17)showVersionTracking();
                    else if(which==18)showDebugger();
                    else if(which==19)showNativePlugins();
                    else if(which==20)showReport("Call-graph prototype constraints",MintSession::interproceduralPrototypes);
                    else if(which==21) {
                        Intent intent=new Intent(Intent.ACTION_CREATE_DOCUMENT);intent.setType("application/zip");
                        intent.addCategory(Intent.CATEGORY_OPENABLE);intent.putExtra(Intent.EXTRA_TITLE,"mint-project.mintproj");
                        startActivityForResult(intent,PROJECT_SAVE_REQUEST);
                    } else if(which==22)pickDocument(PROJECT_OPEN_REQUEST);
                    else if(which==23)showLocalVariables();
                    else if(which==24){final long function=selected==null?listingAddress:selected.entry;showReport("Function ABI storage",s->s.abi(function));}
                    else if(which==25)pickDocument(DEBUG_IMPORT_REQUEST);
                }).show();
    }

    private void pickDocument(int request) {
        Intent intent=new Intent(Intent.ACTION_OPEN_DOCUMENT);intent.setType("*/*");intent.addCategory(Intent.CATEGORY_OPENABLE);startActivityForResult(intent,request);
    }
    private void importExternalDebug(Uri uri) {
        final MintSession active=session;if(active==null)return;
        android.widget.CheckBox unverified=new android.widget.CheckBox(this);unverified.setText("Accept missing identity evidence (partial / unverified report)");
        new androidx.appcompat.app.AlertDialog.Builder(this).setTitle("Import external DWARF / PDB")
                .setMessage("Choose matching ELF/DWO debug information or a Windows PDB7 file. Available build IDs, debuglink CRC, split-unit IDs or PDB GUID/age must match; a mismatch is always rejected. A private bounded copy survives reopening and is included in project backups. No referenced path is followed automatically. Unsupported records stay explicitly partial.")
                .setView(unverified).setNegativeButton("Cancel",null).setPositiveButton("Import",(dialog,button)->{
                    final boolean allow=unverified.isChecked();mutateProject(()->{java.io.File temporary=null;
                        try{temporary=java.io.File.createTempFile("mint-debug-",".bin",getCacheDir());
                            try(java.io.InputStream input=getContentResolver().openInputStream(uri);java.io.FileOutputStream output=new java.io.FileOutputStream(temporary)) {
                                if(input==null)throw new java.io.IOException("Cannot open debug file");byte[] buffer=new byte[65536];long size=0;int count;
                                while((count=input.read(buffer))!=-1){size+=count;if(size>ProjectArchive.MAX_DEBUG)throw new java.io.IOException("External debug file exceeds 128 MiB");output.write(buffer,0,count);}output.getFD().sync();
                            }
                            active.importDebug(temporary.getAbsolutePath(),allow);
                        }catch(java.io.IOException error){throw new IllegalStateException(error.getMessage(),error);}
                        finally{if(temporary!=null)temporary.delete();}
                    });
                }).show();
    }
    private void showVersionTracking() {
        new androidx.appcompat.app.AlertDialog.Builder(this).setTitle("Binary diff / version tracking")
                .setItems(new String[]{"Open comparison binary", "Function-level diff", "Confirm function pair", "Confirmed pairs", "Preview annotation transfer", "Apply transfer to comparison Program", "Save confirmed pairs", "Load confirmed pairs"},(d,which) -> {
                    if(which==0) {
                        if(model.rawConfig()!=null)new androidx.appcompat.app.AlertDialog.Builder(this).setTitle("Explicit comparison interpretation")
                                .setMessage(model.rawConfig().machOSlice?"The comparison Mach-O uses the same explicitly selected CPU slice. Addresses are read from the container.":"The comparison raw binary uses the same architecture, base and entry as this Program.")
                                .setPositiveButton("Choose binary",(a,b)->pickDocument(COMPARISON_REQUEST)).setNegativeButton("Cancel",null).show();
                        else pickDocument(COMPARISON_REQUEST);
                    } else if(which==1)showReport("Semantic diff",active->active.comparison("diff",0,0,""));
                    else if(which==2)promptFunctionPair();
                    else if(which==3)showReport("Confirmed function pairs",active->active.comparison("tracking",0,0,""));
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
                        if(output==null)throw new java.io.IOException("Cannot open tracking destination");
                        byte[] buffer=new byte[8192];int count;while((count=input.read(buffer))!=-1)output.write(buffer,0,count);
                    }
                    result="Confirmed pairs saved. Load them after opening these same source and comparison Programs; changed code or identities are rejected.";
                } else {
                    try(java.io.InputStream input=getContentResolver().openInputStream(document);java.io.FileOutputStream output=new java.io.FileOutputStream(temporary)) {
                        if(input==null)throw new java.io.IOException("Cannot open tracking file");
                        byte[] buffer=new byte[8192];int count;long size=0;while((count=input.read(buffer))!=-1){if((size+=count)>16*1024*1024)throw new java.io.IOException("Tracking file exceeds 16 MiB");output.write(buffer,0,count);}output.getFD().sync();
                    }
                    result=active.comparison("load",0,0,temporary.getAbsolutePath());
                }
            }catch(Exception e){result=(save?"Save failed; destination may be incomplete: ":"Load failed: ")+e.getMessage();}
            finally{if(temporary.exists())temporary.delete();}
            final String body=result;main.post(()->{if(isDestroyed() || active!=session)return;busy(false);displayReport("Version tracking",body);});
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
            final String body=result;main.post(()->{if(isDestroyed() || active!=session)return;busy(false);displayReport("Comparison Program",body);});
        });
    }
    private void promptFunctionPair() {
        LinearLayout fields=new LinearLayout(this);fields.setOrientation(LinearLayout.VERTICAL);
        EditText source=new EditText(this);source.setHint("Source function entry (hex)");source.setText("0x"+Long.toUnsignedString(listingAddress,16));fields.addView(source);
        EditText target=new EditText(this);target.setHint("Comparison function entry (hex)");fields.addView(target);
        new androidx.appcompat.app.AlertDialog.Builder(this).setTitle("Confirm matching functions")
                .setMessage("This is a manual decision, not an automatic match. It authorizes transfer previews for this exact pair and current code; no annotations are transferred yet.")
                .setView(fields).setNegativeButton("Cancel",null).setPositiveButton("Confirm pair",(d,w)->{
                    try {long from=parseHexAddress(source.getText().toString()),to=parseHexAddress(target.getText().toString());showReport("Confirmed pair",active->active.comparison("confirm",from,to,""));}
                    catch(NumberFormatException e){showProjectError("Enter both function entry addresses in hexadecimal");}
                }).show();
    }
    private static long parseHexAddress(String value) {return Long.parseUnsignedLong(value.trim().replaceFirst("^(0x|0X)",""),16);}
    private void previewTransfer(boolean apply) {
        final MintSession active=session;if(active==null)return;busy(true);
        worker.execute(()->{
            String result=null,error=null;try{result=active.comparison("preview",0,0,"");}catch(RuntimeException e){error=e.getMessage();}
            final String body=result,failure=error;main.post(()->{
                if(isDestroyed() || active!=session)return;busy(false);if(failure!=null){showProjectError(failure);return;}
                if(!apply){displayReport("Transfer preview",body);return;}
                new androidx.appcompat.app.AlertDialog.Builder(this).setTitle("Apply annotations to comparison Program?")
                        .setMessage(body+"\nExisting comparison annotations win. Only confirmed instruction-aligned symbols, comments, bookmarks and supported prototypes transfer. Patches and type libraries do not transfer. The current Program is unchanged.")
                        .setNegativeButton("Cancel",null).setPositiveButton("Apply transfer",(d,w)->showReport("Transfer result",s->s.comparison("apply",0,0,""))).show();
            });
        });
    }
    private void showDebugger() {
        String[] actions={"Connect debugger", "Status", "Attach LLDB DAP to PID", "Read registers", "Read 256 bytes at mapped current address", "Set mapped breakpoint here", "Remove mapped breakpoint here", "Step one instruction", "Continue", "Interrupt", "Wait for stop (bounded)", "Disconnect", "Threads / select thread", "Stack frames", "Loaded modules", "Map current binary to runtime base", "Go to mapped PC", "Read RSP register layout", "Clear address mapping"};
        new androidx.appcompat.app.AlertDialog.Builder(this).setTitle("External debugger")
                .setItems(actions,(d,which)->{
                    if(which==0){promptDebuggerConnection();return;}
                    if(which==12){showDebuggerThreads();return;}
                    if(which==13){showDebuggerFrames();return;}
                    if(which==15){promptDebuggerMapping();return;}
                    if(which==16){runDebuggerAndFollowPc("pc-image");return;}
                    if(which==2){EditText pid=new EditText(this);pid.setHint("Existing process ID (decimal)");pid.setInputType(android.text.InputType.TYPE_CLASS_NUMBER);
                        new androidx.appcompat.app.AlertDialog.Builder(this).setTitle("Attach to existing process")
                                .setMessage("LLDB DAP only. Mint never launches a process or executes a shell command.")
                                .setView(pid).setNegativeButton("Cancel",null).setPositiveButton("Attach",(a,b)->{
                                    try{long id=Long.parseLong(pid.getText().toString().trim());if(id<=0)throw new NumberFormatException();showReport("Debugger attach",s->s.debugger("attach",0,id));}
                                    catch(NumberFormatException e){showProjectError("PID must be a positive decimal integer");}
                                }).show();return;
                    }
                    String[] ops={"","status","","registers","memory-image","break-image","unbreak-image","step","continue","interrupt","wait","disconnect","threads","stack","modules","map-image","pc-image","layout","unmap"};
                    final long at=listingAddress;
                    if(which>=5 && which<=9)new androidx.appcompat.app.AlertDialog.Builder(this).setTitle(actions[which])
                            .setMessage("This changes the connected target process. Breakpoints require your explicit image-to-runtime mapping; Mint never guesses the ASLR slide.")
                            .setNegativeButton("Cancel",null).setPositiveButton("Execute",(a,b)->{if(which==7 || which==9)runDebuggerAndFollowPc(ops[which]);else showReport("Debugger",s->s.debugger(ops[which],at,0));}).show();
                    else if(which==10)runDebuggerAndFollowPc("wait");
                    else showReport("Debugger",s->s.debugger(ops[which],at,which==4?256:0));
                }).show();
    }
    private void promptDebuggerMapping() {
        EditText runtime=new EditText(this);runtime.setHint("Runtime load base, hexadecimal (e.g. 0x7f000000)");
        new androidx.appcompat.app.AlertDialog.Builder(this).setTitle("Explicit ASLR mapping")
                .setMessage("Inspect Loaded modules first. Enter the runtime address corresponding to this binary's preferred image base, not its entry point. Confirm this is the same binary. Mapping is session-only and is cleared on disconnect.")
                .setView(runtime).setNegativeButton("Cancel",null).setPositiveButton("Map",(d,w)->{
                    try{String text=runtime.getText().toString().trim();if(text.startsWith("0x"))text=text.substring(2);long base=Long.parseUnsignedLong(text,16);showReport("Address mapping",s->s.debugger("map-image",base,0));}
                    catch(NumberFormatException e){showProjectError("Enter a valid 64-bit hexadecimal runtime base");}
                }).show();
    }
    private void showDebuggerThreads() {
        final MintSession active=session;if(active==null)return;busy(true);
        worker.execute(()->{String result;try{result=active.debugger("threads",0,0);}catch(Exception e){result=e.getMessage();}final String body=result;
            main.post(()->{if(isDestroyed() || active!=session)return;busy(false);
                java.util.ArrayList<String> rows=new java.util.ArrayList<>();java.util.ArrayList<Long> ids=new java.util.ArrayList<>();
                for(String line:body.split("\n")){int tab=line.indexOf('\t');if(tab<1)continue;try{long id=Long.parseUnsignedLong(line.substring(0,tab));ids.add(id);rows.add(line);}catch(NumberFormatException ignored){}}
                if(rows.isEmpty()){displayReport("Threads",body);return;}
                new androidx.appcompat.app.AlertDialog.Builder(this).setTitle("Select debugger thread").setItems(rows.toArray(new String[0]),(d,index)->showReport("Selected thread",s->s.debugger("thread",0,ids.get(index)))).setNegativeButton("Close",null).show();
            });});
    }
    private void showDebuggerFrames() {
        final MintSession active=session;if(active==null)return;busy(true);
        worker.execute(()->{String result;try{result=active.debugger("stack",0,64);}catch(Exception error){result=error.getMessage();}final String body=result;
            main.post(()->{if(isDestroyed() || active!=session)return;busy(false);java.util.ArrayList<String> labels=new java.util.ArrayList<>();java.util.ArrayList<Long> addresses=new java.util.ArrayList<>();
                for(String line:body.split("\n")){String[] fields=line.split("\t",-1);if(fields.length<4 || !fields[2].startsWith("image 0x"))continue;
                    try{addresses.add(Long.parseUnsignedLong(fields[2].substring(8),16));labels.add(fields[3]+" — "+fields[2]+(fields.length>4?" — "+fields[4]:""));}catch(NumberFormatException ignored){}}
                if(labels.isEmpty()){displayReport("Stack frames — no validated image mapping",body);return;}
                new androidx.appcompat.app.AlertDialog.Builder(this).setTitle("Mapped stack frames").setItems(labels.toArray(new String[0]),(d,index)->jumpTo(addresses.get(index))).setNeutralButton("Full report",(d,w)->displayReport("Stack frames",body)).setNegativeButton("Close",null).show();
            });});
    }
    private void runDebuggerAndFollowPc(String operation) {
        final MintSession active=session;if(active==null)return;busy(true);
        worker.execute(()->{String result,pc=null;try{result=active.debugger(operation,0,0);try{pc=operation.equals("pc-image")?result:active.debugger("pc-image",0,0);}catch(Exception e){result+="\nPC not synchronized: "+e.getMessage();}}catch(Exception e){result=e.getMessage();}
            final String body=result,position=pc;main.post(()->{if(isDestroyed() || active!=session)return;busy(false);
                if(position!=null){int tab=position.indexOf('\t');if(tab>2 && position.startsWith("0x"))try{jumpTo(Long.parseUnsignedLong(position.substring(2,tab),16));}catch(NumberFormatException ignored){}}
                displayReport("Debugger",body);
            });});
    }
    private void promptDebuggerConnection() {
        LinearLayout fields=new LinearLayout(this);fields.setOrientation(LinearLayout.VERTICAL);
        android.widget.Spinner backend=new android.widget.Spinner(this);backend.setAdapter(new android.widget.ArrayAdapter<>(this,android.R.layout.simple_spinner_dropdown_item,new String[]{"GDB / LLDB remote (RSP)", "LLDB DAP over TCP"}));fields.addView(backend);
        EditText host=new EditText(this);host.setHint("Numeric IPv4 / IPv6");host.setText("127.0.0.1");fields.addView(host);
        EditText port=new EditText(this);port.setHint("TCP port");port.setInputType(android.text.InputType.TYPE_CLASS_NUMBER);fields.addView(port);
        android.widget.CheckBox remote=new android.widget.CheckBox(this);remote.setText("I accept unencrypted, unauthenticated non-loopback TCP");fields.addView(remote);
        new androidx.appcompat.app.AlertDialog.Builder(this).setTitle("Connect external debugger")
                .setMessage("Connects only when you press Connect. Prefer loopback with your own authenticated tunnel. RSP expects an already attached all-stop stub; DAP requires a separate PID attach. Static analysis remains offline.")
                .setView(fields).setNegativeButton("Cancel",null).setPositiveButton("Connect",(d,w)->{
                    try{int number=Integer.parseInt(port.getText().toString().trim());String address=host.getText().toString().trim();boolean dap=backend.getSelectedItemPosition()==1,allow=remote.isChecked();showReport("Debugger connection",s->s.connectDebugger(address,number,dap,allow));}
                    catch(NumberFormatException e){showProjectError("Enter a numeric TCP port from 1 to 65535");}
                }).show();
    }
    private void showNativePlugins() {
        new androidx.appcompat.app.AlertDialog.Builder(this).setTitle("Native plugins")
                .setItems(new String[]{"Load trusted .so plugin", "List commands", "Run plugin command"},(d,which)->{
                    if(which==0)pickDocument(PLUGIN_REQUEST);
                    else if(which==1)showReport("Plugin commands",MintSession::pluginCommands);
                    else {
                        LinearLayout fields=new LinearLayout(this);fields.setOrientation(LinearLayout.VERTICAL);
                        EditText command=new EditText(this);command.setHint("plugin-id/command-id");fields.addView(command);
                        EditText arguments=new EditText(this);arguments.setHint("Arguments");fields.addView(arguments);
                        android.widget.CheckBox edits=new android.widget.CheckBox(this);edits.setText("Allow Program edits through the host API");fields.addView(edits);
                        new androidx.appcompat.app.AlertDialog.Builder(this).setTitle("Run trusted native code")
                                .setMessage("Native plugins are not sandboxed. The edits switch limits only the provided Mint API, not the plugin's OS access.")
                                .setView(fields).setNegativeButton("Cancel",null).setPositiveButton("Run",(a,b)->{
                                    String id=command.getText().toString(),args=arguments.getText().toString();boolean allow=edits.isChecked();
                                    if(allow){++viewGeneration;pendingAddress=selected==null?-1:selected.entry;}
                                    showReport("Plugin output",s->s.runPlugin(id,args,allow));
                                    if(allow){openFunctions.clear();loadFunctions();}
                                }).show();
                    }
                }).show();
    }
    private void openNativePlugin(Uri uri) {
        final MintSession active=session;if(active==null)return;
        new androidx.appcompat.app.AlertDialog.Builder(this).setTitle("Trust and load native plugin?")
                .setMessage("Loading this file executes unrestricted native code with Mint's permissions, including access to your private projects and network. Only load plugins you trust, built for this device ABI and Mint SDK v1/v2. Files are never auto-loaded on reopening a project.")
                .setNegativeButton("Cancel",null).setPositiveButton("Trust and load",(d,w)->{
                    busy(true);worker.execute(()->{
                        java.io.File file=null;String result;
                        try {
                            java.io.File root=new java.io.File(getCodeCacheDir(),"mint-plugins");if(!root.isDirectory() && !root.mkdirs())throw new java.io.IOException("Cannot create plugin directory");
                            file=java.io.File.createTempFile("plugin-",".so",root);
                            // Set read-only before loading executable code on modern Android.
                            try(java.io.InputStream input=getContentResolver().openInputStream(uri);java.io.FileOutputStream output=new java.io.FileOutputStream(file)) {
                                if(input==null)throw new java.io.IOException("Cannot open plugin");if(!file.setReadOnly())throw new java.io.IOException("Cannot protect plugin file");
                                byte[] buffer=new byte[65536];int n;long size=0;
                                while((n=input.read(buffer))!=-1){if((size+=n)>16*1024*1024)throw new java.io.IOException("Plugin exceeds 16 MiB");output.write(buffer,0,n);}output.getFD().sync();
                            }
                            result=active.loadPlugin(file.getAbsolutePath(),true);
                        }catch(Exception e){if(file!=null && file.exists())file.delete();result=e.getMessage();}
                        final String body=result;main.post(()->{if(isDestroyed() || active!=session)return;busy(false);displayReport("Plugin load",body);});
                    });
                }).show();
    }

    private void showProjectError(String message) {
        new androidx.appcompat.app.AlertDialog.Builder(this).setTitle("Project").setMessage(message)
                .setPositiveButton("OK",null).show();
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
                    rows.add(fields);labels.add(fields[1]+" — "+fields[3]+" bytes, "+fields[4]+(fields[2].isEmpty()?"":" : "+fields[2]));
                }
                if(rows.isEmpty()){displayReport("Local variables",report);return;}
                new androidx.appcompat.app.AlertDialog.Builder(this).setTitle("Persistent local variables")
                        .setItems(labels.toArray(new String[0]),(dialog,which) -> {
                            String[] row=rows.get(which);LinearLayout fields=new LinearLayout(this);fields.setOrientation(LinearLayout.VERTICAL);
                            EditText name=new EditText(this),type=new EditText(this);
                            name.setHint("Local name (empty preserves inference)");name.setText(row[1]);
                            type.setHint("Type: i32, u64, named pointer… (empty preserves inference)");type.setText(row[2]);fields.addView(name);fields.addView(type);
                            new androidx.appcompat.app.AlertDialog.Builder(this).setTitle("Rename / retype "+row[1])
                                    .setMessage("Storage width must match. Bindings are guarded by the current function structure; stale bindings are retained but never applied to different values. Parameter names/types belong in the function prototype.")
                                    .setView(fields).setNegativeButton("Cancel",null)
                                    .setNeutralButton("Remove override",(d,w)->mutateProject(()->active.editLocal(function,row[0],"","")))
                                    .setPositiveButton("Save",(d,w)->{String edited=name.getText().toString().trim(),declared=type.getText().toString().trim();mutateProject(()->active.editLocal(function,row[0],edited,declared));}).show();
                        }).setNegativeButton("Close",null).show();
            });
        });
    }

    private void promptAssembly(long address) {
        final MintSession active=session;if(active==null)return;
        EditText input=new EditText(this);input.setTypeface(Typeface.MONOSPACE);input.setMinLines(4);input.setHint("nop\nret");
        new androidx.appcompat.app.AlertDialog.Builder(this).setTitle(String.format(Locale.US,"Assemble at 0x%x",address))
                .setMessage("Bounded scalar instruction subset with labels. Preview the encoded bytes before replacing code. Unsupported forms are rejected; original input remains unchanged.")
                .setView(input).setNegativeButton("Cancel",null).setPositiveButton("Preview",(d,w) -> {
                    final String source=input.getText().toString();busy(true);
                    worker.execute(() -> {
                        String bytes=null,error=null;try{bytes=active.assemble(address,source,false);}catch(RuntimeException e){error=e.getMessage();}
                        final String encoded=bytes,failure=error;
                        main.post(() -> {
                            if(isDestroyed() || active!=session)return;busy(false);
                            if(failure!=null){showProjectError(failure);return;}
                            new androidx.appcompat.app.AlertDialog.Builder(this).setTitle("Confirm assembly patch")
                                    .setMessage(String.format(Locale.US,"0x%x\n%s\n\nThis replaces %d bytes. Undo/redo and patched-copy export apply.",address,encoded,encoded.isEmpty()?0:(encoded.length()+1)/3))
                                    .setNegativeButton("Cancel",null).setPositiveButton("Apply patch",(confirm,button) -> mutateProject(() -> active.assemble(address,source,true))).show();
                        });
                    });
                }).show();
    }

    private void promptScript(String source) {
        final MintSession active=session;if(active==null)return;
        LinearLayout fields=new LinearLayout(this);fields.setOrientation(LinearLayout.VERTICAL);
        EditText input=new EditText(this);input.setTypeface(Typeface.MONOSPACE);input.setText(source);input.setMinLines(5);input.setMaxLines(14);fields.addView(input);
        android.widget.CheckBox edits=new android.widget.CheckBox(this);edits.setText("Allow this script to edit the Program");fields.addView(edits);
        new androidx.appcompat.app.AlertDialog.Builder(this).setTitle("Run Lua script")
                .setMessage("Read-only by default. No files, network or process access. Execution and memory are bounded. Permitted edits are committed individually and remain undoable even if the script stops with an error.")
                .setView(fields).setNegativeButton("Cancel",null).setPositiveButton("Run",(dialog,which) -> {
                    final String text=input.getText().toString();final boolean allow=edits.isChecked();++viewGeneration;busy(true);
                    worker.execute(() -> {
                        String result;try{result=active.runScript(text,allow);}catch(RuntimeException e){result=e.getMessage();}
                        final String output=result;
                        main.post(() -> {
                            if(isDestroyed() || active!=session)return;busy(false);
                            displayReport("Lua output",output);
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
                if(input==null)throw new java.io.IOException("Cannot open script");
                byte[] buffer=new byte[4096];int count;
                while((count=input.read(buffer))!=-1){if(bytes.size()+count>256*1024)throw new java.io.IOException("Script exceeds 256 KiB");bytes.write(buffer,0,count);}
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
        String[] labels = {"Rename symbol", "Comment", "Bookmark", "Define data — type expression or cstring", "Function prototype: uint64_t(int32_t count, void* buffer)", "Define function entry — code", "Patch hex bytes — 1f 20 03 d5", "References"};
        new androidx.appcompat.app.AlertDialog.Builder(this).setTitle(String.format(Locale.US,"0x%x",address))
                .setItems(labels,(dialog,which) -> {
                    if (which == 7) { showReferences(address); return; }
                    String kind = kinds[which];
                    worker.execute(() -> {
                        String value;
                        try { value = active.annotation(address,kind); }
                        catch (RuntimeException e) { main.post(() -> showProjectError(e.getMessage())); return; }
                        final String initial = value;
                        main.post(() -> {
                            if (isDestroyed() || active != session) return;
                            EditText input = new EditText(this); input.setText(initial);
                            input.setHint("Empty value removes the override");
                            new androidx.appcompat.app.AlertDialog.Builder(this).setTitle(labels[which]).setView(input)
                                    .setPositiveButton("Save",(d,w) -> {
                                        String edited = input.getText().toString();
                                        mutateProject(() -> active.edit(address,kind,edited));
                                    }).setNegativeButton("Cancel",null).show();
                        });
                    });
                }).show();
    }

    private void mutateProject(Runnable operation) {
        ++viewGeneration;
        busy(true);
        final MintSession active = session;
        worker.execute(() -> {
            String failure = null;
            try { if (active == null || active != model.session()) return; operation.run(); }
            catch (RuntimeException e) { failure = e.getMessage(); }
            final String error = failure;
            main.post(() -> {
                if (isDestroyed() || active != session) return;
                busy(false);
                if (error != null) showProjectError(error);
                else { pendingAddress = selected == null ? -1 : selected.entry; openFunctions.clear(); loadFunctions(); }
            });
        });
    }

    private void promptSearch() {
        EditText input = new EditText(this);
        input.setHint("Symbol, comment, bookmark, string, or bytes: 7f 45 4c 46");
        new androidx.appcompat.app.AlertDialog.Builder(this).setTitle("Global search (up to 500 hits)").setView(input)
                .setPositiveButton("Search",(dialog,which) -> {
                    String query = input.getText().toString();
                    showAddressResults("Search",active -> active.search(query));
                }).setNegativeButton("Cancel",null).show();
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

    private void showTypeManager() {
        final MintSession active=session;if(active==null)return;
        new androidx.appcompat.app.AlertDialog.Builder(this).setTitle("Data Type Manager")
                .setItems(new String[]{"View definitions", "Add or replace definition", "Remove definition", "Exportable GNU C11 type header", "Import type / signature library", "View imported signatures"},(d,which) -> {
                    if(which==0){showReport("Data types",MintSession::types);return;}
                    if(which==3){showReport("C type header (select / copy)",MintSession::typesCHeader);return;}
                    if(which==4){pickDocument(LIBRARY_REQUEST);return;}
                    if(which==5){showReport("Signature library",MintSession::signatureLibrary);return;}
                    EditText input=new EditText(this);
                    input.setHint(which==1?"Packet=struct{length:u32;bytes:u8[16];next:Packet*}":"Type name");
                    new androidx.appcompat.app.AlertDialog.Builder(this).setTitle(which==1?"Define type":"Remove type").setView(input)
                            .setPositiveButton("Save",(dialog,w) -> {String declaration=input.getText().toString();mutateProject(() -> {if(which==1)active.defineType(declaration);else active.eraseType(declaration);});})
                            .setNegativeButton("Cancel",null).show();
                }).show();
    }

    private void openLibrary(Uri uri) {
        final MintSession active=session;if(active==null)return;busy(true);
        worker.execute(()->{
            String result=null,error=null;
            try(java.io.InputStream input=getContentResolver().openInputStream(uri);java.io.ByteArrayOutputStream bytes=new java.io.ByteArrayOutputStream()) {
                if(input==null)throw new java.io.IOException("Cannot open library");byte[] buffer=new byte[8192];int n;
                while((n=input.read(buffer))!=-1){if(bytes.size()+n>1024*1024)throw new java.io.IOException("Library exceeds 1 MiB");bytes.write(buffer,0,n);}
                result=new String(bytes.toByteArray(),java.nio.charset.StandardCharsets.UTF_8);
                if(!result.startsWith("MINT_TYPES 1 ") && !result.startsWith("MINTSIG 1\n"))throw new java.io.IOException("Expected MINT_TYPES 1 or MINTSIG 1 library");
            }catch(Exception e){error=e.getMessage();}
            final String source=result,failure=error;main.post(()->{
                if(isDestroyed() || active!=session)return;busy(false);if(failure!=null){showProjectError(failure);return;}
                boolean signatures=source.startsWith("MINTSIG ");String preview=source.length()>8192?source.substring(0,8192)+"\n[Preview truncated]":source;
                new androidx.appcompat.app.AlertDialog.Builder(this).setTitle(signatures?"Import signature library?":"Merge type library?")
                        .setMessage(preview+"\n\nABI and pointer width must match the current Program. Import is one persisted undoable transaction. Type names in this file replace matching definitions; a signature import replaces the previous signature library. Explicit function prototypes retain priority.")
                        .setNegativeButton("Cancel",null).setPositiveButton("Import",(d,w)->mutateProject(()->active.importLibrary(source,signatures))).show();
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
        TextView view=new TextView(this);view.setTypeface(Typeface.MONOSPACE);view.setTextSize(12);view.setTextIsSelectable(true);view.setText(result==null || result.isEmpty()?"No output / metadata found.":result);
        android.widget.ScrollView scroll=new android.widget.ScrollView(this);scroll.addView(view);
        new androidx.appcompat.app.AlertDialog.Builder(this).setTitle(title).setView(scroll).setPositiveButton("Close",null).show();
    }

    private void exportPatchedTo(Uri destination) {
        final MintSession active=session;if(active==null)return;busy(true);
        worker.execute(() -> {
            java.io.File temporary=new java.io.File(getCacheDir(),"mint-export-"+java.util.UUID.randomUUID()+".bin");
            String failure=null;
            try {
                active.exportPatchedCopy(temporary.getAbsolutePath());
                try(java.io.InputStream input=new java.io.FileInputStream(temporary);java.io.OutputStream output=getContentResolver().openOutputStream(destination,"wt")) {
                    if(output==null)throw new java.io.IOException("cannot open export destination");
                    byte[] buffer=new byte[65536];int count;while((count=input.read(buffer))!=-1)output.write(buffer,0,count);
                }
            }catch(Exception e){failure=e.getMessage();}
            finally {if(temporary.exists())temporary.delete();}
            final String error=failure;
            main.post(() -> {if(isDestroyed() || active!=session)return;busy(false);showProjectError(error==null?"Patched copy exported. Original input is unchanged.":"Export failed; destination may be incomplete: "+error);});
        });
    }

    private void exportProjectTo(Uri destination) {
        final MintSession active=session;
        final java.io.File binary=model.binaryFile();
        if(active==null || binary==null)return;
        final ProjectArchive.Metadata metadata=new ProjectArchive.Metadata(model.name()==null?"binary":model.name(),
                model.rawConfig(),model.selectedAddress(),model.listingAddress(),model.pane());
        busy(true);
        worker.execute(() -> {
            java.io.File temporary=null;String failure=null;
            try {
                if(active!=model.session())throw new java.io.IOException("Workspace changed before backup");
                temporary=java.io.File.createTempFile("mint-project-", ".mintproj",getCacheDir());
                ProjectArchive.write(new java.io.FileOutputStream(temporary),binary.getParentFile(),metadata,
                        new java.util.concurrent.atomic.AtomicBoolean());
                try(java.io.InputStream input=new java.io.FileInputStream(temporary);
                    java.io.OutputStream output=getContentResolver().openOutputStream(destination,"wt")) {
                    if(output==null)throw new java.io.IOException("Cannot open backup destination");
                    byte[] buffer=new byte[65536];int count;
                    while((count=input.read(buffer))!=-1)if(count!=0)output.write(buffer,0,count);
                }
            }catch(Exception error){failure=error.getMessage();}
            finally {if(temporary!=null && temporary.exists())temporary.delete();}
            final String error=failure;
            main.post(() -> {
                if(isDestroyed() || active!=session)return;busy(false);
                showProjectError(error==null?"Complete project backed up: original binary, annotations, types, patches and import/navigation settings. Restore creates an independent project.":
                        "Backup failed; chosen document may be incomplete: "+error);
            });
        });
    }

    private interface AddressQuery { String run(MintSession active); }

    private void showReferences(long address) {
        showAddressResults("References at 0x"+Long.toHexString(address),active -> active.references(address));
    }

    private void showAddressResults(String title,AddressQuery query) {
        final MintSession active = session;
        if (active == null) return;
        busy(true);
        worker.execute(() -> {
            List<String> labels = new ArrayList<>(); List<Long> addresses = new ArrayList<>();
            String diagnostic = "No results";
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
                androidx.appcompat.app.AlertDialog.Builder dialog = new androidx.appcompat.app.AlertDialog.Builder(this).setTitle(title);
                if (labels.isEmpty()) dialog.setMessage(message);
                else dialog.setItems(labels.toArray(new String[0]),(d,which) -> jumpTo(addresses.get(which)));
                dialog.setNegativeButton("Close",null).show();
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
