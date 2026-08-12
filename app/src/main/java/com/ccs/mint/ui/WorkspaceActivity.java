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
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.TextView;

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

    /** How many of the biggest functions the program overview lists. */
    private static final int OVERVIEW_FUNCTIONS = 12;

    private ExecutorService worker;
    private WorkspaceViewModel model;

    private MintSession session;
    private final List<FunctionRow> functions = new ArrayList<>();
    private final List<FunctionRow> visible = new ArrayList<>();
    private FunctionRow selected;
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
    private Chip selection;

    private final LineAdapter adapter = new LineAdapter();
    private Highlighter highlighter;
    private androidx.appcompat.app.AlertDialog betaNotice;
    private int dimColour;
    private int pane = Pane.FUNCTIONS;
    private long listingAddress;
    private long pendingAddress;
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
        textScroll = findViewById(R.id.text_scroll);
        graph = findViewById(R.id.graph);
        cancel = findViewById(R.id.cancel_analysis);
        nav = findViewById(R.id.nav);
        selection = findViewById(R.id.selection);
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

        selection.setCloseIconContentDescription(getString(R.string.clear_function));
        selection.setOnCloseIconClickListener(v -> clearSelection());
        selection.setOnClickListener(v -> selectPane(Pane.DISASM));
        graph.setOnNodeClickListener(node -> {
            if (node.address >= 0) jumpTo(node.address);
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
        out.putLong("selected", selected == null ? 0 : selected.entry);
        out.putLong("listing", listingAddress);
        model.rememberWorkspace(selected == null ? 0 : selected.entry, listingAddress, pane);
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
            open(data.getData());
        }
    }

    private void open(@NonNull Uri uri) {
        empty.setVisibility(View.GONE);
        content.setVisibility(View.VISIBLE);
        appendLog("opening " + uri.getLastPathSegment());
        selected = null;
        pendingAddress = 0;
        functions.clear();
        visible.clear();
        adapter.submit(new ArrayList<>());
        graph.setNodes(new ArrayList<>());
        history.clear();
        updateSelectionChip();
        model.rememberWorkspace(0, 0, pane);
        model.open(getContentResolver(), uri);
    }

    private void onOpened(@Nullable String name) {
        session = model.session();
        if (session == null) return;
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
                if (pendingAddress != 0) {
                    FunctionRow restored = findFunction(pendingAddress);
                    if (restored != null) {
                        selected = restored;
                        if (listingAddress == 0) listingAddress = restored.entry;
                    }
                }
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
        selected = null;
        pendingAddress = 0;
        listingAddress = 0;
        model.rememberWorkspace(0, 0, pane);
        history.clear();
        updateSelectionChip();
        showPane();
    }

    private void updateSelectionChip() {
        if (selected == null) {
            selection.setVisibility(View.GONE);
            subtitle.setText(functions.isEmpty() ? "" : String.format(Locale.US,
                    "%,d functions", functions.size()));
        } else {
            selection.setVisibility(View.VISIBLE);
            selection.setText(getString(R.string.viewing_function, selected.label()));
        }
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
            case Pane.IR:
            case Pane.C:
                if (selected == null) loadProgramOverview();
                else loadText(selected, pane == Pane.IR);
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
        final long start;
        final long stop;
        final int cap;
        if (function == null) {
            // listingAddress survives a jump out of a function, so a program listing
            // resumes where the user was rather than at the top of the image.
            start = Math.max(0, listingAddress);
            stop = Long.MAX_VALUE;
            cap = PROGRAM_LISTING_LIMIT;
        } else {
            final long end = function.entry + Math.max(1, function.size);
            start = listingAddress >= function.entry && listingAddress < end
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
                        if (address[i] >= stop || lines.size() >= cap) {
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
                    if (done || got < LISTING_LIMIT || last <= cursor) {
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
                if (isFinishing() || isDestroyed() || active != session) return;
                busy(false);
                adapter.submit(lines);
            });
        });
    }

    /**
     * What the IR and pseudo-C panes show when nothing is selected: the image, the
     * analysis counters, the biggest functions, and whatever the loader complained
     * about.
     *
     * <p>Not a placeholder. These are the numbers that say whether the analysis is
     * worth trusting — a thousand undecodable sites or a section table that
     * disagrees with the program headers means the output below is a partial view of
     * something that has been through a protector.
     */
    private void loadProgramOverview() {
        adapter.submit(new ArrayList<>());
        busy(true);
        final MintSession active = session;
        final List<FunctionRow> snapshot = new ArrayList<>(functions);
        worker.execute(() -> {
            final StringBuilder out = new StringBuilder();
            try {
                if (active == null) return;
                out.append(active.imageSummary().trim()).append("\n\n");

                final long[] stats = new long[MintSession.STAT_COUNT];
                active.stats(stats);
                counter(out, "instructions", stats[MintSession.STAT_INSTRUCTIONS]);
                counter(out, "functions", stats[MintSession.STAT_FUNCTIONS]);
                counter(out, "basic blocks", stats[MintSession.STAT_BLOCKS]);
                counter(out, "CFG edges", stats[MintSession.STAT_EDGES]);
                counter(out, "indirect jumps", stats[MintSession.STAT_INDIRECT_JUMPS]);
                counter(out, "undecodable", stats[MintSession.STAT_UNDECODABLE]);
                counter(out, "incomplete functions",
                        stats[MintSession.STAT_INCOMPLETE_FUNCTIONS]);
                counter(out, "found by sweep", stats[MintSession.STAT_SWEEP_FUNCTIONS]);

                if (!snapshot.isEmpty()) {
                    Collections.sort(snapshot,
                            (a, b) -> Integer.compare(b.instructions, a.instructions));
                    out.append("\n/* largest functions */\n");
                    final int shown = Math.min(OVERVIEW_FUNCTIONS, snapshot.size());
                    for (int i = 0; i < shown; i++) {
                        final FunctionRow row = snapshot.get(i);
                        out.append(String.format(Locale.US, "  %08x  %-38s %,7d insn%n",
                                row.entry, row.label(), row.instructions));
                    }
                }

                final String warnings = active.warnings();
                if (warnings != null && !warnings.trim().isEmpty()) {
                    out.append("\n/* loader warnings */\n");
                    for (String line : warnings.trim().split("\\R")) {
                        out.append("  ").append(line).append('\n');
                    }
                }
                out.append('\n').append(getString(R.string.overview_hint));
            } catch (RuntimeException e) {
                out.append("overview failed: ").append(e.getMessage());
            }
            final CharSequence result = highlighter.code(out.toString());
            runOnUiThread(() -> {
                if (isFinishing() || isDestroyed() || active != session) return;
                busy(false);
                text.setText(result);
            });
        });
    }

    private static void counter(StringBuilder out, String label, long value) {
        out.append(String.format(Locale.US, "%-22s %,12d%n", label, value));
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
                    final long entry = Long.parseLong(fields[1]);
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
                if (isFinishing() || isDestroyed() || active != session) return;
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
                    long start = Long.parseLong(fields[1]);
                    long end = Long.parseLong(fields[2]);
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
                if (isFinishing() || isDestroyed() || active != session) return;
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
                if (isFinishing() || isDestroyed() || active != session) return;
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
        updateSelectionChip();
        selectPane(Pane.DISASM);
    }

    private FunctionRow findFunction(long address) {
        for (FunctionRow row : functions) {
            if (address >= row.entry && address < row.entry + Math.max(1, row.size)) return row;
        }
        for (FunctionRow row : functions) if (row.entry == address) return row;
        return null;
    }

    private void jumpTo(long address) {
        FunctionRow row = findFunction(address);
        if (row == null) {
            appendLog(String.format(Locale.US, "no function for target 0x%x", address));
            return;
        }
        selected = row;
        listingAddress = address;
        pendingAddress = row.entry;
        model.rememberSelection(row.entry, listingAddress);
        history.push(address);
        updateSelectionChip();
        selectPane(Pane.DISASM);
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
                    : line.target >= 0 ? v -> jumpTo(line.target) : null);
            holder.itemView.setClickable(line.function != null || line.target >= 0);
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
