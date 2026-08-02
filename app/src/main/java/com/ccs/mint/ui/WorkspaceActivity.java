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
import com.google.android.material.bottomnavigation.BottomNavigationView;
import com.google.android.material.progressindicator.LinearProgressIndicator;

import java.util.ArrayList;
import java.util.HashMap;
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
    private BottomNavigationView nav;

    private final LineAdapter adapter = new LineAdapter();
    private Highlighter highlighter;
    private androidx.appcompat.app.AlertDialog betaNotice;
    private int dimColour;
    private int pane = R.id.pane_functions;
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

        nav.setOnItemSelectedListener(item -> {
            pane = item.getItemId();
            model.rememberPane(pane);
            showPane();
            return true;
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
                nav.setSelectedItemId(R.id.pane_log);
            } else if (current.phase == WorkspaceViewModel.Phase.CANCELED) {
                appendLog(current.message == null ? "analysis cancelled" : current.message);
                if (session == null) nav.setSelectedItemId(R.id.pane_log);
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
                    nav.setSelectedItemId(R.id.pane_log);
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
            nav.setSelectedItemId(R.id.pane_log);
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
        history.clear();
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
                nav.setSelectedItemId(pane);
            });
        });
    }

    // -------------------------------------------------------------------- panes

    private void showPane() {
        boolean isList = pane == R.id.pane_functions || pane == R.id.pane_disasm;
        list.setVisibility(isList ? View.VISIBLE : View.GONE);
        textScroll.setVisibility(isList || pane == R.id.pane_graph ? View.GONE : View.VISIBLE);
        graph.setVisibility(pane == R.id.pane_graph ? View.VISIBLE : View.GONE);
        filter.setVisibility(pane == R.id.pane_functions ? View.VISIBLE : View.GONE);

        if (pane == R.id.pane_log) {
            text.setText(log.isEmpty() ? "Nothing logged yet." : log);
            return;
        }
        if (session == null) {
            adapter.submit(new ArrayList<>());
            text.setText("");
            return;
        }
        if (pane == R.id.pane_functions) {
            applyFilter();
        } else if (pane == R.id.pane_graph) {
            loadGraph(selected);
        } else if (selected == null) {
            adapter.submit(new ArrayList<>());
            text.setText("Pick a function first.");
        } else if (pane == R.id.pane_disasm) {
            loadListing(selected);
        } else {
            loadText(selected, pane == R.id.pane_ir);
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

    private void loadListing(@NonNull FunctionRow function) {
        busy(true);
        MintSession active = session;
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
                long cursor = listingAddress >= function.entry
                        && listingAddress < function.entry + Math.max(1, function.size)
                        ? listingAddress : function.entry;
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
                        if (address[i] >= function.entry + Math.max(1, function.size)) {
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
                        complete = true;
                        break;
                    }
                    cursor = last;
                }
                if (!complete) {
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
                    node.x = (id % 2) * 205f + 12f;
                    node.y = (id / 2) * 92f + 12f;
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
        subtitle.setText(row.label());
        nav.setSelectedItemId(R.id.pane_disasm);
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
        subtitle.setText(row.label());
        nav.setSelectedItemId(R.id.pane_disasm);
    }

    @Override
    public void onBackPressed() {
        if (history.canGoBack()) {
            jumpTo(history.back());
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
        if (pane == R.id.pane_log) text.setText(log);
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
