package com.ccs.mint.ui;

import android.content.Context;
import android.content.SharedPreferences;
import android.net.Uri;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.lifecycle.LiveData;
import androidx.lifecycle.MutableLiveData;
import androidx.lifecycle.ViewModel;

import com.ccs.mint.core.MintSession;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Owns the native session and its serial worker, rather than the Activity.
 * Rotation therefore recreates only views; the mapped file and completed
 * analysis remain alive until the workspace is actually discarded.
 */
public final class WorkspaceViewModel extends ViewModel {
    public enum Phase { EMPTY, OPENING, READY, FAILED, CANCELED }

    public static final class State {
        public final Phase phase;
        public final String name;
        public final String message;

        State(Phase phase, String name, String message) {
            this.phase = phase;
            this.name = name;
            this.message = message;
        }
    }

    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final MutableLiveData<State> state =
            new MutableLiveData<>(new State(Phase.EMPTY, null, null));
    private final AtomicLong generation = new AtomicLong();
    private final AtomicBoolean cancelRequested = new AtomicBoolean();

    private volatile MintSession session;
    private volatile MintSession opening;
    private volatile String name;
    private volatile int progress;
    private volatile RawImportConfig rawConfig;
    private volatile java.io.File binaryFile;
    private Future<?> openTask;
    private SharedPreferences projectPreferences;

    // Workspace navigation is state too. Keeping it here makes a recreated
    // Activity a new view over the same workspace, rather than a fresh browser.
    private final Object workspaceLock = new Object();
    private long selectedAddress = -1;
    private long listingAddress;
    private int pane = Pane.FUNCTIONS;
    private String claimedViewIntent;
    private final NavigationHistory navigationHistory = new NavigationHistory();

    @NonNull
    public LiveData<State> state() { return state; }

    @NonNull
    public ExecutorService worker() { return worker; }

    public MintSession session() { return session; }

    public String name() { return name; }

    @Nullable
    public RawImportConfig rawConfig() { return rawConfig; }

    @Nullable
    public java.io.File binaryFile() { return binaryFile; }

    public long selectedAddress() {
        synchronized (workspaceLock) { return selectedAddress; }
    }

    public long listingAddress() {
        synchronized (workspaceLock) { return listingAddress; }
    }

    public int pane() {
        synchronized (workspaceLock) { return pane; }
    }

    @NonNull
    public NavigationHistory navigationHistory() { return navigationHistory; }

    public void rememberSelection(long functionAddress, long listing) {
        synchronized (workspaceLock) {
            selectedAddress = functionAddress;
            listingAddress = listing;
            saveNavigation();
        }
    }

    public void rememberPane(int paneId) {
        synchronized (workspaceLock) { pane = paneId; saveNavigation(); }
    }

    public void rememberWorkspace(long functionAddress, long listing, int paneId) {
        synchronized (workspaceLock) {
            selectedAddress = functionAddress;
            listingAddress = listing;
            pane = paneId;
            saveNavigation();
        }
    }

    /**
     * Claims an ACTION_VIEW data URI once for this ViewModel lifetime. Android
     * may deliver the same Intent again after configuration change; reopening
     * that URI would start a second native analysis of the same file.
     */
    public boolean claimViewIntent(@NonNull Uri uri) {
        final String key = uri.toString();
        synchronized (workspaceLock) {
            if (key.equals(claimedViewIntent)) return false;
            claimedViewIntent = key;
            return true;
        }
    }

    public int progress() {
        MintSession active = opening != null ? opening : session;
        if (active == null) return progress;
        try {
            return Math.max(progress, active.progress());
        } catch (IllegalStateException ignored) {
            return progress;
        }
    }

    private void saveNavigation() {
        if (projectPreferences != null) projectPreferences.edit().putLong("selected",selectedAddress)
                .putLong("listing",listingAddress).putInt("pane",pane).apply();
    }

    public void restoreLast(@NonNull Context context) {
        if (session != null || generation.get() != 0) return;
        String path = context.getSharedPreferences("projects",Context.MODE_PRIVATE).getString("last",null);
        if (path == null) return;
        java.io.File binary = new java.io.File(path);
        if (!binary.isFile()) return;
        SharedPreferences preferences = context.getSharedPreferences(
                "project-" + binary.getParentFile().getName(), Context.MODE_PRIVATE);
        try {
            String architecture = preferences.getString("raw_arch", null);
            RawImportConfig restored = architecture == null ? null : new RawImportConfig(architecture,
                    preferences.getLong("raw_base", 0), preferences.getLong("raw_entry", 0));
            // Missing/corrupt raw metadata must not silently reopen a raw
            // Program under automatic format detection or a different ISA.
            if (binary.getParentFile().getName().contains("-raw-") && restored == null) {
                throw new IllegalArgumentException("Saved raw import configuration is missing");
            }
            if (restored != null && !binary.getParentFile().getName().endsWith(restored.projectSuffix())) {
                throw new IllegalArgumentException("Saved raw configuration does not match the project mapping");
            }
            openInternal(context, Uri.fromFile(binary), restored, binary, false);
        } catch (RuntimeException exception) {
            state.postValue(new State(Phase.FAILED, "input.bin", "Cannot restore raw project: " + exception.getMessage()));
        }
    }

    public void open(@NonNull Context context, @NonNull Uri uri) {
        open(context, uri, null);
    }

    /** Null configuration performs native container detection; non-null is explicit raw. */
    public void open(@NonNull Context context, @NonNull Uri uri, @Nullable RawImportConfig config) {
        openInternal(context, uri, config, null, false);
    }

    public void importProjectArchive(@NonNull Context context, @NonNull Uri uri) {
        openInternal(context, uri, null, null, true);
    }

    private void openInternal(@NonNull Context context, @NonNull Uri uri, @Nullable RawImportConfig config,
                              @Nullable java.io.File existingBinary, boolean archive) {
        final Context application = context.getApplicationContext();
        final long token = generation.incrementAndGet();
        cancelRequested.set(false);
        progress = 5;
        state.postValue(new State(Phase.OPENING, uri.getLastPathSegment(), null));
        openTask = worker.submit(() -> {
            MintSession opened = null;
            String error = null;
            String displayName = uri.getLastPathSegment();
            try {
                RawImportConfig actualConfig = config;
                ProjectArchive.Metadata restoredMetadata = null;
                java.io.File binary;
                if (archive) {
                    try (java.io.InputStream input = application.getContentResolver().openInputStream(uri)) {
                        if (input == null) throw new java.io.IOException("Cannot read project archive");
                        ProjectArchive.Restored restored = ProjectArchive.restore(input,
                                new java.io.File(application.getFilesDir(), "projects"), cancelRequested, (directory, metadata) -> {
                                    String path = new java.io.File(directory, "input.bin").getAbsolutePath();
                                    try (MintSession validation = metadata.raw == null ? MintSession.open(path) : metadata.raw.open(path)) {
                                        validation.attachProject(new java.io.File(directory, "program.mint").getAbsolutePath());
                                    }
                                });
                        binary = restored.binary;
                        restoredMetadata = restored.metadata;
                        actualConfig = restoredMetadata.raw;
                        displayName = restoredMetadata.name;
                    }
                } else binary = existingBinary == null ? ProjectStore.importBinary(application,uri,cancelRequested,config) :
                        ProjectStore.requirePrivateInput(application, existingBinary);
                if (cancelRequested.get() || token != generation.get()) throw new java.io.IOException("import cancelled");
                SharedPreferences preferences = application.getSharedPreferences("project-"+binary.getParentFile().getName(),Context.MODE_PRIVATE);
                if ("input.bin".equals(displayName)) displayName = preferences.getString("name",displayName);
                opened = actualConfig == null ? MintSession.open(binary.getAbsolutePath()) : actualConfig.open(binary.getAbsolutePath());
                opened.attachProject(new java.io.File(binary.getParentFile(),"program.mint").getAbsolutePath());
                opening = opened;
                if (cancelRequested.get()) opened.cancelAnalysis();
                progress = 10;
                opened.analyze();
                if (cancelRequested.get() || token != generation.get()) {
                    opened.close();
                    opened = null;
                    if (token == generation.get()) state.postValue(new State(Phase.CANCELED, displayName, null));
                } else {
                    SharedPreferences.Editor projectEditor = preferences.edit().putString("name",displayName);
                    if (actualConfig == null) projectEditor.remove("raw_arch").remove("raw_base").remove("raw_entry");
                    else projectEditor.putString("raw_arch",actualConfig.architecture)
                            .putLong("raw_base",actualConfig.baseAddress).putLong("raw_entry",actualConfig.entryAddress);
                    if (restoredMetadata != null) projectEditor.putLong("selected", restoredMetadata.selected)
                            .putLong("listing", restoredMetadata.listing).putInt("pane", restoredMetadata.pane);
                    // Configuration must be durable before replacing the live
                    // session or updating the cold-start project pointer.
                    if (!projectEditor.commit()) throw new java.io.IOException("cannot save project configuration");
                    MintSession previous = session;
                    session = opened;
                    name = displayName;
                    rawConfig = actualConfig;
                    binaryFile = binary;
                    progress = 100;
                    opened = null;
                    opening = null;
                    if (previous != null) previous.close();
                    synchronized (workspaceLock) {
                        projectPreferences = preferences;
                        selectedAddress = preferences.getLong("selected",-1);
                        listingAddress = preferences.getLong("listing",0);
                        pane = preferences.getInt("pane",Pane.FUNCTIONS);
                        navigationHistory.clear();
                    }
                    application.getSharedPreferences("projects",Context.MODE_PRIVATE).edit().putString("last",binary.getAbsolutePath()).apply();
                    state.postValue(new State(Phase.READY, displayName, null));
                }
            } catch (Exception exception) {
                error = exception.getMessage();
                if (opened != null) opened.close();
                if (token == generation.get()) {
                    state.postValue(new State(
                            cancelRequested.get() ? Phase.CANCELED : Phase.FAILED,
                            displayName, error == null ? exception.toString() : error));
                }
            } finally {
                opening = null;
            }
        });
    }

    /** Stops the current analysis without invalidating the session from a view. */
    public void cancel() {
        cancelRequested.set(true);
        MintSession current = opening;
        if (current != null) current.cancelAnalysis();
        Future<?> task = openTask;
        if (task != null) task.cancel(false);
        state.postValue(new State(Phase.CANCELED, name, "analysis cancelled"));
    }

    @Override
    protected void onCleared() {
        cancelRequested.set(true);
        Future<?> task = openTask;
        if (task != null) task.cancel(false);
        MintSession current = opening;
        if (current != null) current.cancelAnalysis();
        // Do not close from the Activity's onDestroy: that callback also runs for
        // rotation. Queue close behind the serial worker so a native call can never
        // observe a freed Session.
        worker.execute(() -> {
            MintSession old = session;
            session = null;
            if (old != null) old.close();
        });
        worker.shutdown();
    }
}
