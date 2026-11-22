package com.ccs.mint.ui;

import android.content.Context;
import android.content.SharedPreferences;
import android.database.Cursor;
import android.net.Uri;
import android.provider.OpenableColumns;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.lifecycle.LiveData;
import androidx.lifecycle.MutableLiveData;
import androidx.lifecycle.ViewModel;

import com.ccs.mint.R;
import com.ccs.mint.core.MintSession;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;

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
    // Held only while the document picker is open, including rotation.
    String pendingPseudoCExport;
    WorkspaceActivity.PatchReview pendingReviewedExport;
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
    private boolean initialLaunchHandled;
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

    /** Do not replay the launch after rotation, especially a request to clone. */
    boolean claimInitialLaunch() {
        if (initialLaunchHandled) return false;
        initialLaunchHandled = true;
        return true;
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

    @Nullable
    static String lastProjectId(Context context) {
        try {
            String path = context.getSharedPreferences("projects", Context.MODE_PRIVATE).getString("last", null);
            if (path == null) return null;
            return projectId(ProjectStore.requirePrivateInput(context, new File(path)));
        } catch (IOException | ClassCastException ignored) {
            return null;
        }
    }

    @Nullable
    static String lastProjectName(Context context) {
        String id = lastProjectId(context);
        if (id == null) return null;
        try {
            return projectPreferences(context, id).getString("name", null);
        } catch (ClassCastException ignored) {
            return null;
        }
    }

    @Nullable
    String openedProjectId() {
        State current = state.getValue();
        File binary = binaryFile;
        return current != null && current.phase == Phase.READY && binary != null ? projectId(binary) : null;
    }

    void openSavedProject(Context context, String id) {
        openInternal(context, (application, cancel) -> {
            File binary = ProjectStore.findProject(application, id);
            SharedPreferences preferences = projectPreferences(application, id);
            String architecture = preferences.getString("raw_arch", null);
            RawImportConfig config = architecture == null ? null : new RawImportConfig(architecture,
                    preferences.getLong("raw_base", 0), preferences.getLong("raw_entry", 0));
            // A missing or inconsistent mapping cannot be reopened by guessing its format.
            if ((id.contains("-raw-") || id.contains("-macho-")) && config == null) {
                throw new IOException("Saved import configuration is missing");
            }
            if (config != null && !id.endsWith(config.projectSuffix())) {
                throw new IOException("Saved raw configuration does not match the project mapping");
            }
            return new OpenInput(binary, config, preferences.getString("name", "input.bin"), null);
        });
    }

    /** Null configuration performs native container detection; non-null is explicit raw. */
    public void open(@NonNull Context context, @NonNull Uri uri, @Nullable RawImportConfig config) {
        openInternal(context, (application, cancel) -> new OpenInput(
                ProjectStore.importBinary(application, uri, cancel, config), config,
                displayName(application, uri), null));
    }

    void openClone(Context context, Uri uri) {
        openInternal(context, (application, cancel) -> new OpenInput(
                ProjectStore.importClone(application, uri, cancel, null), null,
                MintActivity.localized(application).getString(R.string.binary_clone_name,
                        displayName(application, uri)), null));
    }

    void openLesson(Context context, String id, String asset) {
        openInternal(context, (application, cancel) -> new OpenInput(
                ProjectStore.importLesson(application, id, asset, cancel), null,
                asset.substring(asset.lastIndexOf('/') + 1), null));
    }

    public void importProjectArchive(@NonNull Context context, @NonNull Uri uri) {
        openInternal(context, (application, cancel) -> {
            try (InputStream input = application.getContentResolver().openInputStream(uri)) {
                if (input == null) throw new IOException("Cannot read project archive");
                ProjectArchive.Restored restored = ProjectArchive.restore(input,
                        new File(application.getFilesDir(), "projects"), cancel, (directory, metadata) -> {
                            String path = new File(directory, "input.bin").getAbsolutePath();
                            try (MintSession validation = metadata.raw == null ? MintSession.open(path) : metadata.raw.open(path)) {
                                validation.attachProject(new File(directory, "program.mint").getAbsolutePath());
                            }
                        });
                return new OpenInput(restored.binary, restored.metadata.raw, restored.metadata.name, restored.metadata);
            }
        });
    }

    private static String projectId(File binary) {
        return binary.getParentFile().getName();
    }

    private static SharedPreferences projectPreferences(Context context, String id) {
        return context.getSharedPreferences("project-" + id, Context.MODE_PRIVATE);
    }

    private static String displayName(Context context, Uri uri) {
        if ("content".equals(uri.getScheme())) {
            try (Cursor cursor = context.getContentResolver().query(uri,
                    new String[]{OpenableColumns.DISPLAY_NAME}, null, null, null)) {
                if (cursor != null && cursor.moveToFirst()) {
                    int column = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                    String name = column < 0 ? null : cursor.getString(column);
                    if (name != null && !name.trim().isEmpty()) return name;
                }
            } catch (RuntimeException ignored) {
                // Some providers supply a readable stream without document metadata.
            }
        }
        String name = uri.getLastPathSegment();
        return name == null || name.isEmpty() ? "input.bin" : name;
    }

    private interface InputSource {
        OpenInput prepare(Context context, AtomicBoolean cancel) throws Exception;
    }

    private static final class OpenInput {
        final File binary;
        final RawImportConfig config;
        final String name;
        final ProjectArchive.Metadata restoredArchive;

        OpenInput(File binary, RawImportConfig config, String name, ProjectArchive.Metadata restoredArchive) {
            this.binary = binary;
            this.config = config;
            this.name = name;
            this.restoredArchive = restoredArchive;
        }
    }

    private void openInternal(Context context, InputSource source) {
        final Context application = context.getApplicationContext();
        final long token = generation.incrementAndGet();
        cancelRequested.set(false);
        progress = 5;
        state.postValue(new State(Phase.OPENING, null, null));
        openTask = worker.submit(() -> {
            MintSession opened = null;
            String displayName = null;
            try {
                OpenInput input = source.prepare(application, cancelRequested);
                File binary = input.binary;
                RawImportConfig actualConfig = input.config;
                ProjectArchive.Metadata restoredMetadata = input.restoredArchive;
                displayName = input.name;
                if (cancelRequested.get() || token != generation.get()) throw new IOException("import cancelled");
                String id = projectId(binary);
                SharedPreferences preferences = projectPreferences(application, id);
                opened = actualConfig == null ? MintSession.open(binary.getAbsolutePath()) : actualConfig.open(binary.getAbsolutePath());
                opened.attachProject(new File(binary.getParentFile(), "program.mint").getAbsolutePath());
                opening = opened;
                if (cancelRequested.get()) opened.cancelAnalysis();
                progress = 10;
                opened.analyze();
                if (cancelRequested.get() || token != generation.get()) {
                    opened.close();
                    opened = null;
                    if (token == generation.get()) state.postValue(new State(Phase.CANCELED, displayName, null));
                } else {
                    SharedPreferences.Editor projectEditor = preferences.edit().putString("name", displayName)
                            .putLong("last_opened", System.currentTimeMillis());
                    if (actualConfig == null) projectEditor.remove("raw_arch").remove("raw_base").remove("raw_entry");
                    else projectEditor.putString("raw_arch",actualConfig.architecture)
                            .putLong("raw_base",actualConfig.baseAddress).putLong("raw_entry",actualConfig.entryAddress);
                    if (restoredMetadata != null) projectEditor.putLong("selected", restoredMetadata.selected)
                            .putLong("listing", restoredMetadata.listing).putInt("pane", restoredMetadata.pane);
                    // Configuration must be durable before replacing the live
                    // session or updating the cold-start project pointer.
                    if (!projectEditor.commit()) throw new IOException("cannot save project configuration");
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
                    if (!ProjectStore.isLessonProject(id)) {
                        application.getSharedPreferences("projects", Context.MODE_PRIVATE).edit()
                                .putString("last", binary.getAbsolutePath()).apply();
                    }
                    state.postValue(new State(Phase.READY, displayName, null));
                }
            } catch (Exception exception) {
                String error = exception.getMessage();
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
