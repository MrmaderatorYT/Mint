package com.ccs.mint.ui;

import android.content.ContentResolver;
import android.net.Uri;
import android.os.ParcelFileDescriptor;

import androidx.annotation.NonNull;
import androidx.lifecycle.LiveData;
import androidx.lifecycle.MutableLiveData;
import androidx.lifecycle.ViewModel;

import com.ccs.mint.R;
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
    private Future<?> openTask;

    // Workspace navigation is state too. Keeping it here makes a recreated
    // Activity a new view over the same workspace, rather than a fresh browser.
    private final Object workspaceLock = new Object();
    private long selectedAddress;
    private long listingAddress;
    private int pane = R.id.pane_functions;
    private String claimedViewIntent;
    private final NavigationHistory navigationHistory = new NavigationHistory();

    @NonNull
    public LiveData<State> state() { return state; }

    @NonNull
    public ExecutorService worker() { return worker; }

    public MintSession session() { return session; }

    public String name() { return name; }

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
        }
    }

    public void rememberPane(int paneId) {
        synchronized (workspaceLock) { pane = paneId; }
    }

    public void rememberWorkspace(long functionAddress, long listing, int paneId) {
        synchronized (workspaceLock) {
            selectedAddress = functionAddress;
            listingAddress = listing;
            pane = paneId;
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

    public void open(@NonNull ContentResolver resolver, @NonNull Uri uri) {
        final long token = generation.incrementAndGet();
        cancelRequested.set(false);
        progress = 5;
        state.postValue(new State(Phase.OPENING, uri.getLastPathSegment(), null));
        openTask = worker.submit(() -> {
            MintSession opened = null;
            String error = null;
            final String displayName = uri.getLastPathSegment();
            try (ParcelFileDescriptor descriptor = resolver.openFileDescriptor(uri, "r")) {
                if (descriptor == null) throw new java.io.IOException("no descriptor");
                opened = MintSession.openDescriptor(descriptor.getFd());
                opening = opened;
                if (cancelRequested.get()) opened.cancelAnalysis();
                progress = 10;
                opened.analyze();
                if (cancelRequested.get() || token != generation.get()) {
                    opened.close();
                    opened = null;
                    state.postValue(new State(Phase.CANCELED, displayName, null));
                } else {
                    MintSession previous = session;
                    session = opened;
                    name = displayName;
                    progress = 100;
                    opened = null;
                    opening = null;
                    if (previous != null) previous.close();
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
