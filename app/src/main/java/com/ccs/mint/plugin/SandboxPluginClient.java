package com.ccs.mint.plugin;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Binder;
import android.os.Build;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.Parcel;
import android.os.ParcelFileDescriptor;
import android.os.Process;
import android.os.RemoteException;
import java.io.File;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;

/** Main-thread owner of one unique isolated process. Never falls back to trusted loading. */
public final class SandboxPluginClient implements AutoCloseable {
    public interface Callback { void completed(boolean success, String output, int workerUid, int workerPid); }
    private final Context context;
    private final Handler main = new Handler(Looper.getMainLooper());
    private final AtomicBoolean responseAccepted = new AtomicBoolean();
    private final Callback callback;
    private final File binary, plugin;
    private final String command, arguments, architecture;
    private final long base, entry, timeoutMs;
    private final boolean slice;
    private volatile int peerUid = -1, peerPid = -1;
    private boolean bound, finished;
    private final Runnable timeout = () -> finish(false, "Isolated plugin timed out; worker disconnected");

    /** plugin must be a disposable, read-only copy; this object deletes it on completion/cancellation. */
    public SandboxPluginClient(Context context, File binary, File plugin, String command, String arguments,
                               String architecture, long base, long entry, boolean slice, long timeoutMs, Callback callback) {
        if (Looper.myLooper() != Looper.getMainLooper()) throw new IllegalStateException("Use main thread");
        if (binary == null || plugin == null || callback == null || command == null || command.isEmpty() || command.length() > 160 ||
                arguments == null || arguments.length() > 4096 || architecture == null || architecture.length() > 64 ||
                command.indexOf('\0') >= 0 || arguments.indexOf('\0') >= 0 || architecture.indexOf('\0') >= 0 || timeoutMs < 100 || timeoutMs > 120000)
            throw new IllegalArgumentException("Invalid isolated request");
        this.context = context.getApplicationContext(); this.binary = binary; this.plugin = plugin; this.command = command; this.arguments = arguments;
        this.architecture = architecture; this.base = base; this.entry = entry; this.slice = slice; this.timeoutMs = timeoutMs; this.callback = callback;
    }

    public void start() {
        if (Looper.myLooper() != Looper.getMainLooper()) throw new IllegalStateException("Use main thread");
        if (finished || bound) throw new IllegalStateException("Worker already used");
        if (Build.VERSION.SDK_INT < 29) { finish(false, "Isolated native commands require Android 10 or newer"); return; }
        try {
            // Unique instance per run, never a shared process or reused plugin address space.
            bound = context.bindIsolatedService(new Intent(context, SandboxPluginService.class),
                    Context.BIND_AUTO_CREATE | Context.BIND_NOT_FOREGROUND,
                    "mint_" + UUID.randomUUID().toString().replace("-", ""), context.getMainExecutor(), connection);
            if (!bound) { finish(false, "Cannot bind isolated plugin worker"); return; }
            main.postDelayed(timeout, timeoutMs);
        } catch (RuntimeException error) { finish(false, "Cannot start isolated worker: " + error.getMessage()); }
    }

    private final Binder receiver = new Binder() {
        @Override protected boolean onTransact(int code, Parcel data, Parcel reply, int flags) {
            // Gate on the Binder thread before parsing or posting to the UI:
            // hostile repeated results cannot fill the application's main queue.
            if (code != SandboxProtocol.DELIVER || Binder.getCallingUid() != peerUid || !responseAccepted.compareAndSet(false, true)) return false;
            boolean success = false; String output = "Rejected malformed isolated result";
            if (data.dataSize() <= SandboxProtocol.MAX_RESPONSE_BYTES) try {
                data.enforceInterface(SandboxProtocol.RESULT); success = data.readInt() == 1; output = data.readString();
                if (output == null || output.length() > SandboxProtocol.MAX_RESULT_CHARS || data.dataAvail() != 0) { success = false; output = "Rejected oversized isolated result"; }
            } catch (RuntimeException error) { success = false; output = "Rejected invalid isolated result"; }
            final boolean result = success; final String text = output;
            main.post(() -> finish(result, text)); return true;
        }
    };

    private final ServiceConnection connection = new ServiceConnection() {
        @Override public void onServiceConnected(ComponentName name, IBinder remote) {
            if (finished) return;
            Parcel request = Parcel.obtain(), response = Parcel.obtain();
            try {
                // This handshake runs before any native plugin/runtime is loaded.
                request.writeInterfaceToken(SandboxProtocol.SERVICE);
                if (!remote.transact(SandboxProtocol.HELLO, request, response, 0) || response.readInt() != SandboxProtocol.VERSION) throw new SecurityException("Invalid worker handshake");
                peerUid = response.readInt(); peerPid = response.readInt();
                if (peerUid == Process.myUid() || peerUid < 0 || peerPid <= 0 || peerPid == Process.myPid() || response.dataAvail() != 0)
                    throw new SecurityException("Plugin worker is not a separate isolated process");
                request.recycle(); request = Parcel.obtain();
                request.writeInterfaceToken(SandboxProtocol.SERVICE); request.writeStrongBinder(receiver); request.writeInt(SandboxProtocol.VERSION);
                try (ParcelFileDescriptor input = ParcelFileDescriptor.open(binary, ParcelFileDescriptor.MODE_READ_ONLY);
                     ParcelFileDescriptor code = ParcelFileDescriptor.open(plugin, ParcelFileDescriptor.MODE_READ_ONLY)) {
                    input.writeToParcel(request, 0); code.writeToParcel(request, 0);
                    request.writeString(command); request.writeString(arguments); request.writeString(architecture);
                    request.writeLong(base); request.writeLong(entry); request.writeInt(slice ? 1 : 0);
                    if (request.dataSize() > SandboxProtocol.MAX_REQUEST_BYTES || !remote.transact(SandboxProtocol.RUN, request, null, IBinder.FLAG_ONEWAY))
                        throw new SecurityException("Isolated worker rejected request");
                }
            } catch (Exception error) { finish(false, "Isolated worker unavailable: " + error.getMessage()); }
            finally { request.recycle(); response.recycle(); }
        }
        @Override public void onServiceDisconnected(ComponentName name) { finish(false, "Isolated plugin worker exited or crashed"); }
        @Override public void onBindingDied(ComponentName name) { finish(false, "Isolated plugin binding died"); }
        @Override public void onNullBinding(ComponentName name) { finish(false, "Platform did not provide an isolated worker"); }
    };

    private void finish(boolean success, String output) {
        if (finished) return;
        finished = true; responseAccepted.set(true); main.removeCallbacks(timeout);
        if (bound) { bound = false; try { context.unbindService(connection); } catch (RuntimeException ignored) { } }
        plugin.delete(); callback.completed(success, output, peerUid, peerPid);
    }

    @Override public void close() {
        if (Looper.myLooper() != Looper.getMainLooper()) { main.post(this::close); return; }
        finish(false, "Isolated plugin cancelled");
    }
}
