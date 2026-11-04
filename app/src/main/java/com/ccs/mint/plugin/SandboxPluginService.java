package com.ccs.mint.plugin;

import android.app.Service;
import android.content.Intent;
import android.os.Binder;
import android.os.Build;
import android.os.IBinder;
import android.os.Parcel;
import android.os.ParcelFileDescriptor;
import android.os.Process;
import android.os.RemoteException;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructStat;
import com.ccs.mint.core.MintSession;
import java.util.concurrent.atomic.AtomicBoolean;

/** Each bindIsolatedService instance owns exactly one native invocation. */
public final class SandboxPluginService extends Service {
    private final AtomicBoolean used = new AtomicBoolean();

    private static boolean isolated() {
        return Build.VERSION.SDK_INT >= 29 && Process.isIsolated();
    }

    @Override public IBinder onBind(Intent intent) {
        // Fail before loading the native runtime if the manifest/platform is wrong.
        return isolated() ? endpoint : null;
    }

    private final Binder endpoint = new Binder() {
        @Override protected boolean onTransact(int code, Parcel data, Parcel reply, int flags) throws RemoteException {
            if (!isolated() || data.dataSize() > SandboxProtocol.MAX_REQUEST_BYTES) return false;
            data.enforceInterface(SandboxProtocol.SERVICE);
            if (code == SandboxProtocol.HELLO && !used.get() && reply != null) {
                reply.writeInt(SandboxProtocol.VERSION);
                reply.writeInt(Process.myUid());
                reply.writeInt(Process.myPid());
                return true;
            }
            if (code != SandboxProtocol.RUN || !used.compareAndSet(false, true)) return false;
            IBinder callback = null;
            ParcelFileDescriptor input = null, plugin = null;
            try {
                callback = data.readStrongBinder();
                if (callback == null || data.readInt() != SandboxProtocol.VERSION) throw new IllegalArgumentException("Invalid worker protocol");
                input = ParcelFileDescriptor.CREATOR.createFromParcel(data);
                plugin = ParcelFileDescriptor.CREATOR.createFromParcel(data);
                final String command = data.readString(), arguments = data.readString(), architecture = data.readString();
                final long base = data.readLong(), entry = data.readLong();
                final boolean slice = data.readInt() != 0;
                if (data.dataAvail() != 0 || command == null || command.isEmpty() || command.length() > 160 || arguments == null || arguments.length() > 4096 ||
                        command.indexOf('\0') >= 0 || arguments.indexOf('\0') >= 0 || architecture == null || architecture.length() > 64 || architecture.indexOf('\0') >= 0)
                    throw new IllegalArgumentException("Invalid isolated command request");
                final ParcelFileDescriptor binaryFd = input, pluginFd = plugin;
                final IBinder response = callback;
                new Thread(() -> execute(binaryFd, pluginFd, command, arguments, architecture, base, entry, slice, response), "Mint isolated plugin").start();
                input = plugin = null; // Ownership transferred to worker.
            } catch (RuntimeException error) {
                deliver(callback, false, "Rejected isolated request: " + error.getMessage());
            } finally {
                close(input); close(plugin);
            }
            return true;
        }
    };

    private static void checkDescriptor(ParcelFileDescriptor descriptor, long maximum) throws Exception {
        if (descriptor == null) throw new IllegalArgumentException("Missing read-only descriptor");
        StructStat info = Os.fstat(descriptor.getFileDescriptor());
        int mode = Os.fcntlInt(descriptor.getFileDescriptor(), OsConstants.F_GETFL, 0);
        if (!OsConstants.S_ISREG(info.st_mode) || info.st_size <= 0 || info.st_size > maximum || (mode & OsConstants.O_ACCMODE) != OsConstants.O_RDONLY)
            throw new IllegalArgumentException("Worker accepts bounded, regular read-only files only");
    }

    private void execute(ParcelFileDescriptor input, ParcelFileDescriptor plugin, String command, String arguments,
                         String architecture, long base, long entry, boolean slice, IBinder callback) {
        try {
            checkDescriptor(input, 512L * 1024 * 1024);
            checkDescriptor(plugin, 16L * 1024 * 1024);
            if (!isolated()) throw new SecurityException("Worker is not isolated");
            final String path = "/proc/self/fd/" + input.getFd();
            try (MintSession session = architecture.isEmpty() ? MintSession.openDescriptor(input.getFd()) :
                    slice ? MintSession.openMachO(path, architecture) : MintSession.openRaw(path, architecture, base, entry)) {
                session.analyze();
                session.loadPluginDescriptor(plugin.getFd());
                deliver(callback, true, session.runPlugin(command, arguments, false));
            }
        } catch (Exception | LinkageError error) {
            deliver(callback, false, "Isolated plugin failed: " + error.getMessage());
        } finally {
            close(input); close(plugin);
        }
    }

    private static void close(ParcelFileDescriptor descriptor) {
        if (descriptor != null) try { descriptor.close(); } catch (Exception ignored) { }
    }

    private static void deliver(IBinder callback, boolean success, String text) {
        if (callback == null) return;
        if (text == null) text = "No plugin output";
        if (text.length() > SandboxProtocol.MAX_RESULT_CHARS) text = text.substring(0, SandboxProtocol.MAX_RESULT_CHARS - 48) + "\n[isolated output truncated]";
        Parcel result = Parcel.obtain();
        try {
            result.writeInterfaceToken(SandboxProtocol.RESULT);
            result.writeInt(success ? 1 : 0); result.writeString(text);
            callback.transact(SandboxProtocol.DELIVER, result, null, IBinder.FLAG_ONEWAY);
        } catch (RemoteException | RuntimeException ignored) { }
        finally { result.recycle(); }
    }

    @Override public void onDestroy() {
        super.onDestroy();
        // Bound-only, single-use worker: no plugin threads survive a normal unbind.
        if (isolated()) Process.killProcess(Process.myPid());
    }
}
