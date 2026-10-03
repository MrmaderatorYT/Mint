package com.ccs.mint.ui;

import android.content.Context;
import android.net.Uri;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.util.concurrent.atomic.AtomicBoolean;

/** A content-addressed private copy makes a project independent of SAF grants. */
final class ProjectStore {
    static File requirePrivateInput(Context context, File binary) throws IOException {
        File root = new File(context.getFilesDir(), "projects").getCanonicalFile();
        File exact = binary.getCanonicalFile();
        if (!"input.bin".equals(exact.getName()) || !exact.isFile() ||
                !root.equals(exact.getParentFile().getParentFile()) ||
                java.nio.file.Files.isSymbolicLink(binary.toPath()) ||
                java.nio.file.Files.isSymbolicLink(binary.getParentFile().toPath()))
            throw new IOException("Saved input is not a private Mint project");
        return exact;
    }
    static File importBinary(Context context, Uri uri, AtomicBoolean cancelled) throws Exception {
        return importBinary(context, uri, cancelled, null);
    }

    static File importBinary(Context context, Uri uri, AtomicBoolean cancelled,
                             RawImportConfig rawConfig) throws Exception {
        File root = new File(context.getFilesDir(), "projects");
        if (!root.isDirectory() && !root.mkdirs()) throw new IOException("cannot create projects directory");
        File temporary = File.createTempFile("import-", ".bin", root);
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            try (InputStream input = context.getContentResolver().openInputStream(uri);
                 FileOutputStream output = new FileOutputStream(temporary)) {
                if (input == null) throw new IOException("cannot read binary");
                byte[] buffer = new byte[65536]; int got;
                while ((got = input.read(buffer)) != -1) {
                    if (cancelled.get()) throw new IOException("import cancelled");
                    if (got == 0) continue;
                    digest.update(buffer, 0, got); output.write(buffer, 0, got);
                }
                output.getFD().sync();
            }
            StringBuilder hash = new StringBuilder();
            for (byte b : digest.digest()) hash.append(String.format(java.util.Locale.US,"%02x",b & 255));
            if (cancelled.get()) throw new IOException("import cancelled");
            // One input can be loaded at different bases or under different
            // ISAs. Those are separate Programs, not shared annotations.
            File directory = new File(root,hash + (rawConfig == null ? "" : rawConfig.projectSuffix()));
            if (!directory.isDirectory() && !directory.mkdir()) throw new IOException("cannot create project");
            File binary = new File(directory,"input.bin");
            if (!binary.exists() && !temporary.renameTo(binary)) throw new IOException("cannot commit binary import");
            return binary;
        } finally {
            // Only the owned import temporary is removed, never an existing project.
            if (temporary.exists()) temporary.delete();
        }
    }
    private ProjectStore() {}
}
