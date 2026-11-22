package com.ccs.mint.ui;

import android.content.Context;
import android.content.SharedPreferences;
import android.net.Uri;

import androidx.annotation.Nullable;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;

/** Each project's private input remains available after its document grant ends. */
final class ProjectStore {
    private static final String INPUT_NAME = "input.bin";
    private static final String LESSON_PREFIX = "lesson-";
    private static final String CLONE_PREFIX = "clone-";

    static final class SavedProject {
        final String id;
        final String name;
        final long modifiedAt;

        SavedProject(String id, String name, long modifiedAt) {
            this.id = id;
            this.name = name;
            this.modifiedAt = modifiedAt;
        }
    }

    static File requirePrivateInput(Context context, File binary) throws IOException {
        File root = projectRoot(context);
        binary = binary.getAbsoluteFile();
        File exact = binary.getCanonicalFile();
        File directory = exact.getParentFile();
        if (!INPUT_NAME.equals(exact.getName()) || !exact.isFile() || directory == null ||
                !root.equals(directory.getParentFile()) ||
                Files.isSymbolicLink(binary.toPath()) ||
                Files.isSymbolicLink(binary.getParentFile().toPath())) {
            throw new IOException("Saved input is not a private Mint project");
        }
        return exact;
    }

    static File findProject(Context context, String id) throws IOException {
        if (id == null || !id.matches("[a-z0-9:_-]{1,255}")) {
            throw new IOException("Invalid project identifier");
        }
        return requirePrivateInput(context, new File(new File(projectRoot(context), id), INPUT_NAME));
    }

    static boolean isLessonProject(String projectId) {
        return projectId != null && projectId.startsWith(LESSON_PREFIX);
    }

    static String lessonProjectId(String id) {
        return LESSON_PREFIX + id;
    }

    static List<SavedProject> savedProjects(Context context) {
        List<SavedProject> projects = new ArrayList<>();
        File[] directories;
        try {
            directories = projectRoot(context).listFiles(File::isDirectory);
        } catch (IOException inaccessible) {
            return projects;
        }
        if (directories == null) return projects;

        for (File directory : directories) {
            String id = directory.getName();
            if (isLessonProject(id)) continue;
            try {
                File binary = findProject(context, id);
                SharedPreferences preferences = context.getSharedPreferences("project-" + id, Context.MODE_PRIVATE);
                String name = preferences.getString("name", null);
                if (name == null || name.trim().isEmpty()) continue;
                long modifiedAt = preferences.getLong("last_opened", binary.lastModified());
                projects.add(new SavedProject(id, name, modifiedAt));
            } catch (IOException | ClassCastException inaccessible) {
                // Incomplete imports and invalid project metadata are not selectable.
            }
        }
        projects.sort(Comparator.comparingLong((SavedProject project) -> project.modifiedAt)
                .reversed().thenComparing(project -> project.id));
        return projects;
    }

    static File importBinary(Context context, Uri uri, AtomicBoolean cancelled) throws Exception {
        return importBinary(context, uri, cancelled, null);
    }

    static File importBinary(Context context, Uri uri, AtomicBoolean cancelled,
                             @Nullable RawImportConfig rawConfig) throws Exception {
        return copyInput(context, () -> context.getContentResolver().openInputStream(uri),
                cancelled, null, mappingSuffix(rawConfig));
    }

    static File importClone(Context context, Uri uri, AtomicBoolean cancelled,
                            @Nullable RawImportConfig rawConfig) throws Exception {
        return copyInput(context, () -> context.getContentResolver().openInputStream(uri),
                cancelled, CLONE_PREFIX + UUID.randomUUID(), mappingSuffix(rawConfig));
    }

    static File importLesson(Context context, String id, String assetPath,
                             AtomicBoolean cancelled) throws Exception {
        if (id == null || !id.matches("[a-z0-9_-]{1,64}")) {
            throw new IOException("Invalid lesson identifier");
        }
        String projectId = lessonProjectId(id);
        File existing = new File(new File(projectRoot(context), projectId), INPUT_NAME);
        checkCancelled(cancelled);
        if (existing.exists()) return requirePrivateInput(context, existing);
        return copyInput(context, () -> context.getAssets().open(assetPath), cancelled, projectId, "");
    }

    private interface InputSource {
        InputStream open() throws IOException;
    }

    private static File copyInput(Context context, InputSource source, AtomicBoolean cancelled,
                                  @Nullable String projectId, String mappingSuffix) throws Exception {
        checkCancelled(cancelled);
        File root = projectRoot(context);
        if (!root.mkdirs() && !root.isDirectory()) throw new IOException("Cannot create projects directory");
        File temporary = File.createTempFile("import-", ".bin", root);
        try {
            MessageDigest digest = projectId == null ? MessageDigest.getInstance("SHA-256") : null;
            try (InputStream input = source.open(); FileOutputStream output = new FileOutputStream(temporary)) {
                if (input == null) throw new IOException("Cannot read binary");
                byte[] buffer = new byte[65536];
                int read;
                while ((read = input.read(buffer)) != -1) {
                    checkCancelled(cancelled);
                    if (read == 0) continue;
                    if (digest != null) digest.update(buffer, 0, read);
                    output.write(buffer, 0, read);
                }
                output.getFD().sync();
            }
            if (digest != null) {
                StringBuilder hash = new StringBuilder();
                for (byte value : digest.digest()) hash.append(String.format(Locale.US, "%02x", value & 255));
                projectId = hash.toString();
            }
            // Identical bytes at different bases or under different ISAs keep separate edits.
            return publishInput(context, root, temporary, projectId + mappingSuffix, cancelled);
        } finally {
            // This temporary belongs to this copy attempt even when the project already exists.
            temporary.delete();
        }
    }

    private static synchronized File publishInput(Context context, File root, File temporary,
                                                  String id, AtomicBoolean cancelled) throws IOException {
        checkCancelled(cancelled);
        File directory = new File(root, id);
        if (Files.isSymbolicLink(directory.toPath()) ||
                (!directory.mkdir() && (id.startsWith(CLONE_PREFIX) || !directory.isDirectory()))) {
            throw new IOException("Cannot create project");
        }
        File binary = new File(directory, INPUT_NAME);
        if (Files.isSymbolicLink(binary.toPath())) throw new IOException("Invalid saved input");
        if (!binary.exists()) Files.move(temporary.toPath(), binary.toPath(), StandardCopyOption.ATOMIC_MOVE);
        return requirePrivateInput(context, binary);
    }

    private static File projectRoot(Context context) throws IOException {
        File root = new File(context.getFilesDir(), "projects");
        if (Files.isSymbolicLink(root.toPath())) throw new IOException("Invalid projects directory");
        return root.getCanonicalFile();
    }

    private static String mappingSuffix(@Nullable RawImportConfig config) {
        return config == null ? "" : config.projectSuffix();
    }

    private static void checkCancelled(AtomicBoolean cancelled) throws IOException {
        if (cancelled.get()) throw new IOException("Import cancelled");
    }

    private ProjectStore() {}
}
