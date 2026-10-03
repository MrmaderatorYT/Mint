package com.ccs.mint.ui;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

/** Portable authoritative project backup, never native code or an analysis cache.
 * Import is staged, integrity checked, optionally validated by the native engine,
 * and published as a new project; an existing project is never overwritten. */
public final class ProjectArchive {
    static final long MAX_BINARY = 512L * 1024 * 1024;
    static final long MAX_PROGRAM = 16L * 1024 * 1024;
    static final long MAX_DEBUG = 128L * 1024 * 1024;
    private static final int MAX_MANIFEST = 16384;

    public static final class Metadata {
        public final String name;
        public final RawImportConfig raw;
        public final long selected, listing;
        public final int pane;
        public Metadata(String name, RawImportConfig raw, long selected, long listing, int pane) {
            if (name == null || name.indexOf('\0') >= 0 || name.getBytes(StandardCharsets.UTF_8).length > 4096 || pane < 0 || pane > 15)
                throw new IllegalArgumentException("Invalid project metadata");
            this.name = name; this.raw = raw; this.selected = selected; this.listing = listing; this.pane = pane;
        }
    }

    public static final class Restored {
        public final File binary;
        public final Metadata metadata;
        private Restored(File binary, Metadata metadata) { this.binary = binary; this.metadata = metadata; }
    }

    public interface Validator { void validate(File directory, Metadata metadata) throws Exception; }

    private static void cancelled(AtomicBoolean cancel) throws IOException {
        if (cancel != null && cancel.get()) throw new IOException("Project transfer cancelled");
    }

    private static MessageDigest digest() {
        try { return MessageDigest.getInstance("SHA-256"); }
        catch (NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
    }

    private static String hex(byte[] bytes) {
        StringBuilder text = new StringBuilder();
        for (byte value : bytes) text.append(String.format(java.util.Locale.ROOT, "%02x", value & 255));
        return text.toString();
    }

    private static File ownedFile(File directory, String name, long limit) throws IOException {
        File file = new File(directory, name);
        if (!Files.isRegularFile(file.toPath(), LinkOption.NOFOLLOW_LINKS) || file.length() > limit ||
                !file.getCanonicalFile().getParentFile().equals(directory.getCanonicalFile()))
            throw new IOException("Missing, oversized or non-regular project file: " + name);
        return file;
    }

    private static String checksum(File file, AtomicBoolean cancel) throws IOException {
        MessageDigest hash = digest();
        try (InputStream input = new FileInputStream(file)) {
            byte[] buffer = new byte[65536]; int count;
            while ((count = input.read(buffer)) != -1) { cancelled(cancel); if (count != 0) hash.update(buffer, 0, count); }
        }
        return hex(hash.digest());
    }

    private static void appendEntry(ZipOutputStream zip, String name, File file, long limit,
                                    String expectedHash, AtomicBoolean cancel) throws IOException {
        zip.putNextEntry(new ZipEntry(name));
        MessageDigest hash = digest(); long total = 0;
        try (InputStream input = new FileInputStream(file)) {
            byte[] buffer = new byte[65536]; int count;
            while ((count = input.read(buffer)) != -1) {
                cancelled(cancel); if (count == 0) continue;
                total += count; if (total > limit) throw new IOException("Project file grew beyond transfer limit");
                hash.update(buffer, 0, count); zip.write(buffer, 0, count);
            }
        }
        if (!hex(hash.digest()).equals(expectedHash)) throw new IOException("Project changed during backup; retry after edits finish");
        zip.closeEntry();
    }

    public static void write(OutputStream destination, File directory, Metadata metadata,
                             AtomicBoolean cancel) throws IOException {
        File binary = ownedFile(directory, "input.bin", MAX_BINARY);
        File program = ownedFile(directory, "program.mint", MAX_PROGRAM);
        String binaryHash = checksum(binary, cancel), programHash = checksum(program, cancel);
        File debugMetadata=null,debugBinary=null;String metadataHash="",debugHash="";
        if(Files.exists(new File(directory,"program.mint.debug").toPath(),LinkOption.NOFOLLOW_LINKS)) {
            debugMetadata=ownedFile(directory,"program.mint.debug",256);
            String[] binding=debugBinding(new String(Files.readAllBytes(debugMetadata.toPath()),StandardCharsets.US_ASCII));
            if(!binding[0].equals(binaryHash))throw new IOException("External debug source binding mismatch");
            debugBinary=ownedFile(directory,"program.mint.debug."+binding[1]+".bin",MAX_DEBUG);
            debugHash=checksum(debugBinary,cancel);if(!debugHash.equals(binding[1]))throw new IOException("External debug checksum mismatch");
            metadataHash=checksum(debugMetadata,cancel);
        }
        String manifest = "MINT_PROJECT 1\n" +
                "binary-sha256=" + binaryHash + "\nbinary-size=" + binary.length() +
                "\nprogram-sha256=" + programHash + "\nprogram-size=" + program.length() +
                "\nname=" + Base64.getEncoder().encodeToString(metadata.name.getBytes(StandardCharsets.UTF_8)) +
                "\nraw=" + (metadata.raw == null ? "" : metadata.raw.architecture) +
                "\nbase=" + Long.toUnsignedString(metadata.raw == null ? 0 : metadata.raw.baseAddress, 16) +
                "\nentry=" + Long.toUnsignedString(metadata.raw == null ? 0 : metadata.raw.entryAddress, 16) +
                "\nselected=" + Long.toUnsignedString(metadata.selected, 16) +
                "\nlisting=" + Long.toUnsignedString(metadata.listing, 16) + "\npane=" + metadata.pane + "\n";
        if(debugMetadata!=null)manifest+="debug-metadata-sha256="+metadataHash+"\ndebug-metadata-size="+debugMetadata.length()+"\ndebug-sha256="+debugHash+"\ndebug-size="+debugBinary.length()+"\n";
        try (ZipOutputStream zip = new ZipOutputStream(destination)) {
            zip.putNextEntry(new ZipEntry("manifest.mint"));
            zip.write(manifest.getBytes(StandardCharsets.UTF_8)); zip.closeEntry();
            appendEntry(zip, "input.bin", binary, MAX_BINARY, binaryHash, cancel);
            appendEntry(zip, "program.mint", program, MAX_PROGRAM, programHash, cancel);
            if(debugMetadata!=null){appendEntry(zip,"debug.metadata",debugMetadata,256,metadataHash,cancel);appendEntry(zip,"external-debug.bin",debugBinary,MAX_DEBUG,debugHash,cancel);}
            cancelled(cancel); zip.finish();
        }
    }

    private static String[] parse(String manifest) throws IOException {
        if (manifest.indexOf('\0') >= 0 || !manifest.startsWith("MINT_PROJECT 1\n")) throw new IOException("Unsupported project archive version");
        String[] keys = {"binary-sha256", "binary-size", "program-sha256", "program-size", "name", "raw", "base", "entry", "selected", "listing", "pane","debug-metadata-sha256","debug-metadata-size","debug-sha256","debug-size"};
        String[] values = new String[keys.length]; Set<String> seen = new HashSet<>();
        String[] lines = manifest.split("\n", -1);
        for (int line = 1; line < lines.length; line++) {
            if (line == lines.length - 1 && lines[line].isEmpty()) continue;
            int separator = lines[line].indexOf('=');
            if (separator < 0) throw new IOException("Malformed project manifest");
            String key = lines[line].substring(0, separator); int index = -1;
            for (int i = 0; i < keys.length; i++) if (keys[i].equals(key)) index = i;
            if (index < 0 || !seen.add(key)) throw new IOException("Unknown or duplicate project metadata");
            values[index] = lines[line].substring(separator + 1);
        }
        for(int i=0;i<11;i++)if(values[i]==null)throw new IOException("Missing project metadata");
        if ((seen.size()!=11 && seen.size()!=15) || !values[0].matches("[0-9a-f]{64}") || !values[2].matches("[0-9a-f]{64}") ||
                (seen.size()==15 && (values[11]==null || values[12]==null || values[13]==null || values[14]==null || !values[11].matches("[0-9a-f]{64}") || !values[13].matches("[0-9a-f]{64}"))))
            throw new IOException("Missing project metadata/checksums");
        return values;
    }
    private static String[] debugBinding(String metadata) throws IOException {
        String[] lines=metadata.split("\n",-1);
        if(lines.length!=5 || !lines[0].equals("MINT_DEBUG 1") || !lines[1].matches("[0-9a-f]{64}") || !lines[2].matches("[0-9a-f]{64}") ||
                (!lines[3].equals("0") && !lines[3].equals("1")) || !lines[4].isEmpty())throw new IOException("Malformed external debug binding");
        return new String[]{lines[1],lines[2]};
    }

    private static long address(String value) {
        if (!value.matches("[0-9a-f]{1,16}")) throw new IllegalArgumentException("Invalid project address");
        return Long.parseUnsignedLong(value, 16);
    }

    private static Metadata metadata(String[] values) throws IOException {
        try {
            long base = address(values[6]), entry = address(values[7]);
            if (values[5].isEmpty() && (base != 0 || entry != 0)) throw new IllegalArgumentException("Non-raw project contains raw addresses");
            RawImportConfig raw = values[5].isEmpty() ? null : new RawImportConfig(values[5], base, entry);
            byte[] name = Base64.getDecoder().decode(values[4]);
            String decoded = new String(name, StandardCharsets.UTF_8);
            if (!java.util.Arrays.equals(name, decoded.getBytes(StandardCharsets.UTF_8))) throw new IllegalArgumentException("Invalid UTF-8 name");
            return new Metadata(decoded, raw, address(values[8]), address(values[9]), Integer.parseInt(values[10]));
        } catch (IllegalArgumentException error) { throw new IOException("Invalid project configuration: " + error.getMessage(), error); }
    }

    public static Restored restore(InputStream source, File projects, AtomicBoolean cancel,
                                    Validator validator) throws Exception {
        if (!projects.isDirectory() && !projects.mkdirs()) throw new IOException("Cannot create project storage");
        if (Files.isSymbolicLink(projects.toPath())) throw new IOException("Project storage must not be a symbolic link");
        Path stage = Files.createTempDirectory(projects.toPath(), "import-project-"); boolean published = false;String restoredDebugName=null;
        try {
            byte[] manifest = null; Set<String> entries = new HashSet<>();
            try (ZipInputStream zip = new ZipInputStream(source)) {
                ZipEntry entry;
                while ((entry = zip.getNextEntry()) != null) {
                    cancelled(cancel); String name = entry.getName(); long limit;
                    if (entry.isDirectory() || !entries.add(name)) throw new IOException("Duplicate/directory archive entry");
                    if (name.equals("manifest.mint")) limit = MAX_MANIFEST;
                    else if (name.equals("input.bin")) limit = MAX_BINARY;
                    else if (name.equals("program.mint")) limit = MAX_PROGRAM;
                    else if(name.equals("debug.metadata"))limit=256;
                    else if(name.equals("external-debug.bin"))limit=MAX_DEBUG;
                    else throw new IOException("Unexpected project archive entry: " + name);
                    if (entry.getSize() > limit) throw new IOException("Archive entry exceeds limit");
                    ByteArrayOutputStream text = name.equals("manifest.mint") ? new ByteArrayOutputStream() : null;
                    try (OutputStream output = text != null ? text : new FileOutputStream(stage.resolve(name).toFile())) {
                        byte[] buffer = new byte[65536]; long total = 0; int count;
                        while ((count = zip.read(buffer)) != -1) {
                            cancelled(cancel); if (count == 0) continue;
                            total += count; if (total > limit) throw new IOException("Archive entry exceeds decompressed limit");
                            output.write(buffer, 0, count);
                        }
                        if (output instanceof FileOutputStream) ((FileOutputStream) output).getFD().sync();
                    }
                    if (text != null) manifest = text.toByteArray();
                    zip.closeEntry();
                }
            }
            if (manifest == null || (entries.size() != 3 && entries.size()!=5)) throw new IOException("Incomplete project archive");
            String[] values = parse(new String(manifest, StandardCharsets.UTF_8));
            Metadata metadata = metadata(values);
            File binary = ownedFile(stage.toFile(), "input.bin", MAX_BINARY), program = ownedFile(stage.toFile(), "program.mint", MAX_PROGRAM);
            try {
                if (Long.parseLong(values[1]) != binary.length() || Long.parseLong(values[3]) != program.length())
                    throw new IOException("Project size mismatch");
            } catch (NumberFormatException invalid) { throw new IOException("Invalid project size", invalid); }
            if (!values[0].equals(checksum(binary, cancel)) || !values[2].equals(checksum(program, cancel)))
                throw new IOException("Project checksum mismatch");
            if((values[11]!=null)!=(entries.size()==5))throw new IOException("External debug archive metadata mismatch");
            if(values[11]!=null) {
                File binding=ownedFile(stage.toFile(),"debug.metadata",256),debug=ownedFile(stage.toFile(),"external-debug.bin",MAX_DEBUG);
                try{if(Long.parseLong(values[12])!=binding.length() || Long.parseLong(values[14])!=debug.length())throw new IOException("External debug size mismatch");}
                catch(NumberFormatException invalid){throw new IOException("Invalid external debug size",invalid);}
                if(!values[11].equals(checksum(binding,cancel)) || !values[13].equals(checksum(debug,cancel)))throw new IOException("External debug archive checksum mismatch");
                String[] identity=debugBinding(new String(Files.readAllBytes(binding.toPath()),StandardCharsets.US_ASCII));
                if(!identity[0].equals(values[0]) || !identity[1].equals(values[13]))throw new IOException("External debug identity mismatch");
                restoredDebugName="program.mint.debug."+identity[1]+".bin";
                Files.move(debug.toPath(),stage.resolve(restoredDebugName));Files.move(binding.toPath(),stage.resolve("program.mint.debug"));
            }
            cancelled(cancel);
            if (validator != null) validator.validate(stage.toFile(), metadata);
            cancelled(cancel);
            Path destination = projects.toPath().resolve(values[0] + "-restored-" + UUID.randomUUID() +
                    (metadata.raw == null ? "" : metadata.raw.projectSuffix()));
            // No REPLACE_EXISTING: importing a backup must never destroy live edits.
            Files.move(stage, destination, StandardCopyOption.ATOMIC_MOVE);
            published = true;
            return new Restored(destination.resolve("input.bin").toFile(), metadata);
        } finally {
            if (!published) {
                // These are the only files we create in the exact owned staging directory.
                for (String name : new String[]{"input.bin", "program.mint","debug.metadata","external-debug.bin","program.mint.debug"}) Files.deleteIfExists(stage.resolve(name));
                if(restoredDebugName!=null)Files.deleteIfExists(stage.resolve(restoredDebugName));
                Files.deleteIfExists(stage);
            }
        }
    }

    private ProjectArchive() {}
}
