package com.ccs.mint.ui;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

import static org.junit.Assert.*;

public class ProjectArchiveTest {
    private Path directory, project, restored;
    @Before public void before() throws Exception {
        directory = Files.createTempDirectory("mint-archive-unit-");
        project = Files.createDirectory(directory.resolve("source"));
        restored = Files.createDirectory(directory.resolve("restored"));
        Files.write(project.resolve("input.bin"), new byte[]{1, 2, 3, 4});
        Files.write(project.resolve("program.mint"), "MINTPR03 annotations".getBytes(StandardCharsets.UTF_8));
    }
    @After public void after() throws Exception {
        try (Stream<Path> files = Files.walk(directory)) {
            for (Path path : (Iterable<Path>) files.sorted(Comparator.reverseOrder())::iterator) Files.delete(path);
        }
    }
    private byte[] archive(ProjectArchive.Metadata metadata) throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        ProjectArchive.write(bytes, project.toFile(), metadata, new AtomicBoolean());
        return bytes.toByteArray();
    }
    private ProjectArchive.Metadata metadata() { return new ProjectArchive.Metadata("Проєкт ☘", null, -1, Long.MIN_VALUE, 2); }
    private byte[] changed(byte[] source, String name, byte[] replacement) throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ZipInputStream input = new ZipInputStream(new ByteArrayInputStream(source)); ZipOutputStream output = new ZipOutputStream(bytes)) {
            ZipEntry entry;
            while ((entry = input.getNextEntry()) != null) {
                output.putNextEntry(new ZipEntry(entry.getName()));
                if (entry.getName().equals(name)) output.write(replacement);
                else { byte[] buffer = new byte[4096]; int count; while ((count = input.read(buffer)) != -1) output.write(buffer, 0, count); }
                output.closeEntry(); input.closeEntry();
            }
        }
        return bytes.toByteArray();
    }
    private void rejects(byte[] bytes) throws Exception {
        try { ProjectArchive.restore(new ByteArrayInputStream(bytes), restored.toFile(), new AtomicBoolean(), null); fail("invalid archive accepted"); }
        catch (IOException expected) { assertNotNull(expected.getMessage()); }
        try (Stream<Path> paths = Files.list(restored)) { assertEquals(0, paths.count()); }
    }
    @Test public void roundTripPreservesAllAuthoritativeBytesAndNavigation() throws Exception {
        byte[] bytes = archive(metadata());
        ProjectArchive.Restored result = ProjectArchive.restore(new ByteArrayInputStream(bytes), restored.toFile(), new AtomicBoolean(), (files, meta) -> {
            assertTrue(new File(files, "program.mint").isFile()); assertEquals("Проєкт ☘", meta.name);
        });
        assertEquals(-1, result.metadata.selected); assertEquals(Long.MIN_VALUE, result.metadata.listing); assertEquals(2, result.metadata.pane);
        assertArrayEquals(Files.readAllBytes(project.resolve("input.bin")), Files.readAllBytes(result.binary.toPath()));
        assertArrayEquals(Files.readAllBytes(project.resolve("program.mint")), Files.readAllBytes(result.binary.toPath().getParent().resolve("program.mint")));
    }
    @Test public void rawMappingPreservesExactUnsignedAddresses() throws Exception {
        RawImportConfig raw = new RawImportConfig("x86-64", Long.MIN_VALUE, Long.MIN_VALUE + 1);
        ProjectArchive.Restored result = ProjectArchive.restore(new ByteArrayInputStream(archive(new ProjectArchive.Metadata("raw", raw, 0, 0, 0))), restored.toFile(), null, null);
        assertEquals(raw.architecture, result.metadata.raw.architecture); assertEquals(raw.baseAddress, result.metadata.raw.baseAddress);
        assertTrue(result.binary.getParentFile().getName().endsWith(raw.projectSuffix()));
    }
    @Test public void explicitMachOSliceSelectionSurvivesBackup()throws Exception {
        RawImportConfig slice=RawImportConfig.machOSlice("x86-64");ProjectArchive.Restored result=ProjectArchive.restore(new ByteArrayInputStream(archive(new ProjectArchive.Metadata("fat slice",slice,1,1,0))),restored.toFile(),null,null);
        assertTrue(result.metadata.raw.machOSlice);assertEquals("x86-64",result.metadata.raw.decoderId());assertTrue(result.binary.getParentFile().getName().endsWith("-macho-x86-64"));
    }
    @Test public void repeatedImportNeverOverwritesExistingProject() throws Exception {
        byte[] bytes = archive(metadata());
        ProjectArchive.Restored first = ProjectArchive.restore(new ByteArrayInputStream(bytes), restored.toFile(), null, null);
        Files.write(first.binary.toPath().getParent().resolve("program.mint"), new byte[]{42});
        ProjectArchive.Restored second = ProjectArchive.restore(new ByteArrayInputStream(bytes), restored.toFile(), null, null);
        assertNotEquals(first.binary.getParent(), second.binary.getParent());
        assertArrayEquals(new byte[]{42}, Files.readAllBytes(first.binary.toPath().getParent().resolve("program.mint")));
    }
    @Test public void modifiedBinaryChecksumRejected() throws Exception { rejects(changed(archive(metadata()), "input.bin", new byte[]{9, 2, 3, 4})); }
    @Test public void modifiedProgramChecksumRejected() throws Exception { rejects(changed(archive(metadata()), "program.mint", new byte[]{9})); }
    @Test public void nativeValidationFailurePublishesNothing() throws Exception {
        try { ProjectArchive.restore(new ByteArrayInputStream(archive(metadata())), restored.toFile(), null, (files, meta) -> { throw new IOException("native Program rejected"); }); fail(); }
        catch (IOException expected) { assertEquals("native Program rejected", expected.getMessage()); }
        try (Stream<Path> paths = Files.list(restored)) { assertEquals(0, paths.count()); }
    }
    @Test public void pathTraversalEntryRejectedWithoutWritingOutsideStage() throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(bytes)) { zip.putNextEntry(new ZipEntry("../escape")); zip.write(7); zip.closeEntry(); }
        rejects(bytes.toByteArray()); assertFalse(Files.exists(directory.resolve("escape")));
    }
    @Test public void unexpectedExecutableEntryRejected() throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(bytes)) { zip.putNextEntry(new ZipEntry("plugin.so")); zip.write(7); zip.closeEntry(); }
        rejects(bytes.toByteArray());
    }
    @Test public void oversizedManifestRejected() throws Exception { rejects(changed(archive(metadata()), "manifest.mint", new byte[16385])); }
    @Test public void incompleteArchiveRejected() throws Exception { rejects(new byte[]{1, 2, 3}); }
    @Test public void cancellationPublishesNothing() throws Exception {
        try { ProjectArchive.restore(new ByteArrayInputStream(archive(metadata())), restored.toFile(), new AtomicBoolean(true), null); fail(); }
        catch (IOException expected) { assertTrue(expected.getMessage().contains("cancelled")); }
        try (Stream<Path> paths = Files.list(restored)) { assertEquals(0, paths.count()); }
    }
    @Test public void symbolicProjectInputsRejected() throws Exception {
        Files.delete(project.resolve("input.bin")); Files.createSymbolicLink(project.resolve("input.bin"), project.resolve("program.mint"));
        try { archive(metadata()); fail(); } catch (IOException expected) { assertTrue(expected.getMessage().contains("non-regular")); }
    }
    private String sha(byte[] bytes)throws Exception {
        StringBuilder out=new StringBuilder();for(byte value:java.security.MessageDigest.getInstance("SHA-256").digest(bytes))out.append(String.format(java.util.Locale.ROOT,"%02x",value&255));return out.toString();
    }
    private String addDebug()throws Exception {
        byte[] bytes={5,6,7,8};String hash=sha(bytes);
        Files.write(project.resolve("program.mint.debug."+hash+".bin"),bytes);
        Files.write(project.resolve("program.mint.debug"),("MINT_DEBUG 1\n"+sha(Files.readAllBytes(project.resolve("input.bin")))+"\n"+hash+"\n0\n").getBytes(StandardCharsets.US_ASCII));return hash;
    }
    @Test public void externalDebugSurvivesArchiveAndNativeValidation()throws Exception {
        String hash=addDebug();ProjectArchive.Restored result=ProjectArchive.restore(new ByteArrayInputStream(archive(metadata())),restored.toFile(),null,(files,meta)->{
            assertTrue(new File(files,"program.mint.debug").isFile());assertArrayEquals(new byte[]{5,6,7,8},Files.readAllBytes(new File(files,"program.mint.debug."+hash+".bin").toPath()));
        });assertTrue(new File(result.binary.getParentFile(),"program.mint.debug").isFile());
    }
    @Test public void modifiedExternalDebugPublishesNothing()throws Exception {addDebug();rejects(changed(archive(metadata()),"external-debug.bin",new byte[]{9}));}
    @Test public void modifiedDebugBindingPublishesNothing()throws Exception {addDebug();rejects(changed(archive(metadata()),"debug.metadata",new byte[]{9}));}
    @Test public void mismatchedExternalDebugSourceCannotBeExported()throws Exception {
        addDebug();Files.write(project.resolve("input.bin"),new byte[]{9});try{archive(metadata());fail();}catch(IOException expected){assertTrue(expected.getMessage().contains("binding mismatch"));}
    }
}
