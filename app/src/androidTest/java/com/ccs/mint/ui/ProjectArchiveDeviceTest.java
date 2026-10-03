package com.ccs.mint.ui;

import android.content.Context;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import com.ccs.mint.core.MintSession;
import org.junit.Test;
import org.junit.runner.RunWith;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Comparator;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Stream;
import static org.junit.Assert.*;

/** Real JNI/archive/device integration, restricted to a newly owned cache tree.
 * Never imports/removes the user's projects or changes their restore selection. */
@RunWith(AndroidJUnit4.class)
public class ProjectArchiveDeviceTest {
    private static void cleanup(Path directory)throws Exception{
        try(Stream<Path> files=Files.walk(directory)){for(Path path:(Iterable<Path>)files.sorted(Comparator.reverseOrder())::iterator)Files.deleteIfExists(path);}
    }
    private static long firstFunction(MintSession session){
        long[] entries=new long[1];assertEquals(1,session.functions(0,1,entries,new int[1],new int[1],new int[1],new int[1],new String[1]));return entries[0];
    }
    private static void validate(Path directory,ProjectArchive.Metadata metadata)throws Exception{
        try(MintSession nativeProgram=metadata.raw==null?MintSession.open(directory.resolve("input.bin").toString()):metadata.raw.open(directory.resolve("input.bin").toString())){
            // Source binding and authoritative Program validation do not need
            // analysis; avoid publishing a derived cache into an import stage.
            nativeProgram.attachProject(directory.resolve("program.mint").toString());
        }
    }
    private static void putName(byte[] bytes,int at,String value){byte[] text=value.getBytes(StandardCharsets.US_ASCII);System.arraycopy(text,0,bytes,at,text.length);}
    private static byte[] thinMachO(boolean arm){
        byte[] bytes=new byte[0x300];ByteBuffer file=ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);long base=0x100000000L;file.putInt(0,0xfeedfacf);file.putInt(4,arm?0x0100000c:0x01000007);file.putInt(8,3);file.putInt(12,2);file.putInt(16,2);file.putInt(20,176);
        int at=32;file.putInt(at,0x19);file.putInt(at+4,152);putName(bytes,at+8,"__TEXT");file.putLong(at+24,base);file.putLong(at+32,bytes.length);file.putLong(at+48,bytes.length);file.putInt(at+56,5);file.putInt(at+60,5);file.putInt(at+64,1);putName(bytes,at+72,"__text");putName(bytes,at+88,"__TEXT");file.putLong(at+104,base+0x200);file.putLong(at+112,8);file.putInt(at+120,0x200);file.putInt(at+136,0x80000400);at+=152;file.putInt(at,0x80000028);file.putInt(at+4,24);file.putLong(at+8,0x200);
        if(arm){file.putInt(0x200,0xd28000e0);file.putInt(0x204,0xd65f03c0);}else{bytes[0x200]=(byte)0xb8;bytes[0x201]=11;bytes[0x205]=(byte)0xc3;}return bytes;
    }
    private static byte[] fatMachO(){
        byte[] x64=thinMachO(false),arm=thinMachO(true),bytes=new byte[0x2300];ByteBuffer file=ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);file.putInt(0,0xcafebabe);file.putInt(4,2);file.putInt(8,0x01000007);file.putInt(16,0x1000);file.putInt(20,x64.length);file.putInt(24,12);file.putInt(28,0x0100000c);file.putInt(36,0x2000);file.putInt(40,arm.length);file.putInt(44,12);System.arraycopy(x64,0,bytes,0x1000,x64.length);System.arraycopy(arm,0,bytes,0x2000,arm.length);return bytes;
    }
    @Test public void nonfirstMachOSliceArchiveRestoresExplicitImportIdentity()throws Exception{
        Context context=InstrumentationRegistry.getInstrumentation().getTargetContext();Path temporary=Files.createTempDirectory(context.getCacheDir().toPath(),"archive-macho-device-");
        try{
            Path source=Files.createDirectory(temporary.resolve("source")),input=source.resolve("input.bin");byte[] original=fatMachO();Files.write(input,original);RawImportConfig selected=RawImportConfig.machOSlice("aarch64");long entry=0x100000200L;
            try(MintSession program=selected.open(input.toString())){program.attachProject(source.resolve("program.mint").toString());program.analyze();assertTrue(program.imageSummary().contains("arch=arm64"));program.edit(entry,"name","archived_second_slice");program.defineType("ArchivedSlice=struct{tag:u32;size:u32}");program.assemble(entry,"mov x0,9",true);}
            byte[] originalProgram=Files.readAllBytes(source.resolve("program.mint"));ProjectArchive.Metadata metadata=new ProjectArchive.Metadata("Explicit second Mach-O slice",selected,entry,entry,0);ByteArrayOutputStream output=new ByteArrayOutputStream();ProjectArchive.write(output,source.toFile(),metadata,new AtomicBoolean(false));
            Path projects=Files.createDirectory(temporary.resolve("restores"));ProjectArchive.Restored restored=ProjectArchive.restore(new ByteArrayInputStream(output.toByteArray()),projects.toFile(),new AtomicBoolean(false),(directory,configuration)->validate(directory.toPath(),configuration));
            assertNotNull(restored.metadata.raw);assertTrue(restored.metadata.raw.machOSlice);assertEquals("macho:aarch64",restored.metadata.raw.architecture);assertEquals(0,restored.metadata.raw.baseAddress);assertEquals(0,restored.metadata.raw.entryAddress);assertArrayEquals(original,Files.readAllBytes(restored.binary.toPath()));
            try(MintSession reopened=restored.metadata.raw.open(restored.binary.getAbsolutePath())){reopened.attachProject(new java.io.File(restored.binary.getParentFile(),"program.mint").getAbsolutePath());reopened.analyze();assertTrue(reopened.imageSummary().contains("arch=arm64"));assertEquals("archived_second_slice",reopened.annotation(entry,"name"));assertTrue(reopened.typesCHeader().contains("ArchivedSlice"));assertFalse(reopened.annotation(entry,"patch").isEmpty());assertTrue(reopened.functionIr(entry).contains("9"));}
            try(MintSession wrong=MintSession.open(restored.binary.getAbsolutePath())){assertTrue(wrong.imageSummary().contains("arch=x86-64"));try{wrong.attachProject(new java.io.File(restored.binary.getParentFile(),"program.mint").getAbsolutePath());fail("default first slice must reject selected second slice Program");}catch(Exception expected){assertTrue(expected instanceof java.io.IOException);}}
            assertArrayEquals(original,Files.readAllBytes(input));assertArrayEquals(originalProgram,Files.readAllBytes(source.resolve("program.mint")));
        }finally{cleanup(temporary);}
    }
    @Test public void nativeProgramBackupRestoresIndependentEditsTypesAndPatches()throws Exception{
        Context context=InstrumentationRegistry.getInstrumentation().getTargetContext();Path temporary=Files.createTempDirectory(context.getCacheDir().toPath(),"archive-device-");
        try{
            Path source=Files.createDirectory(temporary.resolve("source")),input=source.resolve("input.bin");
            try(InputStream demo=context.getAssets().open("libmintdemo.so")){Files.copy(demo,input);}byte[] original=Files.readAllBytes(input);long entry;
            try(MintSession program=MintSession.open(input.toString())){
                program.attachProject(source.resolve("program.mint").toString());program.analyze();entry=firstFunction(program);
                program.edit(entry,"name","archived_native_entry");program.edit(entry,"comment","Архівний коментар");program.edit(entry,"bookmark","backup fixture");program.defineType("ArchivePacket=struct{tag:u32;length:u32}");
                // A whole instruction-sized patch overlay is portable. Preview
                // decoder mode derives from the shipped native host demo.
                program.assemble(entry,"nop",true);assertFalse(program.annotation(entry,"patch").isEmpty());
            }
            byte[] originalProgram=Files.readAllBytes(source.resolve("program.mint"));ProjectArchive.Metadata metadata=new ProjectArchive.Metadata("Independent archive fixture",null,entry,entry,2);
            ByteArrayOutputStream output=new ByteArrayOutputStream();ProjectArchive.write(output,source.toFile(),metadata,new AtomicBoolean(false));byte[] archive=output.toByteArray();assertTrue(archive.length>0);
            Path projects=Files.createDirectory(temporary.resolve("restores"));AtomicBoolean cancel=new AtomicBoolean(false);
            ProjectArchive.Restored first=ProjectArchive.restore(new ByteArrayInputStream(archive),projects.toFile(),cancel,(directory,restored)->validate(directory.toPath(),restored));
            ProjectArchive.Restored second=ProjectArchive.restore(new ByteArrayInputStream(archive),projects.toFile(),cancel,(directory,restored)->validate(directory.toPath(),restored));
            assertNotEquals(first.binary.getCanonicalPath(),second.binary.getCanonicalPath());assertEquals(metadata.name,first.metadata.name);assertEquals(entry,first.metadata.selected);assertEquals(2,first.metadata.pane);
            for(ProjectArchive.Restored restored:new ProjectArchive.Restored[]{first,second}){
                assertArrayEquals(original,Files.readAllBytes(restored.binary.toPath()));
                try(MintSession program=MintSession.open(restored.binary.getAbsolutePath())){program.attachProject(new java.io.File(restored.binary.getParentFile(),"program.mint").getAbsolutePath());program.analyze();assertEquals("archived_native_entry",program.annotation(entry,"name"));assertEquals("Архівний коментар",program.annotation(entry,"comment"));assertEquals("backup fixture",program.annotation(entry,"bookmark"));assertFalse(program.annotation(entry,"patch").isEmpty());assertTrue(program.typesCHeader().contains("ArchivePacket"));}
            }
            try(MintSession edit=MintSession.open(first.binary.getAbsolutePath())){edit.attachProject(new java.io.File(first.binary.getParentFile(),"program.mint").getAbsolutePath());edit.analyze();edit.edit(entry,"comment","changed first restore only");}
            try(MintSession independent=MintSession.open(second.binary.getAbsolutePath())){independent.attachProject(new java.io.File(second.binary.getParentFile(),"program.mint").getAbsolutePath());independent.analyze();assertEquals("Архівний коментар",independent.annotation(entry,"comment"));}
            assertArrayEquals(original,Files.readAllBytes(input));assertArrayEquals(originalProgram,Files.readAllBytes(source.resolve("program.mint")));assertTrue(Arrays.equals(original,Files.readAllBytes(second.binary.toPath())));
        }finally{cleanup(temporary);}
    }
}
