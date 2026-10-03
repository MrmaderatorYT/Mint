import com.ccs.mint.core.MintSession;
import com.ccs.mint.core.NativeCore;
import com.ccs.mint.ui.ProjectArchive;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

/** Real portable archive + native Program integration. All writable files live
 * in this probe's newly owned temporary directory; fixture inputs are read-only.
 * No Android runtime, target execution, debugger or network connection is used. */
public final class ArchiveJniProbe {
    private static int checks;
    private static void check(boolean valid,String description) {
        checks++;
        if(!valid)throw new AssertionError(description);
        System.out.println("  ok   "+description);
    }
    private static String sha(byte[] bytes)throws Exception {
        byte[] digest=MessageDigest.getInstance("SHA-256").digest(bytes);StringBuilder text=new StringBuilder();
        for(byte value:digest)text.append(String.format(java.util.Locale.ROOT,"%02x",value&255));return text.toString();
    }
    private static long functionNamed(MintSession session,String name) {
        for(int offset=0;offset<65536;offset+=256) {
            long[] addresses=new long[256];String[] names=new String[256];int count=session.functions(offset,256,addresses,new int[256],new int[256],new int[256],new int[256],names);
            for(int i=0;i<count;i++)if(name.equals(names[i]))return addresses[i];
            if(count<256)break;
        }
        throw new AssertionError("Fixture function not found: "+name);
    }
    private static MintSession open(Path directory,ProjectArchive.Metadata metadata)throws IOException {
        String input=directory.resolve("input.bin").toString();return metadata.raw==null?MintSession.open(input):metadata.raw.open(input);
    }
    private static void binding(Path directory,String sourceHash,String debugHash,byte[] debugBytes)throws Exception {
        String[] lines=Files.readString(directory.resolve("program.mint.debug"),StandardCharsets.US_ASCII).split("\n",-1);
        check(lines.length==5&&lines[0].equals("MINT_DEBUG 1")&&lines[1].equals(sourceHash)&&lines[2].equals(debugHash)&&lines[3].equals("0")&&lines[4].isEmpty(),"external debug sidecar retains exact verified source/content SHA-256 binding");
        check(Arrays.equals(Files.readAllBytes(directory.resolve("program.mint.debug."+debugHash+".bin")),debugBytes),"content-addressed private debug bytes preserved exactly");
    }
    private static void restored(ProjectArchive.Restored result,long entry,String comment,String format,String sourceHash,String debugHash,byte[] debugBytes)throws Exception {
        Path directory=result.binary.getParentFile().toPath();binding(directory,sourceHash,debugHash,debugBytes);
        try(MintSession session=open(directory,result.metadata)) {
            session.attachProject(directory.resolve("program.mint").toString());session.analyze();
            check(session.annotation(entry,"comment").equals(comment),"native restored Program retains private research comment");
            check(session.types().contains("MintNode")&&session.typesCHeader().contains("ArchivedNodeAlias"),"restored native baseline validates user alias depending on externally imported MintNode");
            check(session.debugInfo().contains(format),"restored native debug provenance remains "+format);
            check(functionNamed(session,"mint_debug_entry")==entry,"external function identity survives independent restore and native analysis");
        }
    }
    private static byte[] corruptedDebugEntry(byte[] archive)throws Exception {
        ByteArrayOutputStream bytes=new ByteArrayOutputStream();boolean changed=false;
        try(ZipInputStream input=new ZipInputStream(new ByteArrayInputStream(archive));ZipOutputStream output=new ZipOutputStream(bytes)) {
            ZipEntry entry;while((entry=input.getNextEntry())!=null) {
                byte[] content=input.readAllBytes();if(entry.getName().equals("external-debug.bin")){check(content.length>0,"negative fixture has actual external debug content");content[0]^=1;changed=true;}
                // Recompute ZIP CRC normally so restore must reject its bound
                // SHA-256, not merely malformed compression/container bytes.
                output.putNextEntry(new ZipEntry(entry.getName()));output.write(content);output.closeEntry();input.closeEntry();
            }
        }
        check(changed,"negative archive alters only external-debug.bin");return bytes.toByteArray();
    }
    private static void workflow(Path temporary,Path binaryFixture,Path debugFixture,boolean pdb)throws Exception {
        String label=pdb?"pdb":"dwarf",format=pdb?"PDB7/CodeView":"DWARF";Path source=Files.createDirectory(temporary.resolve(label+"-source")),input=source.resolve("input.bin"),project=source.resolve("program.mint");
        byte[] original=Files.readAllBytes(binaryFixture),debugBytes=Files.readAllBytes(debugFixture);Files.copy(binaryFixture,input);String sourceHash=sha(original),debugHash=sha(debugBytes),comment=label+" external metadata — приватна примітка";long entry;
        try(MintSession session=MintSession.open(input.toString())) {
            session.attachProject(project.toString());session.analyze();session.importDebug(debugFixture.toString(),false);
            check(session.debugInfo().contains(format)&&session.types().contains("MintNode"),"actual "+format+" import enters native authoritative baseline");entry=functionNamed(session,"mint_debug_entry");
            session.defineType("ArchivedNodeAlias=MintNode");session.edit(entry,"comment",comment);
            check(session.typesCHeader().contains("ArchivedNodeAlias"),"user alias requires real externally imported struct layout");
            if(!pdb)check(session.sourceLocation(entry).contains("dwarf_fixture.c:"),"external DWARF source location reaches JNI before backup");
        }
        binding(source,sourceHash,debugHash,debugBytes);byte[] originalProgram=Files.readAllBytes(project),originalBinding=Files.readAllBytes(source.resolve("program.mint.debug"));
        ProjectArchive.Metadata metadata=new ProjectArchive.Metadata(label+" native archive",null,entry,entry,3);ByteArrayOutputStream output=new ByteArrayOutputStream();ProjectArchive.write(output,source.toFile(),metadata,new AtomicBoolean(false));byte[] archive=output.toByteArray();
        Set<String> entries=new HashSet<>();try(ZipInputStream zip=new ZipInputStream(new ByteArrayInputStream(archive))){ZipEntry entryFile;while((entryFile=zip.getNextEntry())!=null){entries.add(entryFile.getName());zip.closeEntry();}}
        check(entries.equals(new HashSet<>(Arrays.asList("manifest.mint","input.bin","program.mint","debug.metadata","external-debug.bin"))),"archive contains authoritative binary/Program/debug only, no cache or executable extension");
        Path projects=Files.createDirectory(temporary.resolve(label+"-restores"));AtomicInteger validations=new AtomicInteger();
        ProjectArchive.Validator validator=(directory,configuration)-> {
            validations.incrementAndGet();binding(directory.toPath(),sourceHash,debugHash,debugBytes);
            check(!Files.exists(directory.toPath().resolve("program.mint.analysis")),"native stage validation begins without derived analysis cache");
            try(MintSession session=open(directory.toPath(),configuration)) {
                // Restore must adopt the sidecar before authoritative aliases
                // are validated, but must not analyze/create a staging cache.
                session.attachProject(new java.io.File(directory,"program.mint").getAbsolutePath());
                check(session.types().contains("ArchivedNodeAlias")&&session.debugInfo().contains(format),"attach-only native validator restores baseline before dependent user type validation");
            }
            check(!Files.exists(directory.toPath().resolve("program.mint.analysis")),"attach-only validator does not publish a staging analysis cache");
        };
        ProjectArchive.Restored first=ProjectArchive.restore(new ByteArrayInputStream(archive),projects.toFile(),new AtomicBoolean(false),validator),second=ProjectArchive.restore(new ByteArrayInputStream(archive),projects.toFile(),new AtomicBoolean(false),validator);
        check(validations.get()==2&&!first.binary.getCanonicalPath().equals(second.binary.getCanonicalPath()),"repeated archive restores validate and publish independent native projects");
        check(first.metadata.name.equals(metadata.name)&&first.metadata.selected==entry&&first.metadata.listing==entry&&first.metadata.pane==3,"workspace name/navigation preserved by portable archive");
        restored(first,entry,comment,format,sourceHash,debugHash,debugBytes);restored(second,entry,comment,format,sourceHash,debugHash,debugBytes);
        Path firstDirectory=first.binary.getParentFile().toPath();try(MintSession edited=open(firstDirectory,first.metadata)){edited.attachProject(firstDirectory.resolve("program.mint").toString());edited.analyze();edited.edit(entry,"comment","independent first restore only");}
        restored(first,entry,"independent first restore only",format,sourceHash,debugHash,debugBytes);restored(second,entry,comment,format,sourceHash,debugHash,debugBytes);
        check(Arrays.equals(original,Files.readAllBytes(first.binary.toPath()))&&Arrays.equals(original,Files.readAllBytes(second.binary.toPath())),"independent restore edits never mutate either imported binary");
        Path rejected=Files.createDirectory(temporary.resolve(label+"-rejected"));int priorValidations=validations.get();boolean refused=false;
        try{ProjectArchive.restore(new ByteArrayInputStream(corruptedDebugEntry(archive)),rejected.toFile(),new AtomicBoolean(false),validator);}catch(IOException expected){refused=expected.getMessage().contains("checksum mismatch");}
        check(refused&&validations.get()==priorValidations,"corrupted external ZIP entry rejected by SHA-256 before native validation");try(Stream<Path> files=Files.list(rejected)){check(files.count()==0,"rejected corrupt archive publishes nothing and removes owned stage");}
        check(Arrays.equals(original,Files.readAllBytes(input))&&Arrays.equals(originalProgram,Files.readAllBytes(project))&&Arrays.equals(originalBinding,Files.readAllBytes(source.resolve("program.mint.debug"))),"backup/restore/conflicting edits preserve original private input/Program/debug binding");
        check(Arrays.equals(original,Files.readAllBytes(binaryFixture))&&Arrays.equals(debugBytes,Files.readAllBytes(debugFixture)),"source compiler fixtures remain unchanged");
    }
    public static void main(String[] args)throws Exception {
        if(args.length!=4)throw new IllegalArgumentException("usage: ArchiveJniProbe stripped.so external.debug windows-types.exe windows-types.pdb");
        System.out.println("archive JNI engine: "+NativeCore.engineInfo());Path temporary=Files.createTempDirectory("mint-archive-jni-");
        try{workflow(temporary,Path.of(args[0]),Path.of(args[1]),false);workflow(temporary,Path.of(args[2]),Path.of(args[3]),true);}
        finally{try(Stream<Path> files=Files.walk(temporary)){for(Path owned:(Iterable<Path>)files.sorted(Comparator.reverseOrder())::iterator)Files.deleteIfExists(owned);}}
        System.out.println("archive JNI contracts: "+checks+" checks passed");
    }
}
