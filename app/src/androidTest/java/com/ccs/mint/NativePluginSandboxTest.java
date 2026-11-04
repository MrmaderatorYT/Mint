package com.ccs.mint;

import android.content.Context;
import android.content.pm.ServiceInfo;
import android.content.ComponentName;
import android.os.Build;
import android.os.Process;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import com.ccs.mint.plugin.SandboxPluginClient;
import com.ccs.mint.plugin.SandboxPluginService;
import org.junit.Assume;
import org.junit.Test;
import org.junit.runner.RunWith;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import static org.junit.Assert.*;

@RunWith(AndroidJUnit4.class)
public class NativePluginSandboxTest {
    private final Context context=InstrumentationRegistry.getInstrumentation().getTargetContext();
    private File copy(InputStream input,String suffix)throws Exception {
        File file=File.createTempFile("sandbox-test-",suffix,context.getCodeCacheDir());
        try(InputStream source=input;FileOutputStream output=new FileOutputStream(file)) {
            assertTrue(file.setReadOnly());byte[] bytes=new byte[65536];int n;long count=0;
            while((n=source.read(bytes))!=-1){count+=n;assertTrue(count<=16*1024*1024);output.write(bytes,0,n);}output.getFD().sync();
        }
        return file;
    }
    private File plugin()throws Exception {
        try(ZipFile apk=new ZipFile(context.getApplicationInfo().sourceDir)) {
            for(String abi:Build.SUPPORTED_ABIS){ZipEntry entry=apk.getEntry("lib/"+abi+"/libmint_sandbox_probe.so");if(entry!=null)return copy(apk.getInputStream(entry),".so");}
        }
        Assume.assumeTrue("Build with -PmintSandboxTestPlugin=true",false);return null;
    }
    private static final class Result {boolean success;String output;int uid,pid;}
    private Result run(String command,String arguments,long timeout)throws Exception {
        Assume.assumeTrue(Build.VERSION.SDK_INT>=29);
        File plugin=plugin(),binary=copy(context.getAssets().open("libmintdemo.so"),".bin");
        CountDownLatch done=new CountDownLatch(1);AtomicReference<Result> result=new AtomicReference<>();
        AtomicReference<SandboxPluginClient> worker=new AtomicReference<>();
        try {
            InstrumentationRegistry.getInstrumentation().runOnMainSync(()->{
                SandboxPluginClient client=new SandboxPluginClient(context,binary,plugin,"sandbox_probe/"+command,arguments,"",0,0,false,timeout,
                        (success,output,uid,pid)->{Result value=new Result();value.success=success;value.output=output;value.uid=uid;value.pid=pid;result.set(value);done.countDown();});
                worker.set(client);client.start();
            });
            assertTrue("worker deadline",done.await(timeout+15000,TimeUnit.MILLISECONDS));
            return result.get();
        } finally {
            InstrumentationRegistry.getInstrumentation().runOnMainSync(()->{if(worker.get()!=null)worker.get().close();});binary.delete();plugin.delete();
        }
    }
    @Test public void manifestRequiresNonExportedIsolatedService()throws Exception {
        ServiceInfo service=context.getPackageManager().getServiceInfo(new ComponentName(context,SandboxPluginService.class),0);
        assertFalse(service.exported);assertTrue((service.flags&ServiceInfo.FLAG_ISOLATED_PROCESS)!=0);
    }
    @Test public void nativeCodeCannotReadPrivateFilesConnectOrEditHostProgram()throws Exception {
        File secret=File.createTempFile("parent-private-",".txt",context.getFilesDir());
        try(FileOutputStream output=new FileOutputStream(secret);ServerSocket listener=new ServerSocket(0,1,InetAddress.getByName("127.0.0.1"))) {
            output.write("parent-only".getBytes(java.nio.charset.StandardCharsets.UTF_8));output.getFD().sync();
            Result result=run("probe",secret.getAbsolutePath()+"\n"+listener.getLocalPort(),60000);
            assertTrue(result.output,result.success);assertNotEquals(Process.myUid(),result.uid);assertNotEquals(Process.myPid(),result.pid);
            assertTrue(result.output,result.output.contains("private=denied"));assertTrue(result.output,result.output.contains("network=denied"));
            assertTrue(result.output,result.output.contains("allow_edits=0"));
        } finally {secret.delete();}
    }
    @Test public void hostApiRejectsProgramEdits()throws Exception {
        Result result=run("edit","",60000);assertFalse(result.output,result.success);
        assertTrue(result.output,result.output.contains("plugin invocation is read-only"));
        assertTrue(result.output,result.pid>0);assertNotEquals(Process.myPid(),result.pid);
    }
    @Test public void nativeCrashIsContained()throws Exception {
        Result result=run("crash","",60000);assertFalse(result.output,result.success);
        assertTrue(result.output,result.pid>0);assertNotEquals(Process.myPid(),result.pid);
        assertTrue(result.output,result.output.contains("crashed") || result.output.contains("binding died"));
    }
    @Test public void nativeHangDoesNotBlockCaller()throws Exception {
        Result result=run("hang","",5000);assertFalse(result.output,result.success);assertTrue(result.output,result.output.contains("timed out"));
        assertTrue(result.output,result.pid>0);assertNotEquals(Process.myPid(),result.pid);
    }
}
