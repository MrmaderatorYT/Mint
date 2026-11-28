package com.ccs.mint.ui;

import android.content.Context;
import android.content.ContextWrapper;
import android.content.SharedPreferences;

import androidx.lifecycle.Observer;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.ccs.mint.core.MintSession;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.File;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;

import static org.junit.Assert.*;

@RunWith(AndroidJUnit4.class)
public final class WorkspaceViewModelRecoveryTest {
    @Test public void savedProjectOpensWhenPreferenceWritesFail() throws Exception {
        var instrumentation = InstrumentationRegistry.getInstrumentation();
        Context target = instrumentation.getTargetContext();
        Path root = Files.createTempDirectory(target.getCacheDir().toPath(), "mint-reopen-");
        RawImportConfig raw = new RawImportConfig("aarch64", 0x1000, 0x1000);
        String id = "fixture" + raw.projectSuffix();
        String projectPrefs = "project-" + id;
        String privatePrefsPrefix = root.getFileName() + "-";
        AtomicInteger commits = new AtomicInteger();
        Context fixture = new ContextWrapper(target) {
            @Override public Context getApplicationContext() { return this; }
            @Override public File getFilesDir() { return root.toFile(); }
            @Override public SharedPreferences getSharedPreferences(String name, int mode) {
                SharedPreferences preferences = target.getSharedPreferences(privatePrefsPrefix + name, mode);
                if (!projectPrefs.equals(name)) return preferences;
                return (SharedPreferences) Proxy.newProxyInstance(SharedPreferences.class.getClassLoader(),
                        new Class<?>[]{SharedPreferences.class}, (proxy, method, args) -> {
                            if (!method.getName().equals("edit")) return method.invoke(preferences, args);
                            return rejectWrites(commits);
                        });
            }
        };

        var result = new AtomicReference<WorkspaceViewModel.State>();
        var finished = new CountDownLatch(1);
        var model = new WorkspaceViewModel();
        Observer<WorkspaceViewModel.State> observer = state -> {
            if (state.phase == WorkspaceViewModel.Phase.READY || state.phase == WorkspaceViewModel.Phase.FAILED) {
                result.set(state);
                finished.countDown();
            }
        };
        try {
            Path project = Files.createDirectories(root.resolve("projects").resolve(id));
            Path input = project.resolve("input.bin");
            Files.write(input, new byte[]{(byte) 0xe0, 0, (byte) 0x80, (byte) 0xd2,
                    (byte) 0xc0, 3, 0x5f, (byte) 0xd6});
            try (MintSession session = raw.open(input.toString())) {
                session.attachProject(project.resolve("program.mint").toString());
                session.analyze();
                session.edit(0x1000, "comment", "Previously committed edit");
            }
            assertTrue(target.getSharedPreferences(privatePrefsPrefix + projectPrefs, Context.MODE_PRIVATE)
                    .edit().putString("name", "Saved raw fixture")
                    .putString("raw_arch", raw.architecture).putLong("raw_base", raw.baseAddress)
                    .putLong("raw_entry", raw.entryAddress).commit());

            instrumentation.runOnMainSync(() -> {
                model.state().observeForever(observer);
                model.openSavedProject(fixture, id);
            });
            assertTrue("Opening the saved workspace timed out", finished.await(15, TimeUnit.SECONDS));
            assertEquals(result.get().message, WorkspaceViewModel.Phase.READY, result.get().phase);
            assertEquals("Saved raw fixture", result.get().name);
            assertEquals(0, commits.get());
            assertEquals("Previously committed edit", model.worker().submit(
                    () -> model.session().annotation(0x1000, "comment")).get(5, TimeUnit.SECONDS));
        } finally {
            instrumentation.runOnMainSync(() -> {
                model.state().removeObserver(observer);
                model.onCleared();
            });
            assertTrue(model.worker().awaitTermination(15, TimeUnit.SECONDS));
            target.deleteSharedPreferences(privatePrefsPrefix + projectPrefs);
            target.deleteSharedPreferences(privatePrefsPrefix + "projects");
            try (Stream<Path> files = Files.walk(root)) {
                for (Path path : files.sorted(Comparator.reverseOrder()).toArray(Path[]::new)) {
                    Files.delete(path);
                }
            }
        }
    }

    private static SharedPreferences.Editor rejectWrites(AtomicInteger commits) {
        return (SharedPreferences.Editor) Proxy.newProxyInstance(SharedPreferences.Editor.class.getClassLoader(),
                new Class<?>[]{SharedPreferences.Editor.class}, (proxy, method, args) -> {
                    if (method.getName().equals("commit")) {
                        commits.incrementAndGet();
                        return false;
                    }
                    if (method.getName().equals("apply")) return null;
                    return proxy;
                });
    }
}
