package com.ccs.mint.ui;

import android.content.Context;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.ccs.mint.core.MintSession;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Comparator;
import java.util.stream.Stream;

import static org.junit.Assert.*;

@RunWith(AndroidJUnit4.class)
public final class LearnLessonDeviceTest {
    @Test public void guideTargetsMatchTheBundledBinaries() throws Exception {
        Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
        Path temp = Files.createTempDirectory(context.getCacheDir().toPath(), "guide-fixtures-");
        try {
            for (LearnLesson lesson : LearnLesson.values()) {
                Path binary = temp.resolve(lesson.id + ".elf");
                try (InputStream asset = context.getAssets().open(lesson.asset)) {
                    Files.copy(asset, binary, StandardCopyOption.REPLACE_EXISTING);
                }
                try (MintSession session = MintSession.open(binary.toString())) {
                    session.attachProject(temp.resolve(lesson.id + ".mint").toString());
                    session.analyze();
                    long[] range = session.functionRangeAt(lesson.entry);
                    assertNotNull(lesson.id, range);
                    assertEquals(lesson.id, lesson.entry, range[0]);
                    if (lesson == LearnLesson.STRINGS) {
                        assertTrue(session.strings(lesson.entry).contains("Mint practice label"));
                        assertTrue(session.references(LearnLesson.PRACTICE_LABEL_ADDRESS)
                                .contains(Long.toHexString(lesson.entry)));
                    } else {
                        String patch = switch (lesson) {
                            case ARITHMETIC -> "add w0, w0, #5";
                            case BRANCH -> "cmp w0, #10";
                            case RECORDS -> "sub w1, w1, w2";
                            case LOOP -> "mov w1, #5";
                            case CALLS -> "add w0, w0, #4";
                            case STRINGS -> null;
                        };
                        assertNotNull(lesson.id, patch);
                        String before = session.patchReviewBytes(lesson.patchAddress, 4);
                        assertFalse(lesson.id, before.isEmpty());
                        assertNotEquals(lesson.id, lesson.expectedPatch, before);
                        assertEquals(lesson.id, lesson.expectedPatch, session.assemble(lesson.patchAddress, patch, false));
                        session.assemble(lesson.patchAddress, patch, true);
                        assertEquals(lesson.id, lesson.expectedPatch, session.patchReviewBytes(lesson.patchAddress, 4));
                        session.undoEdit(false);
                        assertEquals(lesson.id, before, session.patchReviewBytes(lesson.patchAddress, 4));
                    }
                }
            }
        } finally {
            try (Stream<Path> paths = Files.walk(temp)) {
                for (Path path : paths.sorted(Comparator.reverseOrder()).toArray(Path[]::new)) {
                    Files.deleteIfExists(path);
                }
            }
        }
    }
}
