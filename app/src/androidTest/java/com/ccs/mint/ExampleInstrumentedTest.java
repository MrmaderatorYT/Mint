package com.ccs.mint;

import android.view.View;

import androidx.test.core.app.ActivityScenario;
import androidx.test.ext.junit.runners.AndroidJUnit4;

import org.junit.Test;
import org.junit.runner.RunWith;

import static org.junit.Assert.*;

/**
 * Instrumented test, which will execute on an Android device.
 *
 * @see <a href="http://d.android.com/tools/testing">Testing documentation</a>
 */
@RunWith(AndroidJUnit4.class)
public class ExampleInstrumentedTest {
    @Test
    public void workspaceStartsWithoutMockRows() {
        try (ActivityScenario<com.ccs.mint.ui.WorkspaceActivity> scenario =
                     ActivityScenario.launch(com.ccs.mint.ui.WorkspaceActivity.class)) {
            scenario.onActivity(activity -> {
                assertEquals("com.ccs.mint", activity.getPackageName());
                assertEquals(View.VISIBLE, activity.findViewById(R.id.empty).getVisibility());
                assertEquals(View.GONE, activity.findViewById(R.id.content).getVisibility());
            });
        }
    }
}
