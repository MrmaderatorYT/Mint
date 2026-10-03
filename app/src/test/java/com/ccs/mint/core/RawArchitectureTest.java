package com.ccs.mint.core;
import org.junit.Test;
import static org.junit.Assert.*;

public final class RawArchitectureTest {
    @Test public void parsesBoundedNativeSnapshotWithoutLoadingLibrary() {
        RawArchitecture[] values = RawArchitecture.fromNativeMetadata(new String[]{
                "aarch64", "AArch64", "1", "8", "4", "4", "4", "0", "0",
                "test-decoder", "Custom decoder", "220", "4", "2", "8", "2", "1", "0"});
        assertEquals(2, values.length); assertEquals("test-decoder", values[1].id);
        assertEquals(4, values[1].pointerSize); assertEquals(2, values[1].instructionAlignment);
        assertTrue(values[0].hasLifter);assertFalse(values[1].hasLifter);
    }
    @Test public void recognizesSemanticPluginCapability() {
        RawArchitecture[] values=RawArchitecture.fromNativeMetadata(new String[]{"custom","Semantic", "220","8","1","4","1","2","0"});assertTrue(values[0].hasLifter);
    }
    @Test(expected=IllegalStateException.class) public void rejectsSemanticPluginMarkerOnBuiltin() {
        RawArchitecture.fromNativeMetadata(new String[]{"aarch64","AArch64","1","8","4","4","4","2","0"});
    }
    @Test(expected=IllegalStateException.class) public void rejectsTruncatedNativeRow() {
        RawArchitecture.fromNativeMetadata(new String[]{"partial"});
    }
    @Test(expected=IllegalStateException.class) public void rejectsInconsistentCustomMarker() {
        RawArchitecture.fromNativeMetadata(new String[]{"custom", "Custom", "220", "8", "1", "4", "1", "0", "0"});
    }
    @Test(expected=IllegalStateException.class) public void rejectsInventedAddressTag() {
        RawArchitecture.fromNativeMetadata(new String[]{"custom", "Custom", "220", "8", "1", "4", "1", "1", "1"});
    }
    @Test(expected=IllegalArgumentException.class) public void rejectsPathLikeIdentity() {
        new RawArchitecture("../../decoder", "Decoder", 220, 8, 1, 4, 1, false);
    }
    @Test(expected=IllegalStateException.class) public void rejectsDuplicateNativeIdentity() {
        RawArchitecture.fromNativeMetadata(new String[]{
                "custom-one", "One", "220", "8", "1", "4", "1", "1", "0",
                "custom-two", "Two", "220", "8", "1", "4", "1", "1", "0"});
    }
    @Test(expected=IllegalStateException.class) public void rejectsOversizedNativeRegistry() {
        RawArchitecture.fromNativeMetadata(new String[(RawArchitecture.MAX_DESCRIPTORS + 1) * 9]);
    }
}
