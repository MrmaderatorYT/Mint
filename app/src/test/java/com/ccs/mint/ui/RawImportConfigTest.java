package com.ccs.mint.ui;

import org.junit.Test;
import com.ccs.mint.core.RawArchitecture;
import static org.junit.Assert.*;

public final class RawImportConfigTest {
    @Test public void explicitMachOSliceHasSeparatePersistentIdentity() {
        RawImportConfig slice=RawImportConfig.machOSlice("x86-64");assertTrue(slice.machOSlice);assertEquals("x86-64",slice.decoderId());assertEquals("macho:x86-64",slice.architecture);
        assertNotEquals(new RawImportConfig("x86-64",0,0).projectSuffix(),slice.projectSuffix());assertTrue(slice.describe().contains("Mach-O"));
        assertEquals(slice.projectSuffix(),new RawImportConfig(slice.architecture,0,0).projectSuffix());
    }
    @Test(expected=IllegalArgumentException.class) public void machOSliceCannotOverrideContainerAddresses() {new RawImportConfig("macho:aarch64",0x1000,0x1000);}
    @Test(expected=IllegalArgumentException.class) public void unsupportedMachOArchitectureRejected() {RawImportConfig.machOSlice("riscv64");}
    @Test public void normalizesArchitecturesAndHexAddresses() {
        RawImportConfig config=RawImportConfig.fromHex("arm64","0x1000","1004");
        assertEquals("aarch64",config.architecture);assertEquals(0x1000,config.baseAddress);assertEquals(0x1004,config.entryAddress);
        assertEquals("x86-64",new RawImportConfig("x86_64",0,0).architecture);
    }
    @Test public void unsignedAddressesAndZeroAreValid() {
        RawImportConfig high=RawImportConfig.fromHex("amd64","8000000000000000","fffffffffffffffe");
        assertEquals(Long.MIN_VALUE,high.baseAddress);assertEquals(-2,high.entryAddress);
        assertEquals(0,new RawImportConfig("aarch64",0,0).entryAddress);
    }
    @Test public void differentMappingsHaveDifferentProjectIdentities() {
        RawImportConfig a=new RawImportConfig("aarch64",0x1000,0x1000),b=new RawImportConfig("aarch64",0x2000,0x2000);
        assertNotEquals(a.projectSuffix(),b.projectSuffix());
        assertNotEquals(a.projectSuffix(),new RawImportConfig("x86-64",0x1000,0x1000).projectSuffix());
        assertTrue(a.describe().contains("0x1000"));
    }
    @Test(expected=IllegalArgumentException.class) public void rejectsUnsupportedArchitecture() {new RawImportConfig("riscv",0,0);}
    @Test(expected=IllegalArgumentException.class) public void rejectsMisalignedAarch64Entry() {new RawImportConfig("aarch64",0,3);}
    @Test(expected=IllegalArgumentException.class) public void rejectsEntryBeforeUnsignedBase() {new RawImportConfig("x86-64",Long.MIN_VALUE,1);}
    @Test(expected=IllegalArgumentException.class) public void rejectsOverflowingAddress() {RawImportConfig.fromHex("aarch64","10000000000000000","0");}
    @Test(expected=IllegalArgumentException.class) public void rejectsNegativeAddressText() {RawImportConfig.fromHex("x86-64","-1","0");}
    @Test public void acceptsNative32BitAndRiscvModes() {
        assertEquals("arm",new RawImportConfig("arm32",0x1000,0x1000).architecture);
        assertEquals("thumb",new RawImportConfig("thumb",0x1000,0x1001).architecture);
        assertEquals("x86-32",new RawImportConfig("i386",0x1000,0x1001).architecture);
        assertEquals("riscv32",new RawImportConfig("rv32",0x1000,0x1002).architecture);
        assertEquals("riscv64",new RawImportConfig("rv64",0x1000,0x1002).architecture);
    }
    @Test(expected=IllegalArgumentException.class) public void rejects32BitAddressOverflow(){new RawImportConfig("arm",0x100000000L,0x100000000L);}
    @Test(expected=IllegalArgumentException.class) public void rejectsRiscvOddEntry(){new RawImportConfig("rv64",0,1);}
    @Test public void acceptsOnlyExplicitlyRegisteredCustom64BitDecoder() {
        RawArchitecture custom = new RawArchitecture("unit-custom64", "Unit decoder64", 201, 8, 2, 8, 2, false);
        try {
            RawImportConfig.installArchitectures(new RawArchitecture[]{custom});
            RawImportConfig config = new RawImportConfig(custom.id, Long.MIN_VALUE, Long.MIN_VALUE + 2);
            assertEquals(custom.id, config.architecture); assertEquals(Long.MIN_VALUE + 2, config.entryAddress);
            try { new RawImportConfig(custom.id, Long.MIN_VALUE, Long.MIN_VALUE + 1); fail("custom instruction alignment required"); }
            catch (IllegalArgumentException expected) { assertTrue(expected.getMessage().contains("align")); }
        } finally { RawImportConfig.installArchitectures(new RawArchitecture[0]); }
        try { new RawImportConfig(custom.id, 0, 0); fail("cold snapshot cannot guess custom decoder"); }
        catch (IllegalArgumentException expected) { assertTrue(expected.getMessage().contains("reload")); }
    }
    @Test public void custom32BitDecoderRetainsWidthAndAtomicSnapshotValidation() {
        RawArchitecture custom = new RawArchitecture("unit-custom32", "Unit decoder32", 202, 4, 4, 4, 4, false);
        try {
            RawImportConfig.installArchitectures(new RawArchitecture[]{custom});
            assertEquals(custom.id, new RawImportConfig(custom.id, 0xfffffff0L, 0xfffffff4L).architecture);
            try { new RawImportConfig(custom.id, 0x100000000L, 0x100000000L); fail("custom32-bit overflow rejected"); }
            catch (IllegalArgumentException expected) { assertTrue(expected.getMessage().contains("32-bit")); }
            try { RawImportConfig.installArchitectures(new RawArchitecture[]{custom, custom}); fail("duplicate snapshot rejected"); }
            catch (IllegalArgumentException expected) { assertEquals(custom.id, new RawImportConfig(custom.id, 0, 0).architecture); }
            RawArchitecture replacement = new RawArchitecture("aarch64", "Unsafe replacement", 1, 4, 4, 4, 4, false);
            try { RawImportConfig.installArchitectures(new RawArchitecture[]{replacement}); fail("built-in ABI immutable"); }
            catch (IllegalArgumentException expected) { assertEquals(custom.id, new RawImportConfig(custom.id, 0, 0).architecture); }
        } finally { RawImportConfig.installArchitectures(new RawArchitecture[0]); }
    }
    @Test(expected=IllegalArgumentException.class) public void rejectsInvalidCustomDescriptorAlignment() {
        new RawArchitecture("unit-bad", "Bad decoder", 203, 8, 4, 8, 3, false);
    }
}
