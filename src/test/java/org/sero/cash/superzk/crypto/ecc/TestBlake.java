package org.sero.cash.superzk.crypto.ecc;

import static org.junit.Assert.assertTrue;

import org.junit.Test;
import org.sero.cash.superzk.crypto.Blake;
import org.sero.cash.superzk.util.Arrays;
import org.spongycastle.util.encoders.Hex;

public class TestBlake {

    @Test
    public void testBlake2b() {
        byte[] data = Arrays.rightPadBytes(new byte[]{1}, 32);
        byte[] bytes = Blake.blake2b("123456789abc".getBytes(), data);
        assertTrue(new String(Hex.encode(bytes)).compareTo("0c3d6a0a75673fcf6c0a9fa36b95cb5b80ecd0fcebc4772f6a6e341edfd634cb") == 0);
    }

    @Test
    public void testBlake2s() {
        byte[] data = Arrays.rightPadBytes(new byte[]{1}, 64);
        byte[] bytes = Blake.blake2s("12345678".getBytes(), data);
        assertTrue(new String(Hex.encode(bytes)).compareTo("d21ab6f5841a2cf04712307b2021e6f24fd87e09f8c0eb1a3f007eab65e2cb22") == 0);

        bytes = Blake.blake2s("12345678".getBytes(), data);
        assertTrue(new String(Hex.encode(bytes)).compareTo("d21ab6f5841a2cf04712307b2021e6f24fd87e09f8c0eb1a3f007eab65e2cb22") == 0);
    }
}
