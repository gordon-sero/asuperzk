package org.sero.cash.superzk.crypto;

import org.sero.cash.superzk.util.Arrays;

import com.rfksystems.blake2b.Blake2b;

public class Blake {

    public static byte[] blake2b(byte[] personal, byte[] data) {
        byte[] p = Arrays.rightPadBytes(personal, 16);
        Blake2b blake2b = new Blake2b(null, 32, null, p);
        blake2b.update(data, 0, data.length);
        byte[] out = new byte[32];
        blake2b.digest(out, 0);
        return out;
    }

    public static byte[] blake2s(byte[] personal, byte[] data) {
        byte[] p = Arrays.rightPadBytes(personal, 8);
        Blake2s blake2s = new Blake2s(32, new byte[8], p);
        blake2s.update(data, data.length);
        return blake2s.digest();
    }
}
