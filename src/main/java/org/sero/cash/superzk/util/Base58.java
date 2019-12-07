package org.sero.cash.superzk.util;

public class Base58 {

    public static String encode(byte[] bytes) {
        return io.github.novacrypto.base58.Base58.base58Encode(bytes);
    }

    public static byte[] decode(String base58) {
        return io.github.novacrypto.base58.Base58.base58Decode(base58);
    }
}
