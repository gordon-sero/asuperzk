package org.sero.cash.superzk.util;

import java.math.BigInteger;

import org.spongycastle.util.encoders.Hex;

public class HexUtils {
    public static String toHex(byte[] data) {
        return "0x" + Hex.toHexString(data);
    }

    public static String toHex(BigInteger val) {
        return "0x" + Hex.toHexString(val.toByteArray());
    }



    public static byte[] toBytes(String hex) {
        if (hex.startsWith("0x")) {
            hex = hex.substring(2);
        }
        return Hex.decode(hex);
    }


}
