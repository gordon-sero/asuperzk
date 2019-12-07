package org.sero.cash.superzk.util;

import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class TestArrays {
    @Test
    public void testRandomBytes() {
    }

    @Test
    public  void testStringToByte32() {
        byte[] bytes = Arrays.stringToByte32("SER0O0");
        String s = Arrays.byte32ToString(bytes);
        assertTrue(s.compareTo("SER0O0") == 0);

    }
}
