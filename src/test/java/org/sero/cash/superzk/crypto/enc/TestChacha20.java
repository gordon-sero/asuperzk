package org.sero.cash.superzk.crypto.enc;

import org.junit.Test;
import org.sero.cash.superzk.util.Arrays;
import org.sero.cash.superzk.util.HexUtils;

public class TestChacha20 {

    @Test
    public void test() {
//        byte[] key = Arrays.rightPadBytes("12345".getBytes(), 32);
//        byte[] plaintext = Arrays.rightPadBytes("hello".getBytes(), 64);
//
//        byte[] ciphertext = Chacha20.encode(plaintext, key);
//        System.out.println(HexUtils.toHex(ciphertext));
//        byte[] plaintext1 = Chacha20.encode(ciphertext, key);
//
//        assertTrue(Arrays.equals(plaintext, plaintext1));
        
        byte[] data = HexUtils.toBytes("9ceb6ab7032924fa400fd7d4632001c43be58c0e15bd1cc4ea5542236ff5c1754d881670ed49038bfb1104456c94a9a9789ddfc84155328130dad573f740e7c7349db73fc54fd58a644d12d7d10604bda612329f5a7de6dca23b0cbd6d1f8d3bcaea7963abeb2553ddafc9ae1cf2603dc1e5ff68d54495e3b34fb85e7f77125c4353f3bacabd11bcd15f8728cdc79ac1b8b2208f5d9e4089075994d16b4707ef86e53646e5a483c811b688288f9d75902f3fc1abcb3f5da156120016fabbc9fd972004b5911af6502546f66f705563884c05276d2505366dfbfbc76c2f60b731");
        byte[] key1 = HexUtils.toBytes("295347716100f72917c9d8e568001e69b02df978152349e8838272f80096b14f");
        byte[] info = Chacha20.encode(data, key1);
        Arrays.println(data);
        System.out.println(HexUtils.toHex(info));
//        
    }
}
