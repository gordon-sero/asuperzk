package org.sero.cash.superzk.crypto.ecc;

import java.math.BigInteger;

import org.junit.Test;
import org.sero.cash.superzk.util.Arrays;
import org.sero.cash.superzk.util.HexUtils;

public class TestEddsa {

    @Test
    public void test() {
        Group base0 = new Group("5dfbb35a38ffdcab".getBytes(), 1, 256, 8);
        Group base1 = new Group("7f9f2ebf9cb5e28a".getBytes(), 1, 256, 8);

        Field.FR sk = Field.newFR("20205729828150001148051822792008367049313441672068972729859762844264164030");
        byte[] msg = HexUtils.toBytes("0x9e282094f9be08ee6d0340902b8ab8fe57ad82f63700e7d762c1742ec5cca97f");
        byte[] s_ret = Eddsa.sign(msg, sk, base0, base1);
        System.out.println(HexUtils.toHex(s_ret));
    }

    @Test
    public void testEddsa_n() {
        Group base0 = new Group("5dfbb35a38ffdcab".getBytes(), 1, 256, 8);
        Group base1 = new Group("7f9f2ebf9cb5e28a".getBytes(), 1, 256, 8);
        for (int i = 0; i < 100; i++) {
            Field.FR sk = Field.newFR(new BigInteger(Arrays.randomBytes(32)));

            byte[] msg = Arrays.randomBytes(32);
            Point pk0 = base0.mult(sk);
            Point pk1 = base1.mult(sk);

            byte[] s_ret = Eddsa.sign(msg, sk, base0, base1);
            assert (Eddsa.verify(msg, s_ret, pk0, pk1, base0, base1));
        }
    }


    @Test
    public void testEddsa() {
        Group base = new Group("5dfbb35a38ffdcab".getBytes(), 1, 256, 8);
        for (int i = 0; i < 100; i++) {
            Field.FR sk = Field.newFR(Arrays.randomBytes(32));

            byte[] msg = Arrays.randomBytes(32);
            Point pk = base.mult(sk);

            byte[] s_ret = Eddsa.sign(msg, sk, base);
            assert (Eddsa.verify(msg, s_ret, pk, base));
        }
    }

}
