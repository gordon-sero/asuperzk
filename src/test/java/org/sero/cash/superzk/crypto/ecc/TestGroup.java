package org.sero.cash.superzk.crypto.ecc;

import java.math.BigInteger;

import org.junit.Test;
import org.sero.cash.superzk.util.Arrays;

public class TestGroup {

    @Test
    public void test() {
        test_mul(1, 258, 6);
        test_mul(3, 90, 5);
        test_mul(4, 128, 8);
        test_mul(1, 256, 8);
    }

    public void test_mul(int snum, int bitnum, int cnum) {
        Group group = new Group("258_1_6".getBytes(), snum, bitnum, cnum);

        int bitCount = snum * bitnum;
        for (int i = 0; i < 1; i++) {
            int ceil = (int) Math.ceil(bitCount / 8.0);
            byte[] buf = Arrays.randomBytes(ceil);
            Point ret = group.mult(new BitBuffer(buf, 0, bitCount));
            if (ret == null) {
                assert (false);
            }

            Point pt = Point.ZERO;
            for (int j = 0; j < snum; j++) {
                // @ts-ignore
                Point base = group.indexPoints.get(j).get("1");
                if (base != null) {
                    BigInteger val = new BitBuffer(buf, j * bitnum, bitnum).toBigInteger();
                    pt = pt.add(base.mult(Field.newFR(val)));
                } else {
                    assert (false);
                }
            }
            assert (pt.isEqualTo(ret));
        }
    }
}
