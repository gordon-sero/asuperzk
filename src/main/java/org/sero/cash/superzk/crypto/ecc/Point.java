package org.sero.cash.superzk.crypto.ecc;


import java.math.BigInteger;

import org.sero.cash.superzk.crypto.Blake;
import org.sero.cash.superzk.json.HexType;
import org.sero.cash.superzk.util.Arrays;
import org.sero.cash.superzk.util.HexUtils;

public class Point implements Mult, HexType {
    public static Field.FQ ECC_A = Field.newFQ(Constants.ECC_A);
    public static Field.FQ ECC_D = Field.newFQ(Constants.ECC_D);
    public static Point ZERO = new Point(Field.FQ.ZERO, Field.FQ.ONE, Field.FQ.ONE);

    private Field.FQ x;
    private Field.FQ y;
    private Field.FQ z;

    public Point(Field.FQ x, Field.FQ y, Field.FQ z) {
        this.x = x;
        this.y = y;
        this.z = z;
    }

    public Point add(Point point) {
        Field.FQ x1 = this.x;
        Field.FQ y1 = this.y;
        Field.FQ z1 = this.z;

        Field.FQ x2 = point.x;
        Field.FQ y2 = point.y;
        Field.FQ z2 = point.z;

        Field.FQ c = x1.mul(x2);
        Field.FQ d = y1.mul(y2);
        Field.FQ e = Point.ECC_D.mul(c).mul(d);

        if (z1.isEqualTo(Field.FQ.ONE) && z2.isEqualTo(Field.FQ.ONE)) {
            return new Point(
                    Field.FQ.ONE.sub(e).mul(x1.add(y1).mul(x2.add(y2)).sub(c).sub(d)),
                    Field.FQ.ONE.add(e).mul(d.sub(Point.ECC_A.mul(c))),
                    Field.FQ.ONE.sub(e.square())
            );
        } else {
            if (z2.isEqualTo(Field.FQ.ONE)) {
                Field.FQ b = z1.square();
                Field.FQ f = b.sub(e);
                Field.FQ g = b.add(e);

                return new Point(
                        z1.mul(f).mul(x1.add(y1).mul(x2.add(y2)).sub(c).sub(d)),
                        z1.mul(g).mul(d.sub(Point.ECC_A.mul(c))),
                        f.mul(g)
                );
            } else {
                Field.FQ a = z1.mul(z2);
                Field.FQ b = a.square();
                Field.FQ f = b.sub(e);
                Field.FQ g = b.add(e);

                return new Point(
                        a.mul(f).mul(x1.add(y1).mul(x2.add(y2)).sub(c).sub(d)),
                        a.mul(g).mul(d.sub(Point.ECC_A.mul(c))),
                        f.mul(g)
                );
            }
        }
    }

    public Point twice() {
        Field.FQ b = this.x.add(this.y).square();
        Field.FQ c = this.x.square();
        Field.FQ d = this.y.square();
        Field.FQ e = Point.ECC_A.mul(c);
        Field.FQ f = e.add(d);

        if (this.z.isEqualTo(Field.FQ.ONE)) {
            return new Point(
                    b.sub(c).sub(d).mul(f.sub(Field.FQ.TWO)),
                    f.mul(e.sub(d)),
                    f.square().sub(f.mul(Field.FQ.TWO))
            );
        } else {
            Field.FQ h = this.z.square();
            Field.FQ j = f.sub(h.mul(Field.FQ.TWO));
            return new Point(
                    b.sub(c).sub(d).mul(j),
                    f.mul(e.sub(d)),
                    f.mul(j)
            );
        }
    }

    public Point mult(Field.FR val) {
        BigInteger scalar = val.toBigNumber();
        Point p = this;
        Point a = Point.ZERO;

        while (scalar.signum() != 0) {
            if (scalar.testBit(0)) {
                a = a.add(p);
            }
            scalar = scalar.shiftRight(1);
            if (scalar.signum() == 0) {
                break;
            }
            p = p.twice();
        }
        return a;
    }

    public boolean isValid() {
        Field.FQ xx = this.x.mul(this.x);
        Field.FQ yy = this.y.mul(this.y);
        Field.FQ zz = this.z.mul(this.z);
        Field.FQ axx = Point.ECC_A.mul(xx);
        Field.FQ zzzz = zz.mul(zz);
        Field.FQ dxxyy = Point.ECC_D.mul(xx).mul(yy);
        Field.FQ left = zz.mul(axx.add(yy));
        Field.FQ right = zzzz.add(dxxyy);
        if (left.isEqualTo(right)) {
            return true;
        } else {
            return false;
        }
    }

    public boolean isEqualTo(Point point) {
        if (this.x.mul(point.z).isEqualTo(this.z.mul(point.x))) {
            if (this.y.mul(point.z).isEqualTo(this.z.mul(point.y))) {
                return true;
            }
        }
        return false;
    }

    public boolean isZero() {
        return this.isEqualTo(Point.ZERO);
    }

    public byte[] toBytes() {
        Field.FQ inv_z = this.z.invert();
        Field.FQ x = this.x.mul(inv_z);
        Field.FQ y = this.y.mul(inv_z);

        byte[] buf = y.toBytes();
        if (x.isOdd()) {
            buf[31] |= 1 << 7;
        }
        return buf;
    }

    public String toString() {
        byte[] data = this.toBytes();
        return HexUtils.toHex(data);
    }

    public static Point fromHex(String hex) {
        return Point.fromBytes(HexUtils.toBytes(hex));
    }

    public static Point fromBytes(byte[] data) {
        assert (data.length == 32);
        int sign = (data[31] >> 7) & 0x1;
        data[31] &= ~0x80;

        Field.FQ v = Field.newFQ(data);
        Field.FQ vv = v.mul(v);
        Field.FQ vvd = Point.ECC_D.mul(vv);
        Field.FQ u2 = vv.sub(Field.FQ.ONE).mul(vvd.sub(Point.ECC_A).invert());
        Field.FQ st = u2.sqrt();
        if (st == null) {
            return null;
        }

        Field.FQ u = st;
        if (st.isOdd() != (sign != 0)) {
            u = Field.FQ.ZERO.sub(st);
        }
        return new Point(u, v, Field.FQ.ONE);
    }

    public static Point randomPt() {
        while (true) {
            byte[] data = Arrays.randomBytes(32);
            Point pt = Blake2b.findPoint("randomPT".getBytes(), data);
            if (pt != null) {
                return pt;
            }
        }
    }

    private static Field.FR scalar = Field.newFR(8);

    public static class Blake2b {

        public static Point genPoint(byte[] personal, byte[] data) {
            data = Arrays.concat(Constants.CRS, data);
            byte[] buf = Blake.blake2b(personal, data);
            Point point = Point.fromBytes(buf);
            if (point != null) {
                point = point.mult(scalar);
                if (!point.isEqualTo(Point.ZERO)) {
                    return point;
                }
            }
            return null;
        }

        public static Point findPoint(byte[] personal, byte[] data) {
            assert (personal.length <= 16 && data.length == 32);
            byte[] temp = Arrays.copy(data);
            for (int i = 0; true; i++) {
                temp[31] += i;
                Point point = Blake2b.genPoint(personal, temp);
                if (point != null) {
                    return point;
                }
                if (i > 256) {
                    return null;
                }
            }
        }
    }

    public static class Blake2s {

        private static Point genPoint(byte[] personal, byte[] data) {
            byte[] buf = Blake.blake2s(personal, data);
            buf[31] &= 0x9f;
            Point point = Point.fromBytes(buf);
            if (point != null && !point.isZero() && point.isValid()) {
                return point.mult(scalar);
            }
            return null;
        }

        public static Point findPoint(byte[] personal, byte[] data) {
            assert (personal.length <= 8 && data.length == 64);
            byte[] temp = Arrays.copy(data);
            for (int i = 0; i < 256; i++) {
                temp[63] = (byte) (i & 0xff);
                Point point = genPoint(personal, temp);
                if (point != null) {
                    return point;
                }
            }
            return null;
        }
    }
}
