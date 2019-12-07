package org.sero.cash.superzk.crypto.ecc;

import java.math.BigInteger;
import java.util.Random;

import org.sero.cash.superzk.json.HexType;
import org.sero.cash.superzk.util.Arrays;
import org.sero.cash.superzk.util.HexUtils;

public class Field<T extends Field<?>> {
    public BigInteger x;
    public BigInteger q;

    public static class FQ extends Field<FQ> {

        public static FQ ONE = newFQ(BigInteger.valueOf(1));
        public static FQ ZERO = newFQ(BigInteger.valueOf(0));
        public static FQ TWO = newFQ(BigInteger.valueOf(2));

        private FQ(String val) {
            this(new BigInteger(val, 10));
        }

        private FQ(String val, int base) {
            this(new BigInteger(val, base));
        }

        private FQ(BigInteger x) {
            super(x, Constants.FQ_MODULUS);
        }
    }

    public static class FR extends Field<FR> implements HexType {
        public static FR ONE = newFR(BigInteger.valueOf(1));
        public static FR ZERO = newFR(BigInteger.valueOf(0));


        private FR(String val) {
            this(new BigInteger(val, 10));
        }

        private FR(String val, int base) {
            this(new BigInteger(val, base));
        }

        private FR(BigInteger x) {
            super(x, Constants.FR_MODULUS);
        }
    }

    public static FR randomFR() {
        return Field.newFR(Arrays.randomBytes(32));
    }

    public static FQ newFQ(long n) {
        return new FQ(BigInteger.valueOf(n));
    }

    public static FQ newFQ(byte[] data) {
        return new FQ(new BigInteger(1, Arrays.reverse(data)));
    }

    public static FQ newFQ(String val) {
        return new FQ(new BigInteger(val, 10));
    }

    public static FQ newFQ(String val, int base) {
        return new FQ(new BigInteger(val, base));
    }

    public static FQ newFQ(BigInteger x) {
        return new FQ(x);
    }

    public static FR newFR(byte[] data) {
        return new FR(new BigInteger(1, Arrays.reverse(data)));
    }

    public static FR newFR(long n) {
        return new FR(BigInteger.valueOf(n));
    }

    public static FR newFR(String val) {
        return new FR(new BigInteger(val, 10));
    }

    public static FR newFR(String val, int base) {
        return new FR(new BigInteger(val, base));
    }

    public static FR newFR(BigInteger x) {
        return new FR(x);
    }

    private Field(BigInteger x, BigInteger q) {
        this.x = x.mod(q);
        this.q = q;
    }

    @SuppressWarnings({ "unchecked"})
	private T newInstance(BigInteger val) {
        if (this.getClass().equals(FQ.class)) {
            return (T) new FQ(val);
        } else {
            return (T) new FR(val);
        }
    }

    public T add(T val) {
        return newInstance(this.x.add(val.x));
    }

    public T mul(T val) {
        return newInstance(this.x.multiply(val.x));
    }

    public T sub(T val) {
        return newInstance(this.x.subtract(val.x));
    }

    public T div(T val) {
        return newInstance(this.x.divide(val.x));
    }

    public T negate() {
        return newInstance(this.x.negate());
    }

    public T square() {
        return newInstance(this.x.multiply(this.x));
    }

    public T invert() {
        return newInstance(this.x.modInverse(this.q));
    }

    public T pow() {
        return newInstance(this.x.pow(2));
    }

    public T sqrt() {
        if (this.isZero()) {
            return newInstance(BigInteger.ZERO);
        }
        // p mod 4 == 3
        if (q.testBit(1)) {
            T z = newInstance(this.x.modPow(this.q.shiftRight(2).add(Constants.ONE), this.q));
            return z.square().equals(this) ? z : null;
        }

        // p mod 4 == 1
        BigInteger qMinusOne = this.q.subtract(Constants.ONE);
        BigInteger legendreExponent = qMinusOne.shiftRight(1);
        if (!(this.x.modPow(legendreExponent, this.q).equals(Constants.ONE))) {
            return null;
        }

        BigInteger u = qMinusOne.shiftRight(2);
        BigInteger k = u.shiftLeft(1).add(Constants.ONE);

        BigInteger Q = this.x;
        BigInteger fourQ = Q.shiftLeft(2).mod(this.q);

        BigInteger U, V;
        Random rand = new Random();
        do {
            BigInteger P;
            do {
                P = new BigInteger(this.q.bitLength(), rand);
            } while (P.compareTo(this.q) >= 0 || !(P.multiply(P).subtract(fourQ).modPow(legendreExponent, this.q).equals(qMinusOne)));

            BigInteger[] result = lucasSequence(this.q, P, Q, k);
            U = result[0];
            V = result[1];

            if (V.multiply(V).mod(this.q).equals(fourQ)) {
                if (V.testBit(0)) {
                    V = V.add(this.q);
                }
                V = V.shiftRight(1);
                return newInstance(V);
            }
        } while (U.equals(Constants.ONE) || U.equals(qMinusOne));
        return null;
    }

    public BigInteger toBigNumber() {
        return this.x;
    }

    public byte[] toBytes() {
        return Arrays.rightPadBytes(Arrays.reverse(this.x.toByteArray()), 32);
    }

    public String toString() {
        return HexUtils.toHex(this.toBytes());
    }

    public boolean isOdd() {
        return this.x.testBit(0);
    }

    public boolean isZero() {
        return this.x.signum() == 0;
    }

    public boolean isEqualTo(Field<?> f) {
        return this.x.compareTo(f.x) == 0;
    }

    private static BigInteger[] lucasSequence(BigInteger p, BigInteger P, BigInteger Q, BigInteger k) {
        int n = k.bitLength();
        int s = k.getLowestSetBit();

        BigInteger Uh = Constants.ONE;
        BigInteger Vl = Constants.TWO;
        BigInteger Vh = P;
        BigInteger Ql = Constants.ONE;
        BigInteger Qh = Constants.ONE;

        for (int j = n - 1; j >= s + 1; --j) {
            Ql = Ql.multiply(Qh).mod(p);

            if (k.testBit(j)) {
                Qh = Ql.multiply(Q).mod(p);
                Uh = Uh.multiply(Vh).mod(p);
                Vl = Vh.multiply(Vl).subtract(P.multiply(Ql)).mod(p);
                Vh = Vh.multiply(Vh).subtract(Qh.shiftLeft(1)).mod(p);
            } else {
                Qh = Ql;
                Uh = Uh.multiply(Vl).subtract(Ql).mod(p);
                Vh = Vh.multiply(Vl).subtract(P.multiply(Ql)).mod(p);
                Vl = Vl.multiply(Vl).subtract(Ql.shiftLeft(1)).mod(p);
            }
        }

        Ql = Ql.multiply(Qh).mod(p);
        Qh = Ql.multiply(Q).mod(p);
        Uh = Uh.multiply(Vl).subtract(Ql).mod(p);
        Vl = Vh.multiply(Vl).subtract(P.multiply(Ql)).mod(p);
        Ql = Ql.multiply(Qh).mod(p);

        for (int j = 1; j <= s; ++j) {
            Uh = Uh.multiply(Vl).mod(p);
            Vl = Vl.multiply(Vl).subtract(Ql.shiftLeft(1)).mod(p);
            Ql = Ql.multiply(Ql).mod(p);
        }

        return new BigInteger[]{Uh, Vl};
    }


}
