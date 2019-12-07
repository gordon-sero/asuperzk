package org.sero.cash.superzk.crypto.ecc;

import org.sero.cash.superzk.crypto.Blake;
import org.sero.cash.superzk.util.Arrays;

public class Eddsa {

    private static byte[] hash_1(byte[] input) {
        return Blake.blake2b("SZK$DSA$HASH1".getBytes(), input);
    }

    private static byte[] hash_2(byte[] input) {
        return Blake.blake2b("SZK$DSA$HASH2".getBytes(), input);
    }

    private static byte[] hash_1_n(byte[] input) {
        return Blake.blake2b("SZK$DSAN$HASH1".getBytes(), input);
    }

    private static byte[] hash_2_n(byte[] input) {
        return Blake.blake2b("SZK$DSAN$HASH2".getBytes(), input);
    }


    public static byte[] sign(byte[] msg, Field.FR sk, Mult base0, Mult base1) {
        byte[] buf1 = Arrays.concat(Arrays.randomBytes(32), sk.toBytes(), msg);
        Field.FR frA = Field.newFR(hash_1_n(buf1));
        Point R0 = base0.mult(frA);
        if (R0 == null || R0.isZero() || !R0.isValid()) {
            return null;
        }
        Point R1 = base1.mult(frA);
        if (R1 == null || R1.isZero() || !R1.isValid()) {
            return null;
        }
        Point PK0 = base0.mult(sk);
        if (PK0 == null || PK0.isZero() || !PK0.isValid()) {
            return null;
        }
        Point PK1 = base1.mult(sk);
        if (PK1 == null || PK1.isZero() || !PK1.isValid()) {
            return null;
        }

        byte[] buf2 = Arrays.concat(R0.toBytes(), R1.toBytes(), PK0.toBytes(), PK1.toBytes(), msg);
        Field.FR S = frA.add(sk.mul(Field.newFR(hash_2_n(buf2))));
        return Arrays.concat(S.toBytes(), R0.toBytes(), R1.toBytes());
    }

    public static boolean verify(byte[] msg, byte[] sign, Point pk0, Point pk1, Mult base0, Mult base1) {
        assert (sign.length == 96);

        if (pk0 == null || pk0.isZero() || !pk0.isValid()) {
            return false;
        }
        if (pk1 == null || pk1.isZero() || !pk1.isValid()) {
            return false;
        }
        Field.FR S = Field.newFR(Arrays.slice(sign, 0, 32));
        Point R0 = Point.fromBytes(Arrays.slice(sign, 32, 64));
        Point R1 = Point.fromBytes(Arrays.slice(sign, 64, 96));

        if (S == null || S.isZero()) {
            return false;
        }
        if (R0 == null || R0.isZero() || !R0.isValid()) {
            return false;
        }
        if (R1 == null || R1.isZero() || !R1.isValid()) {
            return false;
        }

        Point SB0 = base0.mult(S);
        if (SB0 == null || SB0.isZero() || !SB0.isValid()) {
            return false;
        }
        Point SB1 = base1.mult(S);
        if (SB1 == null || SB1.isZero() || !SB1.isValid()) {
            return false;
        }

        byte[] buf = Arrays.concat(R0.toBytes(), R1.toBytes(),pk0.toBytes(), pk1.toBytes(), msg);
        Field.FR m = Field.newFR(hash_2_n(buf));
        Point ma0 = pk0.mult(m);
        Point right0 = R0.add(ma0);
        if (!SB0.isEqualTo(right0)) {
            return false;
        }

        Point ma1 = pk1.mult(m);
        Point right1 = R1.add(ma1);
        if (!SB1.isEqualTo(right1)) {
            return false;
        }

        return true;
    }


	public static byte[] sign(byte[] msg, Field.FR sk, Mult base) {
		byte[] buf1 = Arrays.concat(Arrays.randomBytes(32), sk.toBytes(), msg);
		
		Field.FR frA = Field.newFR(hash_1(buf1));
		
		
		Point R = base.mult(frA);
		
		if (R == null) {
			return null;
		}
		Point PK = base.mult(sk);
		if (PK == null || !PK.isValid()) {
			return null;
		}
		byte[] buf2 = Arrays.concat(R.toBytes(), PK.toBytes(), msg);
		Field.FR frM = Field.newFR(hash_2(buf2));
		Field.FR S = frA.add(sk.mul(frM));
		return Arrays.concat(R.toBytes(), S.toBytes());
	}

    public static boolean verify(byte[] msg, byte[] sign, Point pk, Mult base) {
        assert (sign.length == 64);

        if (pk.isZero()) {
            return false;
        }
        Point R = Point.fromBytes(Arrays.slice(sign, 0, 32));
        if (R == null || R.isZero() || !R.isValid()) {
            return false;
        }
        Field.FR S = Field.newFR(Arrays.slice(sign, 32, 64));
        if (S.isZero()) {
            return false;
        }
        Point sb = base.mult(S);
        if (sb.isZero() || !sb.isValid()) {
            return false;
        }
        byte[] buf = Arrays.concat(R.toBytes(), pk.toBytes(), msg);
        Field.FR m = Field.newFR(hash_2(buf));
        Point ma = pk.mult(m);
        Point right = R.add(ma);
        if (sb.isEqualTo(right)) {
            return true;
        } else {
            return false;
        }
    }
}
