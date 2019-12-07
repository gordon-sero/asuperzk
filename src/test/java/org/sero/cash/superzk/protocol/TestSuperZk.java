package org.sero.cash.superzk.protocol;

import static org.junit.Assert.assertTrue;

import org.junit.Test;
import org.sero.cash.superzk.crypto.ecc.Field;
import org.sero.cash.superzk.crypto.ecc.Point;
import org.sero.cash.superzk.protocol.superzk.Account;
import org.sero.cash.superzk.protocol.superzk.SuperZk;
import org.sero.cash.superzk.util.Arrays;
import org.spongycastle.util.encoders.Hex;

public class TestSuperZk {
    public static byte[] seed_arg = Hex.decode("4325491eae1136dd99fbbcc4c2748fff7ed1ff4f4b3e93ef173e34b33fd30e4a");

    public static byte[] sk_arg = Hex.decode(
            "ed676f034883c55cd7d79c68fc967d1c1cd6f26b6b24224ca3f049fff7c26704cfaa945ccc4daf598b2f28aa60e11cdea37928c6d1ed3fcdf687aa3bb60b2a03"
    );

    public static byte[] tk_arg = Hex.decode(
            "d4804429371f3f75070f39df542a3bcc9703acdee7a8e2133d5970a787294e0acfaa945ccc4daf598b2f28aa60e11cdea37928c6d1ed3fcdf687aa3bb60b2a03"
    );

    public static byte[] pk_arg = Hex.decode(
            "d4804429371f3f75070f39df542a3bcc9703acdee7a8e2133d5970a787294e0a99cecfb457217252559b4add3db14f33d5957bd870922ff654ef4f83241d88d7"
    );
    public static String r_arg = "81cc09a7d57b43ece33f351303eb4f08e799c77d976c2b7c691340cfa3e5a124";
    public static byte[] pkr_arg = Hex.decode(
            "bb8361c41579cd2a6c2570dd68966dde25a1696e9a9f2d208324a77514631a1030edbef4f929c0873cc70c38fd53b273c4e2279a652da2843bbf97c36f60b88ab020ea6b184ff73ef4b1da1095bbf0b324befa5f81e5479f84d1ba783276d0cb"
    );

    @Test
    public void testSeed2Sk() {
        Account.SK sk = Account.seed2SK(seed_arg);
        assertTrue(Arrays.equals(sk.toBytes(), Param.setFlag(sk_arg)));
    }

    @Test
    public void testSk2TK() {
        Account.SK sk = Account.seed2SK(seed_arg);
        AccountType.TK tk = sk.toTK();
        assertTrue(Arrays.equals(tk.toBytes(), Param.setFlag(tk_arg)));
    }

    @Test
    public void testTk2PK() {
        Account.TK tk = new Account.TK(tk_arg);
        AccountType.PK pk = tk.toPK();
        assertTrue(Arrays.equals(pk.toBytes(), Param.setFlag(pk_arg)));
    }

    @Test
    public void testCreatePKr() {
        Account.TK tk = new Account.TK(tk_arg);
        Account.PK pk = new Account.PK(pk_arg);
        AccountType.PKr pkr = pk.createPKr(Field.newFR(Hex.decode(r_arg)));
        assertTrue(Arrays.equals(pkr.toBytes(), Param.setFlag(pkr_arg)));
        assertTrue(tk.isMyPKr(pkr));
    }

    @Test
    public void testSignPKr() {
        byte[] h = Arrays.randomBytes(32);
        Account.SK sk = Account.seed2SK(seed_arg);
        Account.PKr pkr = new Account.PKr(pkr_arg);
        byte[] sign_pkr = SuperZk.signPKr(sk, h, pkr);
        assertTrue(sign_pkr != null);
        assertTrue(SuperZk.verifyPKr(h, sign_pkr, pkr));
    }

    @Test
    public void testGenNil() {

        Point cm = Point.randomPt();
        Account.TK tk = new Account.TK(tk_arg);
        Account.PKr pkr = new Account.PKr(pkr_arg);
        byte[] nil = SuperZk.genNil(tk, cm, pkr);
        assertTrue(nil != null);

        byte[] h = Arrays.randomBytes(32);
        byte[] sign_nil = SuperZk.signNil(h, tk, cm, pkr);
        assertTrue(sign_nil != null);

        assertTrue(SuperZk.verifyNil(h, sign_nil, nil, cm, pkr));
    }


    @Test
    public void testSignZPKa() {
        Field.FR a = Field.randomFR();
        Account.PKr pkr = new Account.PKr(pkr_arg);
        Point zpka = SuperZk.genZPKa(pkr, a);

        assertTrue(zpka != null);
        byte[] h = Arrays.randomBytes(32);
        Account.SK sk = Account.seed2SK(seed_arg);
        byte[] sign_zpka = SuperZk.signZPKa(h, sk, a, pkr);

        assertTrue(sign_zpka != null);

        assert (SuperZk.verifyZPKa(h, sign_zpka, zpka));
    }

    @Test
    public void testFetchKey() {
        Account.TK tk = new Account.TK(tk_arg);
        Account.PKr pkr = new Account.PKr(pkr_arg);
        Field.FR rsk = Field.randomFR();
        byte[][] key_pair = SuperZk.genPKrKey(pkr, rsk);

        byte[] key = SuperZk.fetchRPKKey(pkr, tk, key_pair[1]);
        assertTrue(Arrays.equals(key, key_pair[0]));
    }
}
