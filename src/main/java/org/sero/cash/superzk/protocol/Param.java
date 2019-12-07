package org.sero.cash.superzk.protocol;

import org.sero.cash.superzk.crypto.Blake;
import org.sero.cash.superzk.crypto.ecc.BitBuffer;
import org.sero.cash.superzk.crypto.ecc.Eddsa;
import org.sero.cash.superzk.crypto.ecc.Field;
import org.sero.cash.superzk.crypto.ecc.Group;
import org.sero.cash.superzk.crypto.ecc.Point;
import org.sero.cash.superzk.protocol.superzk.Account;
import org.sero.cash.superzk.util.Arrays;


public class Param {
    public static Group accountBase = new Group("$SROKEYSGEN".getBytes(), 1, 256, 4);
    public static Group crBase = new Group("SZK$ASSET$CR".getBytes(), 1, 256, 4);
    public static Group rootBase = new Group("SZK$ROOTCM".getBytes(), 10, 128, 4);


    public static byte[] setFlag(byte[] buf) {
        buf[buf.length - 1] |= 0x1 << 6;
        return buf;
    }

    public static void clearFlag(byte[] buf) {
        buf[buf.length - 1] &= ~(0x1 << 6);
    }

    public static boolean isFlagSet(byte[] buf) {
        return (buf[buf.length - 1] & (0x1 << 6)) != 0;
    }


    public static byte[] hashIndex(int index) {
        return Blake.blake2b("SZK$ROOT$INDEX".getBytes(), Arrays.intToByteLE(index));
    }

    public static Point genRootCM(int index, Account.PKr pkr, Point asset_cm) {
        byte[] inde_hash = hashIndex(index);
        byte[] data = Arrays.concat(inde_hash, pkr.toBytes(), asset_cm.toBytes());
        BitBuffer bits = new BitBuffer(data);
        return rootBase.mult(bits);
    }

    public static byte[][] signBalance(byte[] h, Types.Params params) {
        assert (h.length == 32);
        assert (params.zin_acms.size() == params.zin_ars.size());
        assert (params.zout_acms.size() == params.zout_ars.size());

        Point zin_acm = Point.ZERO;
        Field.FR zin_ar = Field.FR.ZERO;

        for (int i = 0; i < params.zin_ars.size(); i++) {
            zin_acm = zin_acm.add(params.zin_acms.get(i));
            zin_ar = zin_ar.add(params.zin_ars.get(i));
        }

        Point zout_acm = Point.ZERO;
        Field.FR zout_ar = Field.FR.ZERO;
        for (int i = 0; i < params.zout_ars.size(); i++) {
            zout_acm = zout_acm.add(params.zout_acms.get(i));
            zout_ar = zout_ar.add(params.zout_ars.get(i));
        }

        Point oin_acc = Point.ZERO;
        for (int i = 0; i < params.oin_accs.size(); i++) {
            oin_acc = oin_acc.add(params.oin_accs.get(i));
        }

        Point oout_acc = Point.ZERO;
        for (int i = 0; i < params.oout_accs.size(); i++) {
            oout_acc = oout_acc.add(params.oout_accs.get(i));
        }

        Point zacm = zin_acm.add(zout_acm.mult(Field.FR.ONE.negate()));
        Field.FR zar = zin_ar.add(zout_ar.negate());
        if (zar.isZero()) {
            return null;
        }

        Point oacc = oout_acc.add(oin_acc.mult(Field.FR.ONE.negate()));
        Point bcr = crBase.mult(zar);
        Point oacm = oacc.add(bcr);

        if (!oacm.isEqualTo(zacm)) {
            return null;
        }

        byte[] bsign = Eddsa.sign(h, zar, crBase);
        if (bsign == null) {
            return null;
        }
        return new byte[][]{bsign, bcr.toBytes()};
    }

    public static boolean verifyBalance(byte[] h, byte[] bsign, Types.Params params, Point bcr) {
        assert (h.length == 32);
        assert (bsign.length == 64);

        Point zin_acm = Point.ZERO;
        for (int i = 0; i < params.zin_acms.size(); i++) {
            zin_acm = zin_acm.add(params.zin_acms.get(i));
        }
        Point zout_acm = Point.ZERO;
        for (int i = 0; i < params.zout_acms.size(); i++) {
            zout_acm = zout_acm.add(params.zout_acms.get(i));
        }
        Point oin_acc = Point.ZERO;
        for (int i = 0; i < params.oin_accs.size(); i++) {
            oin_acc = oin_acc.add(params.oin_accs.get(i));
        }
        Point oout_acc = Point.ZERO;
        for (int i = 0; i < params.oout_accs.size(); i++) {
            oout_acc = oout_acc.add(params.oout_accs.get(i));
        }
        Point zacm = zin_acm.add(zout_acm.mult(Field.FR.ONE.negate()));
        Point oacc = oout_acc.add(oin_acc.mult(Field.FR.ONE.negate()));
        Point oacm = oacc.add(bcr);
        if (!oacm.isEqualTo(zacm)) {
            return false;
        }
        return Eddsa.verify(h, bsign, bcr, crBase);
    }
}
