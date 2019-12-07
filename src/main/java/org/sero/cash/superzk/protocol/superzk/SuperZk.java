package org.sero.cash.superzk.protocol.superzk;

import org.sero.cash.superzk.crypto.Blake;
import org.sero.cash.superzk.crypto.ecc.Eddsa;
import org.sero.cash.superzk.crypto.ecc.Field;
import org.sero.cash.superzk.crypto.ecc.Point;
import org.sero.cash.superzk.crypto.enc.Chacha20;
import org.sero.cash.superzk.protocol.AccountType;
import org.sero.cash.superzk.protocol.Asset;
import org.sero.cash.superzk.protocol.Param;
import org.sero.cash.superzk.protocol.Types;
import org.sero.cash.superzk.util.Arrays;
import org.sero.cash.superzk.util.HexUtils;

import com.google.common.collect.Lists;

public class SuperZk {


    private static byte[] kdf(Point secret) {
        return Blake.blake2b("SZK$PKR$KDF".getBytes(), secret.toBytes());
    }

    public static byte[] signPKr(AccountType.SK sk, byte[] h, AccountType.PKr pkr) {
        Field.FR hr_z = Account.toHr_Z(pkr.BASEr.mult(sk.vsk));
        Field.FR zskr = hr_z.add(sk.zsk);
        return Eddsa.sign(h, zskr, Param.accountBase);
    }

    public static byte[][] genPKrKey(AccountType.PKr pkr, Field.FR rsk) {
        Point secret = pkr.VPKr.mult(rsk);
        byte[] key = SuperZk.kdf(secret);
        Point rpk = Param.accountBase.mult(rsk);
        return new byte[][]{key, rpk.toBytes()};
    }

    public static boolean verifyPKr(byte[] h, byte[] sign, Account.PKr pkr) {
        return Eddsa.verify(h, sign, pkr.ZPKr, Param.accountBase);
    }


    public static byte[] signNil(byte[] h, AccountType.TK tk, Point cm, AccountType.PKr pkr) {
        Field.FR hr_v = Account.toHr_V(pkr.BASEr.mult(tk.vsk));
        Field.FR vskr = hr_v.add(tk.vsk);
        return Eddsa.sign(h, vskr, Param.accountBase, cm);
    }


    public static byte[] genNil(AccountType.TK tk, Point cm, AccountType.PKr pkr) {
        Field.FR hr_v = Account.toHr_V(pkr.BASEr.mult(tk.vsk));
        Field.FR vskr = hr_v.add(tk.vsk);
        byte[] nil = cm.mult(vskr).toBytes();
        Param.setFlag(nil);
        return nil;
    }

    public static boolean verifyNil(byte[] h, byte[] sign, byte[] nil, Point cm, Account.PKr pkr) {
        Param.clearFlag(nil);
        return Eddsa.verify(h, sign, pkr.VPKr, Point.fromBytes(nil), Param.accountBase, cm);
    }

    public static Point genZPKa(Account.PKr pkr, Field.FR a) {
        return pkr.genZPKa(a);
    }

    public static byte[] signZPKa(byte[] h, AccountType.SK sk, Field.FR a, AccountType.PKr pkr) {
        Point vsk_baser = pkr.BASEr.mult(sk.vsk);
        Field.FR hr_z = Account.toHr_Z(vsk_baser);
        Field.FR zskr = hr_z.add(sk.zsk);
        Field.FR zska = a.mul(zskr);
        return Eddsa.sign(h, zska, Param.accountBase);
    }

    public static boolean verifyZPKa(byte[] h, byte[] sign, Point zpka) {
        return Eddsa.verify(h, sign, zpka, Param.accountBase);
    }

    public static byte[] fetchRPKKey(AccountType.PKr pkr, AccountType.TK tk, byte[] rpk) {
        Point vsk_baser = pkr.BASEr.mult(tk.vsk);
        Field.FR hr_v = Account.toHr_V(vsk_baser);
        Field.FR vskr = hr_v.add(tk.vsk);
        Point secret = Point.fromBytes(rpk).mult(vskr);
        byte[] key = SuperZk.kdf(secret);
        return key;
    }


    public static byte[] encInfo(byte[] key, Info info) {
        return Chacha20.encode(info.toBytes(), key);
    }

    public static Info decEInfo(byte[] key, byte[] einfo) {
        byte[] binfo = Chacha20.encode(einfo, key);
        return new Info(binfo);
    }

    public static Types.TDOut confirmOutC(byte[] key, byte[] einfo, Point assetCM) {
        Info info = decEInfo(key, einfo);

        Point checkAssetCM = info.asset.genAssetCM(info.ar);
        if (!checkAssetCM.isEqualTo(assetCM)) {
            return null;
        }
        return new Types.TDOut(info.asset.toAsset(), info.memo, Lists.newArrayList());
    }


    public static class Info {
        public Asset asset;
        public byte[] memo;
        public Field.FR ar;

        public Info(byte[] data) {
            assert (data.length == 224);
            this.asset = new Asset(Arrays.slice(data, 0, 128));
            this.memo = Arrays.slice(data, 128, 192);
            this.ar = Field.newFR(Arrays.slice(data, 192, 224));
        }

        public Info(Asset asset, byte[] memo, Field.FR ar) {
            this.asset = asset;
            this.memo = memo;
            this.ar = ar;
        }

        public boolean isValid() {
            if (!this.asset.isValid()) {
                return false;
            }
            if (this.ar.isZero()) {
                return false;
            }
            return true;
        }

        public byte[] toBytes() {
            return Arrays.concat(this.asset.toBytes(), this.memo, this.ar.toBytes());
        }

        public String toString() {
            return HexUtils.toHex(this.toBytes());
        }
    }

}
