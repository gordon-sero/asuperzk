package org.sero.cash.superzk.protocol.czero;

import org.sero.cash.superzk.crypto.Blake;
import org.sero.cash.superzk.crypto.ecc.BitBuffer;
import org.sero.cash.superzk.crypto.ecc.Eddsa;
import org.sero.cash.superzk.crypto.ecc.Field;
import org.sero.cash.superzk.crypto.ecc.Group;
import org.sero.cash.superzk.crypto.ecc.Point;
import org.sero.cash.superzk.crypto.enc.Chacha20;
import org.sero.cash.superzk.protocol.AccountType;
import org.sero.cash.superzk.protocol.Asset;
import org.sero.cash.superzk.protocol.Param;
import org.sero.cash.superzk.protocol.Types;
import org.sero.cash.superzk.util.Arrays;
import org.sero.cash.superzk.util.HexUtils;

import com.google.common.collect.Lists;

public class Czero {
    private static byte[] EMPTY = new byte[32];
    private static Group outCmBase = new Group("$SROOUTCMGEN".getBytes(), 8, 192, 4);

    public static Point genNil(AccountType.SK sk, Point rootCm) {
        if (!sk.isValid() || !rootCm.isValid()) {
            return null;
        }
        return rootCm.mult(sk.vsk.mul(sk.zsk));
    }


    public static byte[] signNil(byte[] hash, AccountType.SK sk, AccountType.PKr pkr, Point rootCm) {
        assert (hash.length == 32);

        if (hash == null || hash.length == 0 || !sk.isValid() || !pkr.isValid() || !rootCm.isValid()) {
            return null;
        }
        Point base = pkr.BASEr.add(Param.accountBase.points.get(0));
        return Eddsa.sign(hash, sk.vsk.mul(sk.zsk), base, rootCm);
    }



    public static boolean verifyNil(byte[] hash, byte[] sign, Point nil, AccountType.PKr pkr, Point rootCm) {
        assert (hash.length == 32);
        assert (sign.length == 96);

        if (hash == null || hash.length == 0 || sign == null || sign.length == 0 || !pkr.isValid() || !rootCm.isValid()) {
            return false;
        }
        Point base0 = pkr.BASEr.add(Param.accountBase.points.get(0));
        return Eddsa.verify(hash, sign, pkr.VPKr, nil, base0, rootCm);
    }


    public static byte[] signByPKr(AccountType.SK sk, byte[] msg, AccountType.PKr pkr) {
        Point base = pkr.BASEr.add(Param.accountBase.points.get(0));
        return Eddsa.sign(msg, sk.vsk.mul(sk.zsk), base);
    }

    public static boolean verifyByPKr(byte[] msg, byte[] sign, AccountType.PKr pkr) {
        assert (msg.length == 32);
        if (msg == null || msg.length == 0 || sign == null || sign.length == 0 || !pkr.isValid()) {
            return false;
        }
        Point base = pkr.BASEr.add(Param.accountBase.points.get(0));
        return Eddsa.verify(msg, sign, pkr.VPKr, base);
    }

    public static Point genTrace(AccountType.TK tk, Point rootCm) {
        if (!tk.isValid() || !rootCm.isValid()) {
            return null;
        }
        return rootCm.mult(tk.vsk);
    }


    public static byte[] fetchKey(AccountType.TK tk, byte[] rpk) {
        assert (rpk.length == 32);
        if ((rpk[31] & 0x40) != 0) {
            rpk[31] &= ~0x40;
        }
        Point p = Point.fromBytes(rpk);
        if (p == null) {
            return null;
        }
        Point secret = p.mult(tk.vsk);
        return Blake.blake2b("CZERO.KEYS.KDF".getBytes(), secret.toBytes());
    }

    public static Point genOutCm(Asset asset, byte[] memo, Field.FR rsk, AccountType.PKr pkr) {
        assert (memo.length == 64);
        if (!asset.isValid() || !pkr.isValid()) {
            return null;
        }
        Point asset_cc = genAssetCurrency(asset.tkn_currency).mult(asset.tkn_value);
        if (!Arrays.equals(asset.tkt_value, EMPTY)) {
            asset_cc = asset_cc.add(genAssetTkt(asset.tkt_category, asset.tkt_value));
        }
        byte[] blob = Arrays.concat(
                asset_cc.toBytes(),
                memo,
                pkr.VPKr.toBytes(),
                pkr.BASEr.toBytes(),
                rsk.toBytes()
        );

        assert (blob.length == 192);
        return outCmBase.mult(new BitBuffer(blob));
    }


    public static Types.TDOut confirmOutZ(byte[] key, byte[] einfo, AccountType.PKr pkr, byte[] outCM) {
        Info info = decEInfo(einfo, key, true);
        Point checkOutCM = genOutCm(info.asset, info.memo, info.rsk, pkr);
        if (checkOutCM == null) {
            return null;
        }
        if (!Arrays.equals(outCM, checkOutCM.toBytes())) {
            return null;
        }
        return new Types.TDOut(info.asset.toAsset(), info.memo, Lists.newArrayList());
    }

    public static Point genAssetCurrency(byte[] currency) {
        assert (currency.length == 32);
        Point ret = Point.Blake2b.findPoint("$SROASSETCY".getBytes(), currency);
        if (ret == null) {
            throw new RuntimeException("find point error");
        }
        return ret;
    }

    public static Point genAssetTkt(byte[] category, byte[] value) {
        assert (category.length == 32);
        assert (value.length == 32);
        byte[] h = Arrays.concat(category, value);
        Point ret = Point.Blake2b.findPoint("$SROASSETTK".getBytes(), Blake.blake2b("$SROASSETTK.H".getBytes(), h));
        if (ret == null) {
            throw new RuntimeException("find point error");
        }
        return ret;
    }

    public static byte[] encInfo(Info info, byte[] key) {
        return Chacha20.encode(info.toBytes(), key);
    }

    public static Info decEInfo(byte[] einfo, byte[] key, boolean flag) {
        assert (flag);
        assert (einfo.length == 224);
        assert (key.length == 32);
        byte[] binfo = Chacha20.encode(einfo, key);
        return new Info(binfo);
    }

    public static class Info {
        Asset asset;
        Field.FR rsk;
        byte[] memo;

        public Info() {
        }

        public Info(byte[] buf) {
            this(new Asset(Arrays.slice(buf, 0, 128)),
                    Field.newFR(Arrays.slice(buf, 128, 160)),
                    Arrays.slice(buf, 160, 224));
        }

        public Info(Asset asset, Field.FR rsk, byte[] memo) {
            this.asset = asset;
            this.rsk = rsk;
            this.memo = memo;
        }


        public boolean isValid() {
            if (!this.asset.isValid()) {
                return false;
            }
            if (this.rsk.isZero()) {
                return false;
            }
            return true;
        }

        public byte[] toBytes() {
            return Arrays.concat(this.asset.toBytes(), this.rsk.toBytes(), this.memo);
        }

        public String toString() {
            return HexUtils.toHex(this.toBytes());
        }
    }

}
