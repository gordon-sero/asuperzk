package org.sero.cash.superzk.protocol;

import org.sero.cash.superzk.crypto.ecc.Field;
import org.sero.cash.superzk.crypto.ecc.Point;
import org.sero.cash.superzk.util.Arrays;
import org.sero.cash.superzk.util.HexUtils;

public class Asset {
    private static byte[] EMPTY = new byte[32];
    public byte[] tkn_currency;
    public Field.FR tkn_value;
    public byte[] tkt_category;
    public byte[] tkt_value;

    public Asset() {
    }

    public Asset(byte[] data) {
        assert (data.length == 128);
        this.tkn_currency = Arrays.slice(data, 0, 32);
        this.tkn_value = Field.newFR(Arrays.slice(data, 32, 64));
        this.tkt_category = Arrays.slice(data, 64, 96);
        this.tkt_value = Arrays.slice(data, 96, 128);
    }

    public Asset(byte[] tkn_currency, Field.FR tkn_value, byte[] tkt_category, byte[] tkt_value) {
        this.tkn_currency = tkn_currency;
        this.tkn_value = tkn_value;
        this.tkt_category = tkt_category;
        this.tkt_value = tkt_value;
    }

    public byte[] getTkn_currency() {
        return tkn_currency;
    }

    public Field.FR getTkn_value() {
        return tkn_value;
    }

    public byte[] getTkt_category() {
        return tkt_category;
    }

    public byte[] getTkt_value() {
        return tkt_value;
    }

    public boolean isValid() {
        byte[] bytes = this.tkn_value.toBytes();
        return bytes[31] == 0 && bytes[30] == 0;
    }

    public boolean hasTkt() {
        return !Arrays.equals(EMPTY, this.tkt_value);
    }

    public byte[] toBytes() {
        return Arrays.concat(this.tkn_currency, this.tkn_value.toBytes(), this.tkt_category, this.tkt_value);
    }

    public String toString() {
        return HexUtils.toHex(this.toBytes());
    }

    public Types.Asset toAsset() {
        Types.Asset a = new Types.Asset();
        if (!Arrays.equals(tkn_currency, EMPTY)) {
            a.Tkn = new Types.Token(tkn_currency, tkn_value.toBigNumber());
        }
        if (!Arrays.equals(tkt_category, EMPTY)) {
            a.Tkt = new Types.Ticket(tkt_category, tkt_value);
        }
        return a;
    }

    public Point genAssetCC() {
        Point tknBase = genTknBase(this.tkn_currency);
        Point G_tkn = tknBase.mult(this.tkn_value);
        if (this.hasTkt()) {
            Point G_tkt = genTktBase(this.tkt_category, this.tkt_value);
            return G_tkn.add(G_tkt);
        } else {
            return G_tkn;
        }
    }

    public Point genAssetCM(Field.FR ar) {
        Point cc = this.genAssetCC();
        Point cr = Param.crBase.mult(ar);
        return cc.add(cr);
    }

    private Point genTknBase(byte[] currency) {
        assert (currency.length == 32);
        byte[] data = new byte[64];
        System.arraycopy(currency, 0, data, 0, 32);
        Point ret = Point.Blake2s.findPoint("SZK$TKN".getBytes(), data);
        if (ret == null) {
            throw new RuntimeException("find point error");
        }
        return ret;
    }

    private Point genTktBase(byte[] category, byte[] value) {
        assert (category.length == 32);
        assert (value.length == 32);
        byte[] data = Arrays.concat(category, value);
        Point ret = Point.Blake2s.findPoint("SZK$TKT".getBytes(), data);
        if (ret == null) {
            throw new RuntimeException("find point error");
        }
        return ret;
    }
}
