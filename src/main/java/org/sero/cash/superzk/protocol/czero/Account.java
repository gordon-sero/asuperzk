package org.sero.cash.superzk.protocol.czero;

import org.sero.cash.superzk.crypto.Blake;
import org.sero.cash.superzk.crypto.ecc.Field;
import org.sero.cash.superzk.crypto.ecc.Point;
import org.sero.cash.superzk.protocol.AccountType;
import org.sero.cash.superzk.protocol.Param;
import org.sero.cash.superzk.util.Arrays;

public class Account {

    public static AccountType.SK seed2SK(byte[] seed) {
        assert (seed.length == 32);
        byte[] zsk = Blake.blake2b("LIBZEROZSK".getBytes(), seed);
        byte[] vsk = Blake.blake2b("LIBZEROVSK".getBytes(), seed);
        return new SK(Field.newFR(zsk), Field.newFR(vsk));
    }

    public static class SK extends AccountType.SK {

        public SK() {
        }

        public SK(byte[] data) {
            assert (data.length >= 64);
            if (data.length > 64) {
                data = Arrays.slice(data, 0, 64);
            }
            this.zsk = Field.newFR(Arrays.slice(data, 0, 32));
            this.vsk = Field.newFR(Arrays.slice(data, 32, 64));
        }

        public SK(Field.FR zsk, Field.FR vsk) {
            super(zsk, vsk);
        }

        @Override
        public AccountType.TK toTK() {
            return new TK(Param.accountBase.mult(this.zsk), this.vsk);
        }
    }

    public static class TK extends AccountType.TK {

        public TK(byte[] data) {
            assert (data.length >= 64);
            if (data.length > 64) {
                data = Arrays.slice(data, 0, 64);
            }
            this.zpk = Point.fromBytes(Arrays.slice(data, 0, 32));
            this.vsk = Field.newFR(Arrays.slice(data, 32, 64));
        }

        public TK(Point zpk, Field.FR vsk) {
            this.zpk = zpk;
            this.vsk = vsk;
        }

        public Point genTrace(Point rootCm) {
            if (rootCm.isValid()) {
                return null;
            }
            return rootCm.mult(this.vsk);
        }


        public AccountType.PK toPK() {
            Point zpk = this.zpk;
            Point vpk = this.zpk.mult(this.vsk);
            return new PK(zpk, vpk);
        }

        @Override
        public boolean isMyPKr(AccountType.PKr pkr) {
            if (!this.isValid() || !pkr.isValid()) {
                return false;
            }
            Point left = pkr.ZPKr.add(this.zpk.mult(Field.FR.ONE.negate())).mult(this.vsk);
            Point right = pkr.VPKr.add(this.zpk.mult(this.vsk.mul(Field.FR.ONE.negate())));
            return left.isEqualTo(right);
        }
    }

    public static class PK extends AccountType.PK {

        public PK(byte[] data) {
            if (data.length != 64) {
                return;
            }

            Point zpk = Point.fromBytes(Arrays.slice(data, 0, 32));
            if (zpk == null) {
                return;
            }
            Point vpk = Point.fromBytes(Arrays.slice(data, 32, 64));
            if (vpk == null) {
                return;
            }
            this.zpk = zpk;
            this.vpk = vpk;
        }

        public PK(Point zpk, Point vpk) {
            this.zpk = zpk;
            this.vpk = vpk;
        }

        public AccountType.PKr createPKr(Field.FR r) {
            Point ZPK = this.zpk.mult(r).add(this.zpk);
            Point VPK = this.vpk.mult(r).add(this.vpk);
            Point baser = Param.accountBase.mult(r);
            return new PKr(ZPK, VPK, baser);
        }
    }

    public static class PKr extends AccountType.PKr {
        public PKr(byte[] data) {
            assert (!Param.isFlagSet(data) && data.length == 96);
            this.ZPKr = Point.fromBytes(Arrays.slice(data, 0, 32));
            if (this.ZPKr == null) {
                return;
            }
            this.VPKr = Point.fromBytes(Arrays.slice(data, 32, 64));
            if (this.VPKr == null) {
                return;
            }
            this.BASEr = Point.fromBytes(Arrays.slice(data, 64, 96));
            if (this.BASEr == null) {
                return;
            }
        }

        public PKr(Point zpkr, Point vpkr, Point baser) {
            this.ZPKr = zpkr;
            this.VPKr = vpkr;
            this.BASEr = baser;
        }

        Point genZPKa(Field.FR a) {
            return this.ZPKr.mult(a);
        }

        public byte[] toBytes() {
            byte[] data = Arrays.concat(ZPKr.toBytes(), VPKr.toBytes(), BASEr.toBytes());
            return data;
        }
    }
}
