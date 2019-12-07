package org.sero.cash.superzk.protocol.superzk;

import org.sero.cash.superzk.crypto.Blake;
import org.sero.cash.superzk.crypto.ecc.Eddsa;
import org.sero.cash.superzk.crypto.ecc.Field;
import org.sero.cash.superzk.crypto.ecc.Point;
import org.sero.cash.superzk.protocol.AccountType;
import org.sero.cash.superzk.protocol.Param;
import org.sero.cash.superzk.util.Arrays;

public class Account {


    public static SK seed2SK(byte[] seed) {
        assert (seed.length == 32);
        byte[] zsk = Blake.blake2b("LIBZEROZSK".getBytes(), seed);
        byte[] vsk = Blake.blake2b("LIBZEROVSK".getBytes(), seed);
        return new SK(Field.newFR(zsk), Field.newFR(vsk));
    }

    public static Field.FR toHr_Z(Point rvpk) {
        byte[] hr_h = Blake.blake2b("SZK$PKR$HR$Z".getBytes(), rvpk.toBytes());
        return Field.newFR(hr_h);
    }

    public static Field.FR toHr_V(Point rvpk) {
        byte[] hr_h = Blake.blake2b("SZK$PKR$HR$V".getBytes(), rvpk.toBytes());
        return Field.newFR(hr_h);
    }

    private static Point[] toPKr(Field.FR hr_z, Field.FR hr_v, PK pk) {
        Point Grz = Param.accountBase.mult(hr_z);
        Point Grv = Param.accountBase.mult(hr_v);
        return new Point[]{Grz.add(pk.zpk), Grv.add(pk.vpk)};
    }


    public static class SK extends AccountType.SK {

        public SK(byte[] data) {
            assert (data.length >= 64);
            if (data.length > 64) {
                data = Arrays.slice(data, 0, 64);
            }
            Param.clearFlag(data);
            this.zsk = Field.newFR(Arrays.slice(data, 0, 32));
            this.vsk = Field.newFR(Arrays.slice(data, 32, 64));
        }

        public SK(Field.FR zsk, Field.FR vsk) {
            this.zsk = zsk;
            this.vsk = vsk;
        }

        public AccountType.TK toTK() {
            return new TK(Param.accountBase.mult(this.zsk), this.vsk);
        }

        public byte[] signPKr(byte[] h, PKr pkr) {
            Field.FR hr_z = toHr_Z(pkr.BASEr.mult(this.vsk));
            Field.FR zskr = hr_z.add(this.zsk);
            return Eddsa.sign(h, zskr, Param.accountBase);
        }

        public byte[] toBytes() {
            return Param.setFlag(super.toBytes());
        }
    }

    public static class TK extends AccountType.TK {

        public TK(byte[] data) {
            assert (data.length >= 64);
            if (data.length > 64) {
                data = Arrays.slice(data, 0, 64);
            }
            Param.clearFlag(data);

            this.zpk = Point.fromBytes(Arrays.slice(data, 0, 32));
            this.vsk = Field.newFR(Arrays.slice(data, 32, 64));
        }

        public TK(Point zpk, Field.FR vsk) {
            this.zpk = zpk;
            this.vsk = vsk;
        }

        public byte[] toBytes() {
            return Param.setFlag(super.toBytes());
        }

        public Point genTrace(Point rootCm) {
            if (rootCm.isValid()) {
                return null;
            }
            return rootCm.mult(this.vsk);
        }


        public AccountType.PK toPK() {
            Point vpk = Param.accountBase.mult(this.vsk);
            return new PK(this.zpk, vpk);
        }

        public boolean isMyPKr(AccountType.PKr pkr) {
            PK pk = (PK) this.toPK();
            Point vsk_baser = pkr.BASEr.mult(this.vsk);
            Field.FR hr_z = toHr_Z(vsk_baser);
            Field.FR hr_v = toHr_V(vsk_baser);
            Point[] to_pkr = toPKr(hr_z, hr_v, pk);
            if (!to_pkr[1].isEqualTo(pkr.VPKr)) {
                return false;
            }
            if (!to_pkr[0].isEqualTo(pkr.ZPKr)) {
                return false;
            }
            return true;
        }


    }

    public static class PK extends AccountType.PK {

        public PK(byte[] data) {
            if (!Param.isFlagSet(data) || data.length != 64) {
                return;
            }
            Param.clearFlag(data);

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

        public byte[] toBytes() {
            return Param.setFlag(super.toBytes());
        }

        public AccountType.PKr createPKr(Field.FR r) {
            Field.FR hr_z = toHr_Z(this.vpk.mult(r));
            Field.FR hr_v = toHr_V(this.vpk.mult(r));
            Point[] ret = Account.toPKr(hr_z, hr_v, this);
            Point baser = Param.accountBase.mult(r);
            return new PKr(ret[0], ret[1], baser);
        }


    }

    public static class PKr extends AccountType.PKr {
        public PKr(byte[] data) {
            assert (data.length == 96);
            Param.clearFlag(data);
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
            Param.setFlag(data);
            return data;
        }
    }
}
