package org.sero.cash.superzk.protocol;

import org.sero.cash.superzk.crypto.ecc.Field;
import org.sero.cash.superzk.crypto.ecc.Point;
import org.sero.cash.superzk.json.HexType;
import org.sero.cash.superzk.protocol.superzk.Account;
import org.sero.cash.superzk.util.Base58;
import org.sero.cash.superzk.util.HexUtils;

public class AccountType {

    public static abstract class SK implements HexType {
        public Field.FR zsk;
        public Field.FR vsk;

        public SK() {
        }

        public SK(Field.FR zsk, Field.FR vsk) {
            this.zsk = zsk;
            this.vsk = vsk;
        }

        public abstract TK toTK();

        public boolean isValid() {
            if (this.zsk.isZero()) {
                return false;
            }
            if (this.vsk.isZero()) {
                return false;
            }
            return true;
        }

        public SK fromBytes(byte[] data) {
            if (Param.isFlagSet(data)) {
                return new Account.SK(data);
            } else {
                return new org.sero.cash.superzk.protocol.czero.Account.SK(data);
            }
        }

        public byte[] toBytes() {
            byte[] ret = new byte[64];
            System.arraycopy(this.zsk.toBytes(), 0, ret, 0, 32);
            System.arraycopy(this.vsk.toBytes(), 0, ret, 32, 32);
            return ret;
        }


        public String toString() {
            return HexUtils.toHex(this.toBytes());
        }
    }

    public static abstract class TK implements HexType {
        public Point zpk;
        public Field.FR vsk;

        public abstract PK toPK();

        public abstract boolean isMyPKr(PKr pkr);

        public static TK fromBytes(byte[] data) {
            if (Param.isFlagSet(data)) {
                return new Account.TK(data);
            } else {
                return new org.sero.cash.superzk.protocol.czero.Account.TK(data);
            }
        }

        public byte[] toBytes() {
            byte[] ret = new byte[64];
            System.arraycopy(this.zpk.toBytes(), 0, ret, 0, 32);
            System.arraycopy(this.vsk.toBytes(), 0, ret, 32, 32);
            return ret;
        }

        public boolean isValid() {
            return this.zpk.isValid() && !this.vsk.isZero();
        }

        public String toString() {
            return Base58.encode(this.toBytes());
        }

        public String toHex() {
            return HexUtils.toHex(this.toBytes());
        }
    }

    public static abstract class PK implements HexType {
        public Point zpk;
        public Point vpk;

        public static PK fromBytes(byte[] data) {
            if (Param.isFlagSet(data)) {
                return new Account.PK(data);
            } else {
                return new org.sero.cash.superzk.protocol.czero.Account.PK(data);
            }
        }

        public byte[] toBytes() {
            byte[] ret = new byte[64];
            System.arraycopy(this.zpk.toBytes(), 0, ret, 0, 32);
            System.arraycopy(this.vpk.toBytes(), 0, ret, 32, 32);
            return ret;
        }

        public abstract PKr createPKr(Field.FR a);

        public boolean isValid(byte[] data) {
            return zpk != null && zpk != null;
        }

        public String toString() {
            return Base58.encode(this.toBytes());
        }

    }

    public static abstract class PKr implements HexType {
        protected int i;
        public Point ZPKr;
        public Point VPKr;
        public Point BASEr;

        public boolean isValid() {
            return this.ZPKr != null && this.ZPKr.isValid() &&
                    this.VPKr != null && this.VPKr.isValid() &&
                    this.BASEr != null && this.BASEr.isValid();
        }

        public static PKr fromBytes(byte[] data) {
            if (Param.isFlagSet(data)) {
                return new Account.PKr(data);
            } else {
                return new org.sero.cash.superzk.protocol.czero.Account.PKr(data);
            }
        }

        public String toHex() {
            return HexUtils.toHex(this.toBytes());
        }

        public String toString() {
            return HexUtils.toHex(this.toBytes());
        }
    }


}
