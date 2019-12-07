package org.sero.cash.superzk.crypto.ecc;

public interface Mult {
    public abstract Point mult(Field.FR val);
}
