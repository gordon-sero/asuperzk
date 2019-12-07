package org.sero.cash.superzk.crypto.ecc;

import java.math.BigInteger;

import org.sero.cash.superzk.util.Arrays;
import org.spongycastle.util.encoders.Hex;

public class Constants {

    public static BigInteger ONE = BigInteger.ONE;
    public static BigInteger TWO = BigInteger.valueOf(2);

    public static BigInteger FQ_MODULUS = new BigInteger("21888242871839275222246405745257275088548364400416034343698204186575808495617");
    public static BigInteger FR_MODULUS = new BigInteger("2736030358979909402780800718157159386076813972158567259200215660948447373041");

    public static BigInteger ECC_A = new BigInteger("168700");
    public static BigInteger ECC_D = new BigInteger("168696");

    public static byte[] CRS = Arrays.reverse(Hex.decode("096b36a5804bfacef1691e173c366a47ff5ba84a44f26ddd7e8d9f79d5b42df0"));
}
