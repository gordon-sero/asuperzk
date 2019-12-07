package org.sero.cash.superzk.util;

import java.io.IOException;
import java.math.BigInteger;

import org.junit.Test;
import org.spongycastle.util.encoders.Hex;

public class TestHex {

    @Test
    public void test() throws IOException {
        BigInteger n = new BigInteger("17777552123799933955779906779655732241715742912184938656739573121738514868267");
        byte[] data = n.toByteArray();

        String x = new String(Hex.encode(data));
        System.out.println(x.length());
        System.out.println(x);

        data = Hex.decode(x);
        System.out.println(new BigInteger(data));



    }
}
