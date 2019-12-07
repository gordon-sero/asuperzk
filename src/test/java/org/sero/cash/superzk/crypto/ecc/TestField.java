package org.sero.cash.superzk.crypto.ecc;

import static org.junit.Assert.assertTrue;

import java.math.BigInteger;

import org.junit.Test;

public class TestField {

    private static Field.FQ base = Field.newFQ(new BigInteger("17777552123799933955779906779655732241715742912184938656739573121738514868267"));

    @Test
    public void test() {
    	Field.FQ n = Field.newFQ("1024");
        byte[] x = n.toBytes();
        assertTrue(x.length == 32);
        System.out.println(Field.randomFR().toBigNumber());
    }

    @Test
    public void testAdd() {
    	Field.FQ doubleBase1 = base.add(base);
    	Field.FQ doubleBase2 = base.mul(Field.newFQ(new BigInteger("2")));
        assertTrue(doubleBase2.isEqualTo(doubleBase1));
    }

    @Test
    public void testSquared() {
    	Field.FQ fq1 = base.mul(base);
    	Field.FQ fq2 = base.pow();
    	Field.FQ fq3 = base.square();

        assertTrue(fq1.isEqualTo(fq2));
        assertTrue(fq1.isEqualTo(fq3));

        Field.FQ sqrt = fq1.sqrt();
        assertTrue(sqrt != null);
        assertTrue(sqrt.square().isEqualTo(fq1));
    }
}
