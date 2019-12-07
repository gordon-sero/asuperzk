package org.sero.cash.superzk.crypto.ecc;

import static org.junit.Assert.assertTrue;

import org.junit.Test;
import org.sero.cash.superzk.util.Arrays;
import org.spongycastle.util.encoders.Hex;

public class TestPoint {

    private static Field.FQ fq1 = Field.newFQ("17777552123799933955779906779655732241715742912184938656739573121738514868268");
    private static Field.FQ fq2 = Field.newFQ("2626589144620713026669568689430873010625803728049924121243784502389097019475");
    private static Field.FR fr1 = Field.newFR("120664075238337199387162984796177147820973068364675632137645760787230319545");


    @Test
    public void testOP() {
        Point pt1 = new Point(fq1, fq2, Field.FQ.ONE);
        assertTrue(pt1.isValid());
        Point mult = pt1.mult(fr1);
        assertTrue(mult.isValid());
        System.out.println(mult.toString());
        assertTrue(mult.toString().compareTo("0xbf6ea2f29caf321b5735c26fea9d4bfd4ce03b9a561c5133839e76c44b6063a9") == 0);

        byte[] data = Hex.decode("bf6ea2f29caf321b5735c26fea9d4bfd4ce03b9a561c5133839e76c44b6063a9");
        Point point = Point.fromBytes(data);
        assertTrue(point.isEqualTo(mult));

        Point add = pt1.add(pt1);
        assertTrue(add.isValid());
        assertTrue(add.isEqualTo(pt1.twice()));
    }


    @Test
    public void testFromBytes() {
        byte[] data = Hex.decode("78de25585f58aab09c3f9155e39affd40fef928aced65ad315d7dbfbd05b6304");
        Point point = Point.fromBytes(Arrays.copy(data));
        assertTrue(Arrays.equals(data, point.toBytes()));

    }

    @Test
    public void testFindPoint_Blake2b() {
        byte[] data = Hex.decode("15f909235e10f2a3bdf38beda4bcc59094d0cda686f6b9ec943eb89ecaabf4c4");
        Point point = Point.Blake2b.findPoint("123456789abc".getBytes(), data);
        System.out.println(new String(Hex.encode(point.toBytes())));
    }

    @Test
    public void testFinePoint_Blake2b() {
        for (int i = 0; i < 100; i++) {
            byte[] personal = Arrays.randomBytes(16);
            byte[] data = Arrays.randomBytes(32);
            Point fp = Point.Blake2b.findPoint(personal, data);
            if (fp == null) {
                assert (false);
            } else {
                testBufferToPoint(fp);
            }
        }
    }

    @Test
    public void testFindPoint_Blake2s() {
        byte[] data = Hex.decode("336d1f61907193f182af073ec66673c408c495158f581630b32d68148e8164d375c9756ab5f78b3c482754477f5658a7757d92c624895c852e3327aac6105e0f");
        Point point = Point.Blake2s.findPoint("12345678".getBytes(), data);
        assertTrue(Arrays.equals(point.toBytes(), Hex.decode("46cddd6702cfd890c4a636500c0cfd4a191b22709534c11c6d03ad87c0c40e1e")));
    }

    @Test
    public void testFinePoint_Blake2s() {
        for (int i = 0; i < 100; i++) {
            byte[] personal = Arrays.randomBytes(8);
            byte[] data = Arrays.randomBytes(64);
            Point fp = Point.Blake2s.findPoint(personal, data);
            if (fp == null) {
                assert (false);
            } else {
                testBufferToPoint(fp);
            }
        }
    }

    public void testBufferToPoint(Point pt1) {
        byte[] toBuffer = pt1.toBytes();
        Point pt2 = Point.fromBytes(toBuffer);
        if (pt2 != null && pt2.isValid()) {
            assert (pt2.isEqualTo(pt1));
        } else {
            assert (false);
        }
    }
}
