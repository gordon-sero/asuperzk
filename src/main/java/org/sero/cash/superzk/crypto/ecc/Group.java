package org.sero.cash.superzk.crypto.ecc;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

import org.sero.cash.superzk.util.Arrays;

public class Group implements Mult{
    private byte[] personal;
    private int SegNum;
    private int SegBitsNum;
    private int Bits;

    public Map<Integer, Map<String, Point>> indexPoints;
    public Map<Integer, Point> points;

    public Group(byte[] personal, int SNum, int BitNum, int CNum) {
        this.personal = personal;
        this.SegNum = SNum;
        this.SegBitsNum = BitNum;
        this.Bits = CNum;
        this.indexPoints = new HashMap<Integer, Map<String, Point>>();
        this.points = new HashMap<Integer, Point>();
        this.init();
    }

    private void init() {
        BigInteger combination = new BigInteger("2").pow(this.Bits);
        int groupNum = (int) Math.ceil(this.SegBitsNum * 1.0 / this.Bits);
        Field.FR fr_combination = Field.newFR(combination);
        for (int i = 0; i < this.SegNum; i++) {
            Point point = Point.Blake2b.findPoint(this.personal, Arrays.rightPadBytes(Arrays.reverse(BigInteger.valueOf(i).toByteArray()), 32));
            if (point == null) {
                throw new RuntimeException("findPoint error");
            }
            this.points.put(i, point);
            Map<String, Point> points = new HashMap<String, Point>();
            for (int j = 0; j < groupNum; j++) {
                for (int k = 0; k < combination.intValue(); k++) {
                    BigInteger num = BigInteger.valueOf(k).shiftLeft(this.Bits * j);
                    String key = num.toString();
                    Point val;
                    if (j > 0) {
                        String perKey = num.shiftRight(this.Bits).toString();
                        val = points.get(perKey).mult(fr_combination);
                    } else {
                        val = point.mult(Field.newFR(num));
                    }
                    points.put(key, val);
                }
            }
            this.indexPoints.put(i, points);
        }
    }

    public Point mult(Field.FR fr) {
        return this.mult(new BitBuffer(fr.toBytes(), 0, 256));
    }

    public Point mult(BitBuffer bitBuffer) {
        if (bitBuffer.bitsLength() > this.SegNum * this.SegBitsNum) {
            throw new RuntimeException("bigBuffer.length > SegNum * SegBitsNum");
        }
        int groupNum = (int) Math.ceil(this.SegBitsNum * 1.0 / this.Bits);
        int segNum = (int) Math.ceil(bitBuffer.bitsLength() * 1.0 / this.SegBitsNum);
        Point ret = Point.ZERO;
        for (int i = 0; i < segNum; i++) {
            BitBuffer subBitBuf = BitBuffer.from(bitBuffer, i * this.SegBitsNum, this.SegBitsNum);
            Map<String, Point> pints = this.indexPoints.get(i);
            for (int j = 0; j < groupNum; j++) {
                BigInteger key = BitBuffer.from(subBitBuf, this.Bits * j, this.Bits)
                        .toBigInteger()
                        .shiftLeft(this.Bits * j);
                ret = ret.add(pints.get(key.toString()));
            }
        }
        return ret;
    }
}
