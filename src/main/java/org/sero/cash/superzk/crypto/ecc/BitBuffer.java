package org.sero.cash.superzk.crypto.ecc;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

import org.sero.cash.superzk.util.Arrays;

public class BitBuffer {
    private final static Map<Integer, Integer> nums = new HashMap<Integer, Integer>() {
		private static final long serialVersionUID = 1L;

	{
        put(0, 0xff);
        put(1, 0x01);
        put(2, 0x03);
        put(3, 0x07);
        put(4, 0x0f);
        put(5, 0x1f);
        put(6, 0x3f);
        put(7, 0x7f);
    }};

    private int bitsLen;
    private int rightBits;
    private byte[] data;

    public BitBuffer(byte[] buf) {
        this(buf, 0, buf.length * 8);
    }

    public BitBuffer(byte[] buf, int start, int bitsLen) {

        int bitsEnd = start + bitsLen;
        int bytesLen = (int) Math.ceil(bitsEnd / 8.0);
        assert (buf.length >= bytesLen);
        this.bitsLen = bitsLen;
        this.rightBits = start % 8;

        int srcPos = (int) Math.floor(start / 8.0);
        int len = ((int) Math.floor((bitsEnd - 1) / 8.0) + 1) - srcPos;
        this.data = new byte[len];
        System.arraycopy(buf, srcPos, this.data, 0, len);

        // @ts-ignore
        this.data[this.data.length - 1] &= nums.get(bitsEnd % 8);
    }

    public BigInteger toBigInteger() {
        return new BigInteger(1, Arrays.reverse(this.data)).shiftRight(this.rightBits);
    }

    public int bitsLength() {
        return this.bitsLen;
    }

    public static BitBuffer from(BitBuffer bitBuf, int start, int len) {
        return new BitBuffer(bitBuf.data, start + bitBuf.rightBits, len);
    }
}
