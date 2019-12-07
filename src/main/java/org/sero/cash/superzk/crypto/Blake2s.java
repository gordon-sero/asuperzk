package org.sero.cash.superzk.crypto;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

public class Blake2s {
    private static final int BLOCK_SIZE = 64;

    private static final int[] IV = {
            0x6a09e667, 0xbb67ae85, 0x3c6ef372,
            0xa54ff53a, 0x510e527f, 0x9b05688c,
            0x1f83d9ab, 0x5be0cd19
    };

    private int[] cfg;
    private byte[] buffer;
    private int bufferLength = 0;
    private boolean lastNode = false;
    private boolean finished = false;
    private int digestLength = 0;
    private int flag0 = 0;
    private int flag1 = 0;
    private int ctr0 = 0;
    private int ctr1 = 0;

    public Blake2s(int digestLength) {
        this(digestLength, new Blake2sTree());
    }

    public Blake2s(int digestLength, Blake2sTree tree) {
        init(digestLength, tree, null, null, null);
    }

    public Blake2s(int digestLength, byte[] key) {
        init(digestLength, new Blake2sTree(), key, null, null);
    }

    public Blake2s(int digestLength, byte[] salt, byte[] personalization) {
        init(digestLength, new Blake2sTree(), null, salt, personalization);
    }

    public Blake2s(int digestLength, byte[] key, byte[] salt, byte[] personalization) {
        init(digestLength, new Blake2sTree(), key, salt, personalization);
    }

    public Blake2s(int digestLength, Blake2sTree tree, byte[] key, byte[] salt, byte[] personalization) {
        init(digestLength, tree, key, salt, personalization);
    }

    public void update(byte[] data, int dataLength) {
//        if (finished) {
//            throw new Exception("blake2s: can't update because hash was finished");
//        }

        final int left = Blake2s.BLOCK_SIZE - bufferLength;
        int dataPos = 0;

        if (dataLength == 0) {
            return;
        }

        if (dataLength > left) {
            System.arraycopy(data, dataPos, buffer, bufferLength, left);
            processBlock(Blake2s.BLOCK_SIZE);
            dataPos += left;
            dataLength -= left;
            bufferLength = 0;
        }

        while (dataLength > Blake2s.BLOCK_SIZE) {
            System.arraycopy(data, dataPos, buffer, 0, Blake2s.BLOCK_SIZE);
            processBlock(Blake2s.BLOCK_SIZE);
            dataPos += Blake2s.BLOCK_SIZE;
            dataLength -= Blake2s.BLOCK_SIZE;
            bufferLength = 0;
        }

        System.arraycopy(data, dataPos, buffer, bufferLength, dataLength);
        bufferLength += dataLength;
    }

    public void finish(byte[] out) {
        if (!finished) {
            for (int i = bufferLength; i < Blake2s.BLOCK_SIZE; i++) {
                buffer[i] = 0;
            }

            flag0 = 0xffffffff;

            if (lastNode) {
                flag1 = 0xffffffff;
            }

            processBlock(bufferLength);
            finished = true;
        }

        byte[] tmp = Arrays.copyOfRange(buffer, 0, 32);
        for (int i = 0; i < 8; i++) {
            ByteBuffer bb = ByteBuffer.allocate(4);
            bb.order(ByteOrder.LITTLE_ENDIAN);
            bb.putInt(cfg[i]);
            System.arraycopy(bb.array(), 0, tmp, i * 4, 4);
        }

        System.arraycopy(tmp, 0, out, 0, out.length);
    }

    public byte[] digest() {
        byte[] out = new byte[digestLength];
        finish(out);
        return out;
    }

    private void init(int digestLength, Blake2sTree tree, byte[] key, byte[] salt, byte[] personalization) {
        this.digestLength = digestLength;
        buffer = new byte[Blake2s.BLOCK_SIZE];

        if (key == null) {
            key = new byte[0];
        }

        cfg = Arrays.copyOf(Blake2s.IV, 8);
        cfg[0] ^= digestLength | (key.length << 8) | (tree.getFanout() << 16) | (tree.getMaxDepth() << 24);
        cfg[1] ^= tree.getLeafSize();

        int nofHi = (int) (tree.getNodeOffset() >> 32);
        int nofLo = (int) tree.getNodeOffset();
        cfg[2] ^= nofLo;
        cfg[3] ^= nofHi | (tree.getNodeDepth() << 16) | (tree.getInnerDigestLength() << 24);

        lastNode = tree.isLastNode();

        if (salt != null && salt.length == 8) {
            ByteBuffer bb = ByteBuffer.wrap(salt);
            bb.order(ByteOrder.LITTLE_ENDIAN);
            cfg[4] ^= bb.getInt(0);
            cfg[5] ^= bb.getInt(4);
        }

        if (personalization != null && personalization.length == 8) {
            ByteBuffer bb = ByteBuffer.wrap(personalization);
            bb.order(ByteOrder.LITTLE_ENDIAN);
            cfg[6] ^= bb.getInt(0);
            cfg[7] ^= bb.getInt(4);
        }

        if (key.length > 0) {
            byte[] paddedKey = new byte[Blake2s.BLOCK_SIZE];
            Arrays.fill(paddedKey, (byte) 0);

            System.arraycopy(key, 0, paddedKey, 0, key.length);
            System.arraycopy(paddedKey, 0, buffer, 0, paddedKey.length);
            bufferLength = paddedKey.length;
        }
    }

    private void processBlock(int length) {
        ctr0 += length;
        if (ctr0 == 0 && length != 0) {
            ctr1++;
        }

        int v0 = cfg[0],
                v1 = cfg[1],
                v2 = cfg[2],
                v3 = cfg[3],
                v4 = cfg[4],
                v5 = cfg[5],
                v6 = cfg[6],
                v7 = cfg[7],
                v8 = Blake2s.IV[0],
                v9 = Blake2s.IV[1],
                v10 = Blake2s.IV[2],
                v11 = Blake2s.IV[3],
                v12 = Blake2s.IV[4] ^ ctr0,
                v13 = Blake2s.IV[5] ^ ctr1,
                v14 = Blake2s.IV[6] ^ flag0,
                v15 = Blake2s.IV[7] ^ flag1;

        final int[] x = new int[buffer.length];
        for (int i = 0; i < buffer.length; i++) {
            x[i] = buffer[i] & 0xFF;
        }

        final int m0 = (x[3] << 24) | (x[2] << 16) | (x[1] << 8) | x[0];
        final int m1 = (x[7] << 24) | (x[6] << 16) | (x[5] << 8) | x[4];
        final int m2 = (x[11] << 24) | (x[10] << 16) | (x[9] << 8) | x[8];
        final int m3 = (x[15] << 24) | (x[14] << 16) | (x[13] << 8) | x[12];
        final int m4 = (x[19] << 24) | (x[18] << 16) | (x[17] << 8) | x[16];
        final int m5 = (x[23] << 24) | (x[22] << 16) | (x[21] << 8) | x[20];
        final int m6 = (x[27] << 24) | (x[26] << 16) | (x[25] << 8) | x[24];
        final int m7 = (x[31] << 24) | (x[30] << 16) | (x[29] << 8) | x[28];
        final int m8 = (x[35] << 24) | (x[34] << 16) | (x[33] << 8) | x[32];
        final int m9 = (x[39] << 24) | (x[38] << 16) | (x[37] << 8) | x[36];
        final int m10 = (x[43] << 24) | (x[42] << 16) | (x[41] << 8) | x[40];
        final int m11 = (x[47] << 24) | (x[46] << 16) | (x[45] << 8) | x[44];
        final int m12 = (x[51] << 24) | (x[50] << 16) | (x[49] << 8) | x[48];
        final int m13 = (x[55] << 24) | (x[54] << 16) | (x[53] << 8) | x[52];
        final int m14 = (x[59] << 24) | (x[58] << 16) | (x[57] << 8) | x[56];
        final int m15 = (x[63] << 24) | (x[62] << 16) | (x[61] << 8) | x[60];

        // Round 1.
        v0 = v0 + m0;
        v0 = v0 + v4;
        v12 ^= v0;
        v12 = v12 << (32 - 16) | v12 >>> 16;
        v8 = v8 + v12;
        v4 ^= v8;
        v4 = v4 << (32 - 12) | v4 >>> 12;
        v1 = v1 + m2;
        v1 = v1 + v5;
        v13 ^= v1;
        v13 = v13 << (32 - 16) | v13 >>> 16;
        v9 = v9 + v13;
        v5 ^= v9;
        v5 = v5 << (32 - 12) | v5 >>> 12;
        v2 = v2 + m4;
        v2 = v2 + v6;
        v14 ^= v2;
        v14 = v14 << (32 - 16) | v14 >>> 16;
        v10 = v10 + v14;
        v6 ^= v10;
        v6 = v6 << (32 - 12) | v6 >>> 12;
        v3 = v3 + m6;
        v3 = v3 + v7;
        v15 ^= v3;
        v15 = v15 << (32 - 16) | v15 >>> 16;
        v11 = v11 + v15;
        v7 ^= v11;
        v7 = v7 << (32 - 12) | v7 >>> 12;
        v2 = v2 + m5;
        v2 = v2 + v6;
        v14 ^= v2;
        v14 = v14 << (32 - 8) | v14 >>> 8;
        v10 = v10 + v14;
        v6 ^= v10;
        v6 = v6 << (32 - 7) | v6 >>> 7;
        v3 = v3 + m7;
        v3 = v3 + v7;
        v15 ^= v3;
        v15 = v15 << (32 - 8) | v15 >>> 8;
        v11 = v11 + v15;
        v7 ^= v11;
        v7 = v7 << (32 - 7) | v7 >>> 7;
        v1 = v1 + m3;
        v1 = v1 + v5;
        v13 ^= v1;
        v13 = v13 << (32 - 8) | v13 >>> 8;
        v9 = v9 + v13;
        v5 ^= v9;
        v5 = v5 << (32 - 7) | v5 >>> 7;
        v0 = v0 + m1;
        v0 = v0 + v4;
        v12 ^= v0;
        v12 = v12 << (32 - 8) | v12 >>> 8;
        v8 = v8 + v12;
        v4 ^= v8;
        v4 = v4 << (32 - 7) | v4 >>> 7;
        v0 = v0 + m8;
        v0 = v0 + v5;
        v15 ^= v0;
        v15 = v15 << (32 - 16) | v15 >>> 16;
        v10 = v10 + v15;
        v5 ^= v10;
        v5 = v5 << (32 - 12) | v5 >>> 12;
        v1 = v1 + m10;
        v1 = v1 + v6;
        v12 ^= v1;
        v12 = v12 << (32 - 16) | v12 >>> 16;
        v11 = v11 + v12;
        v6 ^= v11;
        v6 = v6 << (32 - 12) | v6 >>> 12;
        v2 = v2 + m12;
        v2 = v2 + v7;
        v13 ^= v2;
        v13 = v13 << (32 - 16) | v13 >>> 16;
        v8 = v8 + v13;
        v7 ^= v8;
        v7 = v7 << (32 - 12) | v7 >>> 12;
        v3 = v3 + m14;
        v3 = v3 + v4;
        v14 ^= v3;
        v14 = v14 << (32 - 16) | v14 >>> 16;
        v9 = v9 + v14;
        v4 ^= v9;
        v4 = v4 << (32 - 12) | v4 >>> 12;
        v2 = v2 + m13;
        v2 = v2 + v7;
        v13 ^= v2;
        v13 = v13 << (32 - 8) | v13 >>> 8;
        v8 = v8 + v13;
        v7 ^= v8;
        v7 = v7 << (32 - 7) | v7 >>> 7;
        v3 = v3 + m15;
        v3 = v3 + v4;
        v14 ^= v3;
        v14 = v14 << (32 - 8) | v14 >>> 8;
        v9 = v9 + v14;
        v4 ^= v9;
        v4 = v4 << (32 - 7) | v4 >>> 7;
        v1 = v1 + m11;
        v1 = v1 + v6;
        v12 ^= v1;
        v12 = v12 << (32 - 8) | v12 >>> 8;
        v11 = v11 + v12;
        v6 ^= v11;
        v6 = v6 << (32 - 7) | v6 >>> 7;
        v0 = v0 + m9;
        v0 = v0 + v5;
        v15 ^= v0;
        v15 = v15 << (32 - 8) | v15 >>> 8;
        v10 = v10 + v15;
        v5 ^= v10;
        v5 = v5 << (32 - 7) | v5 >>> 7;

        // Round 2.
        v0 = v0 + m14;
        v0 = v0 + v4;
        v12 ^= v0;
        v12 = v12 << (32 - 16) | v12 >>> 16;
        v8 = v8 + v12;
        v4 ^= v8;
        v4 = v4 << (32 - 12) | v4 >>> 12;
        v1 = v1 + m4;
        v1 = v1 + v5;
        v13 ^= v1;
        v13 = v13 << (32 - 16) | v13 >>> 16;
        v9 = v9 + v13;
        v5 ^= v9;
        v5 = v5 << (32 - 12) | v5 >>> 12;
        v2 = v2 + m9;
        v2 = v2 + v6;
        v14 ^= v2;
        v14 = v14 << (32 - 16) | v14 >>> 16;
        v10 = v10 + v14;
        v6 ^= v10;
        v6 = v6 << (32 - 12) | v6 >>> 12;
        v3 = v3 + m13;
        v3 = v3 + v7;
        v15 ^= v3;
        v15 = v15 << (32 - 16) | v15 >>> 16;
        v11 = v11 + v15;
        v7 ^= v11;
        v7 = v7 << (32 - 12) | v7 >>> 12;
        v2 = v2 + m15;
        v2 = v2 + v6;
        v14 ^= v2;
        v14 = v14 << (32 - 8) | v14 >>> 8;
        v10 = v10 + v14;
        v6 ^= v10;
        v6 = v6 << (32 - 7) | v6 >>> 7;
        v3 = v3 + m6;
        v3 = v3 + v7;
        v15 ^= v3;
        v15 = v15 << (32 - 8) | v15 >>> 8;
        v11 = v11 + v15;
        v7 ^= v11;
        v7 = v7 << (32 - 7) | v7 >>> 7;
        v1 = v1 + m8;
        v1 = v1 + v5;
        v13 ^= v1;
        v13 = v13 << (32 - 8) | v13 >>> 8;
        v9 = v9 + v13;
        v5 ^= v9;
        v5 = v5 << (32 - 7) | v5 >>> 7;
        v0 = v0 + m10;
        v0 = v0 + v4;
        v12 ^= v0;
        v12 = v12 << (32 - 8) | v12 >>> 8;
        v8 = v8 + v12;
        v4 ^= v8;
        v4 = v4 << (32 - 7) | v4 >>> 7;
        v0 = v0 + m1;
        v0 = v0 + v5;
        v15 ^= v0;
        v15 = v15 << (32 - 16) | v15 >>> 16;
        v10 = v10 + v15;
        v5 ^= v10;
        v5 = v5 << (32 - 12) | v5 >>> 12;
        v1 = v1 + m0;
        v1 = v1 + v6;
        v12 ^= v1;
        v12 = v12 << (32 - 16) | v12 >>> 16;
        v11 = v11 + v12;
        v6 ^= v11;
        v6 = v6 << (32 - 12) | v6 >>> 12;
        v2 = v2 + m11;
        v2 = v2 + v7;
        v13 ^= v2;
        v13 = v13 << (32 - 16) | v13 >>> 16;
        v8 = v8 + v13;
        v7 ^= v8;
        v7 = v7 << (32 - 12) | v7 >>> 12;
        v3 = v3 + m5;
        v3 = v3 + v4;
        v14 ^= v3;
        v14 = v14 << (32 - 16) | v14 >>> 16;
        v9 = v9 + v14;
        v4 ^= v9;
        v4 = v4 << (32 - 12) | v4 >>> 12;
        v2 = v2 + m7;
        v2 = v2 + v7;
        v13 ^= v2;
        v13 = v13 << (32 - 8) | v13 >>> 8;
        v8 = v8 + v13;
        v7 ^= v8;
        v7 = v7 << (32 - 7) | v7 >>> 7;
        v3 = v3 + m3;
        v3 = v3 + v4;
        v14 ^= v3;
        v14 = v14 << (32 - 8) | v14 >>> 8;
        v9 = v9 + v14;
        v4 ^= v9;
        v4 = v4 << (32 - 7) | v4 >>> 7;
        v1 = v1 + m2;
        v1 = v1 + v6;
        v12 ^= v1;
        v12 = v12 << (32 - 8) | v12 >>> 8;
        v11 = v11 + v12;
        v6 ^= v11;
        v6 = v6 << (32 - 7) | v6 >>> 7;
        v0 = v0 + m12;
        v0 = v0 + v5;
        v15 ^= v0;
        v15 = v15 << (32 - 8) | v15 >>> 8;
        v10 = v10 + v15;
        v5 ^= v10;
        v5 = v5 << (32 - 7) | v5 >>> 7;

        // Round 3.
        v0 = v0 + m11;
        v0 = v0 + v4;
        v12 ^= v0;
        v12 = v12 << (32 - 16) | v12 >>> 16;
        v8 = v8 + v12;
        v4 ^= v8;
        v4 = v4 << (32 - 12) | v4 >>> 12;
        v1 = v1 + m12;
        v1 = v1 + v5;
        v13 ^= v1;
        v13 = v13 << (32 - 16) | v13 >>> 16;
        v9 = v9 + v13;
        v5 ^= v9;
        v5 = v5 << (32 - 12) | v5 >>> 12;
        v2 = v2 + m5;
        v2 = v2 + v6;
        v14 ^= v2;
        v14 = v14 << (32 - 16) | v14 >>> 16;
        v10 = v10 + v14;
        v6 ^= v10;
        v6 = v6 << (32 - 12) | v6 >>> 12;
        v3 = v3 + m15;
        v3 = v3 + v7;
        v15 ^= v3;
        v15 = v15 << (32 - 16) | v15 >>> 16;
        v11 = v11 + v15;
        v7 ^= v11;
        v7 = v7 << (32 - 12) | v7 >>> 12;
        v2 = v2 + m2;
        v2 = v2 + v6;
        v14 ^= v2;
        v14 = v14 << (32 - 8) | v14 >>> 8;
        v10 = v10 + v14;
        v6 ^= v10;
        v6 = v6 << (32 - 7) | v6 >>> 7;
        v3 = v3 + m13;
        v3 = v3 + v7;
        v15 ^= v3;
        v15 = v15 << (32 - 8) | v15 >>> 8;
        v11 = v11 + v15;
        v7 ^= v11;
        v7 = v7 << (32 - 7) | v7 >>> 7;
        v1 = v1 + m0;
        v1 = v1 + v5;
        v13 ^= v1;
        v13 = v13 << (32 - 8) | v13 >>> 8;
        v9 = v9 + v13;
        v5 ^= v9;
        v5 = v5 << (32 - 7) | v5 >>> 7;
        v0 = v0 + m8;
        v0 = v0 + v4;
        v12 ^= v0;
        v12 = v12 << (32 - 8) | v12 >>> 8;
        v8 = v8 + v12;
        v4 ^= v8;
        v4 = v4 << (32 - 7) | v4 >>> 7;
        v0 = v0 + m10;
        v0 = v0 + v5;
        v15 ^= v0;
        v15 = v15 << (32 - 16) | v15 >>> 16;
        v10 = v10 + v15;
        v5 ^= v10;
        v5 = v5 << (32 - 12) | v5 >>> 12;
        v1 = v1 + m3;
        v1 = v1 + v6;
        v12 ^= v1;
        v12 = v12 << (32 - 16) | v12 >>> 16;
        v11 = v11 + v12;
        v6 ^= v11;
        v6 = v6 << (32 - 12) | v6 >>> 12;
        v2 = v2 + m7;
        v2 = v2 + v7;
        v13 ^= v2;
        v13 = v13 << (32 - 16) | v13 >>> 16;
        v8 = v8 + v13;
        v7 ^= v8;
        v7 = v7 << (32 - 12) | v7 >>> 12;
        v3 = v3 + m9;
        v3 = v3 + v4;
        v14 ^= v3;
        v14 = v14 << (32 - 16) | v14 >>> 16;
        v9 = v9 + v14;
        v4 ^= v9;
        v4 = v4 << (32 - 12) | v4 >>> 12;
        v2 = v2 + m1;
        v2 = v2 + v7;
        v13 ^= v2;
        v13 = v13 << (32 - 8) | v13 >>> 8;
        v8 = v8 + v13;
        v7 ^= v8;
        v7 = v7 << (32 - 7) | v7 >>> 7;
        v3 = v3 + m4;
        v3 = v3 + v4;
        v14 ^= v3;
        v14 = v14 << (32 - 8) | v14 >>> 8;
        v9 = v9 + v14;
        v4 ^= v9;
        v4 = v4 << (32 - 7) | v4 >>> 7;
        v1 = v1 + m6;
        v1 = v1 + v6;
        v12 ^= v1;
        v12 = v12 << (32 - 8) | v12 >>> 8;
        v11 = v11 + v12;
        v6 ^= v11;
        v6 = v6 << (32 - 7) | v6 >>> 7;
        v0 = v0 + m14;
        v0 = v0 + v5;
        v15 ^= v0;
        v15 = v15 << (32 - 8) | v15 >>> 8;
        v10 = v10 + v15;
        v5 ^= v10;
        v5 = v5 << (32 - 7) | v5 >>> 7;

        // Round 4.
        v0 = v0 + m7;
        v0 = v0 + v4;
        v12 ^= v0;
        v12 = v12 << (32 - 16) | v12 >>> 16;
        v8 = v8 + v12;
        v4 ^= v8;
        v4 = v4 << (32 - 12) | v4 >>> 12;
        v1 = v1 + m3;
        v1 = v1 + v5;
        v13 ^= v1;
        v13 = v13 << (32 - 16) | v13 >>> 16;
        v9 = v9 + v13;
        v5 ^= v9;
        v5 = v5 << (32 - 12) | v5 >>> 12;
        v2 = v2 + m13;
        v2 = v2 + v6;
        v14 ^= v2;
        v14 = v14 << (32 - 16) | v14 >>> 16;
        v10 = v10 + v14;
        v6 ^= v10;
        v6 = v6 << (32 - 12) | v6 >>> 12;
        v3 = v3 + m11;
        v3 = v3 + v7;
        v15 ^= v3;
        v15 = v15 << (32 - 16) | v15 >>> 16;
        v11 = v11 + v15;
        v7 ^= v11;
        v7 = v7 << (32 - 12) | v7 >>> 12;
        v2 = v2 + m12;
        v2 = v2 + v6;
        v14 ^= v2;
        v14 = v14 << (32 - 8) | v14 >>> 8;
        v10 = v10 + v14;
        v6 ^= v10;
        v6 = v6 << (32 - 7) | v6 >>> 7;
        v3 = v3 + m14;
        v3 = v3 + v7;
        v15 ^= v3;
        v15 = v15 << (32 - 8) | v15 >>> 8;
        v11 = v11 + v15;
        v7 ^= v11;
        v7 = v7 << (32 - 7) | v7 >>> 7;
        v1 = v1 + m1;
        v1 = v1 + v5;
        v13 ^= v1;
        v13 = v13 << (32 - 8) | v13 >>> 8;
        v9 = v9 + v13;
        v5 ^= v9;
        v5 = v5 << (32 - 7) | v5 >>> 7;
        v0 = v0 + m9;
        v0 = v0 + v4;
        v12 ^= v0;
        v12 = v12 << (32 - 8) | v12 >>> 8;
        v8 = v8 + v12;
        v4 ^= v8;
        v4 = v4 << (32 - 7) | v4 >>> 7;
        v0 = v0 + m2;
        v0 = v0 + v5;
        v15 ^= v0;
        v15 = v15 << (32 - 16) | v15 >>> 16;
        v10 = v10 + v15;
        v5 ^= v10;
        v5 = v5 << (32 - 12) | v5 >>> 12;
        v1 = v1 + m5;
        v1 = v1 + v6;
        v12 ^= v1;
        v12 = v12 << (32 - 16) | v12 >>> 16;
        v11 = v11 + v12;
        v6 ^= v11;
        v6 = v6 << (32 - 12) | v6 >>> 12;
        v2 = v2 + m4;
        v2 = v2 + v7;
        v13 ^= v2;
        v13 = v13 << (32 - 16) | v13 >>> 16;
        v8 = v8 + v13;
        v7 ^= v8;
        v7 = v7 << (32 - 12) | v7 >>> 12;
        v3 = v3 + m15;
        v3 = v3 + v4;
        v14 ^= v3;
        v14 = v14 << (32 - 16) | v14 >>> 16;
        v9 = v9 + v14;
        v4 ^= v9;
        v4 = v4 << (32 - 12) | v4 >>> 12;
        v2 = v2 + m0;
        v2 = v2 + v7;
        v13 ^= v2;
        v13 = v13 << (32 - 8) | v13 >>> 8;
        v8 = v8 + v13;
        v7 ^= v8;
        v7 = v7 << (32 - 7) | v7 >>> 7;
        v3 = v3 + m8;
        v3 = v3 + v4;
        v14 ^= v3;
        v14 = v14 << (32 - 8) | v14 >>> 8;
        v9 = v9 + v14;
        v4 ^= v9;
        v4 = v4 << (32 - 7) | v4 >>> 7;
        v1 = v1 + m10;
        v1 = v1 + v6;
        v12 ^= v1;
        v12 = v12 << (32 - 8) | v12 >>> 8;
        v11 = v11 + v12;
        v6 ^= v11;
        v6 = v6 << (32 - 7) | v6 >>> 7;
        v0 = v0 + m6;
        v0 = v0 + v5;
        v15 ^= v0;
        v15 = v15 << (32 - 8) | v15 >>> 8;
        v10 = v10 + v15;
        v5 ^= v10;
        v5 = v5 << (32 - 7) | v5 >>> 7;

        // Round 5.
        v0 = v0 + m9;
        v0 = v0 + v4;
        v12 ^= v0;
        v12 = v12 << (32 - 16) | v12 >>> 16;
        v8 = v8 + v12;
        v4 ^= v8;
        v4 = v4 << (32 - 12) | v4 >>> 12;
        v1 = v1 + m5;
        v1 = v1 + v5;
        v13 ^= v1;
        v13 = v13 << (32 - 16) | v13 >>> 16;
        v9 = v9 + v13;
        v5 ^= v9;
        v5 = v5 << (32 - 12) | v5 >>> 12;
        v2 = v2 + m2;
        v2 = v2 + v6;
        v14 ^= v2;
        v14 = v14 << (32 - 16) | v14 >>> 16;
        v10 = v10 + v14;
        v6 ^= v10;
        v6 = v6 << (32 - 12) | v6 >>> 12;
        v3 = v3 + m10;
        v3 = v3 + v7;
        v15 ^= v3;
        v15 = v15 << (32 - 16) | v15 >>> 16;
        v11 = v11 + v15;
        v7 ^= v11;
        v7 = v7 << (32 - 12) | v7 >>> 12;
        v2 = v2 + m4;
        v2 = v2 + v6;
        v14 ^= v2;
        v14 = v14 << (32 - 8) | v14 >>> 8;
        v10 = v10 + v14;
        v6 ^= v10;
        v6 = v6 << (32 - 7) | v6 >>> 7;
        v3 = v3 + m15;
        v3 = v3 + v7;
        v15 ^= v3;
        v15 = v15 << (32 - 8) | v15 >>> 8;
        v11 = v11 + v15;
        v7 ^= v11;
        v7 = v7 << (32 - 7) | v7 >>> 7;
        v1 = v1 + m7;
        v1 = v1 + v5;
        v13 ^= v1;
        v13 = v13 << (32 - 8) | v13 >>> 8;
        v9 = v9 + v13;
        v5 ^= v9;
        v5 = v5 << (32 - 7) | v5 >>> 7;
        v0 = v0 + m0;
        v0 = v0 + v4;
        v12 ^= v0;
        v12 = v12 << (32 - 8) | v12 >>> 8;
        v8 = v8 + v12;
        v4 ^= v8;
        v4 = v4 << (32 - 7) | v4 >>> 7;
        v0 = v0 + m14;
        v0 = v0 + v5;
        v15 ^= v0;
        v15 = v15 << (32 - 16) | v15 >>> 16;
        v10 = v10 + v15;
        v5 ^= v10;
        v5 = v5 << (32 - 12) | v5 >>> 12;
        v1 = v1 + m11;
        v1 = v1 + v6;
        v12 ^= v1;
        v12 = v12 << (32 - 16) | v12 >>> 16;
        v11 = v11 + v12;
        v6 ^= v11;
        v6 = v6 << (32 - 12) | v6 >>> 12;
        v2 = v2 + m6;
        v2 = v2 + v7;
        v13 ^= v2;
        v13 = v13 << (32 - 16) | v13 >>> 16;
        v8 = v8 + v13;
        v7 ^= v8;
        v7 = v7 << (32 - 12) | v7 >>> 12;
        v3 = v3 + m3;
        v3 = v3 + v4;
        v14 ^= v3;
        v14 = v14 << (32 - 16) | v14 >>> 16;
        v9 = v9 + v14;
        v4 ^= v9;
        v4 = v4 << (32 - 12) | v4 >>> 12;
        v2 = v2 + m8;
        v2 = v2 + v7;
        v13 ^= v2;
        v13 = v13 << (32 - 8) | v13 >>> 8;
        v8 = v8 + v13;
        v7 ^= v8;
        v7 = v7 << (32 - 7) | v7 >>> 7;
        v3 = v3 + m13;
        v3 = v3 + v4;
        v14 ^= v3;
        v14 = v14 << (32 - 8) | v14 >>> 8;
        v9 = v9 + v14;
        v4 ^= v9;
        v4 = v4 << (32 - 7) | v4 >>> 7;
        v1 = v1 + m12;
        v1 = v1 + v6;
        v12 ^= v1;
        v12 = v12 << (32 - 8) | v12 >>> 8;
        v11 = v11 + v12;
        v6 ^= v11;
        v6 = v6 << (32 - 7) | v6 >>> 7;
        v0 = v0 + m1;
        v0 = v0 + v5;
        v15 ^= v0;
        v15 = v15 << (32 - 8) | v15 >>> 8;
        v10 = v10 + v15;
        v5 ^= v10;
        v5 = v5 << (32 - 7) | v5 >>> 7;

        // Round 6.
        v0 = v0 + m2;
        v0 = v0 + v4;
        v12 ^= v0;
        v12 = v12 << (32 - 16) | v12 >>> 16;
        v8 = v8 + v12;
        v4 ^= v8;
        v4 = v4 << (32 - 12) | v4 >>> 12;
        v1 = v1 + m6;
        v1 = v1 + v5;
        v13 ^= v1;
        v13 = v13 << (32 - 16) | v13 >>> 16;
        v9 = v9 + v13;
        v5 ^= v9;
        v5 = v5 << (32 - 12) | v5 >>> 12;
        v2 = v2 + m0;
        v2 = v2 + v6;
        v14 ^= v2;
        v14 = v14 << (32 - 16) | v14 >>> 16;
        v10 = v10 + v14;
        v6 ^= v10;
        v6 = v6 << (32 - 12) | v6 >>> 12;
        v3 = v3 + m8;
        v3 = v3 + v7;
        v15 ^= v3;
        v15 = v15 << (32 - 16) | v15 >>> 16;
        v11 = v11 + v15;
        v7 ^= v11;
        v7 = v7 << (32 - 12) | v7 >>> 12;
        v2 = v2 + m11;
        v2 = v2 + v6;
        v14 ^= v2;
        v14 = v14 << (32 - 8) | v14 >>> 8;
        v10 = v10 + v14;
        v6 ^= v10;
        v6 = v6 << (32 - 7) | v6 >>> 7;
        v3 = v3 + m3;
        v3 = v3 + v7;
        v15 ^= v3;
        v15 = v15 << (32 - 8) | v15 >>> 8;
        v11 = v11 + v15;
        v7 ^= v11;
        v7 = v7 << (32 - 7) | v7 >>> 7;
        v1 = v1 + m10;
        v1 = v1 + v5;
        v13 ^= v1;
        v13 = v13 << (32 - 8) | v13 >>> 8;
        v9 = v9 + v13;
        v5 ^= v9;
        v5 = v5 << (32 - 7) | v5 >>> 7;
        v0 = v0 + m12;
        v0 = v0 + v4;
        v12 ^= v0;
        v12 = v12 << (32 - 8) | v12 >>> 8;
        v8 = v8 + v12;
        v4 ^= v8;
        v4 = v4 << (32 - 7) | v4 >>> 7;
        v0 = v0 + m4;
        v0 = v0 + v5;
        v15 ^= v0;
        v15 = v15 << (32 - 16) | v15 >>> 16;
        v10 = v10 + v15;
        v5 ^= v10;
        v5 = v5 << (32 - 12) | v5 >>> 12;
        v1 = v1 + m7;
        v1 = v1 + v6;
        v12 ^= v1;
        v12 = v12 << (32 - 16) | v12 >>> 16;
        v11 = v11 + v12;
        v6 ^= v11;
        v6 = v6 << (32 - 12) | v6 >>> 12;
        v2 = v2 + m15;
        v2 = v2 + v7;
        v13 ^= v2;
        v13 = v13 << (32 - 16) | v13 >>> 16;
        v8 = v8 + v13;
        v7 ^= v8;
        v7 = v7 << (32 - 12) | v7 >>> 12;
        v3 = v3 + m1;
        v3 = v3 + v4;
        v14 ^= v3;
        v14 = v14 << (32 - 16) | v14 >>> 16;
        v9 = v9 + v14;
        v4 ^= v9;
        v4 = v4 << (32 - 12) | v4 >>> 12;
        v2 = v2 + m14;
        v2 = v2 + v7;
        v13 ^= v2;
        v13 = v13 << (32 - 8) | v13 >>> 8;
        v8 = v8 + v13;
        v7 ^= v8;
        v7 = v7 << (32 - 7) | v7 >>> 7;
        v3 = v3 + m9;
        v3 = v3 + v4;
        v14 ^= v3;
        v14 = v14 << (32 - 8) | v14 >>> 8;
        v9 = v9 + v14;
        v4 ^= v9;
        v4 = v4 << (32 - 7) | v4 >>> 7;
        v1 = v1 + m5;
        v1 = v1 + v6;
        v12 ^= v1;
        v12 = v12 << (32 - 8) | v12 >>> 8;
        v11 = v11 + v12;
        v6 ^= v11;
        v6 = v6 << (32 - 7) | v6 >>> 7;
        v0 = v0 + m13;
        v0 = v0 + v5;
        v15 ^= v0;
        v15 = v15 << (32 - 8) | v15 >>> 8;
        v10 = v10 + v15;
        v5 ^= v10;
        v5 = v5 << (32 - 7) | v5 >>> 7;

        // Round 7.
        v0 = v0 + m12;
        v0 = v0 + v4;
        v12 ^= v0;
        v12 = v12 << (32 - 16) | v12 >>> 16;
        v8 = v8 + v12;
        v4 ^= v8;
        v4 = v4 << (32 - 12) | v4 >>> 12;
        v1 = v1 + m1;
        v1 = v1 + v5;
        v13 ^= v1;
        v13 = v13 << (32 - 16) | v13 >>> 16;
        v9 = v9 + v13;
        v5 ^= v9;
        v5 = v5 << (32 - 12) | v5 >>> 12;
        v2 = v2 + m14;
        v2 = v2 + v6;
        v14 ^= v2;
        v14 = v14 << (32 - 16) | v14 >>> 16;
        v10 = v10 + v14;
        v6 ^= v10;
        v6 = v6 << (32 - 12) | v6 >>> 12;
        v3 = v3 + m4;
        v3 = v3 + v7;
        v15 ^= v3;
        v15 = v15 << (32 - 16) | v15 >>> 16;
        v11 = v11 + v15;
        v7 ^= v11;
        v7 = v7 << (32 - 12) | v7 >>> 12;
        v2 = v2 + m13;
        v2 = v2 + v6;
        v14 ^= v2;
        v14 = v14 << (32 - 8) | v14 >>> 8;
        v10 = v10 + v14;
        v6 ^= v10;
        v6 = v6 << (32 - 7) | v6 >>> 7;
        v3 = v3 + m10;
        v3 = v3 + v7;
        v15 ^= v3;
        v15 = v15 << (32 - 8) | v15 >>> 8;
        v11 = v11 + v15;
        v7 ^= v11;
        v7 = v7 << (32 - 7) | v7 >>> 7;
        v1 = v1 + m15;
        v1 = v1 + v5;
        v13 ^= v1;
        v13 = v13 << (32 - 8) | v13 >>> 8;
        v9 = v9 + v13;
        v5 ^= v9;
        v5 = v5 << (32 - 7) | v5 >>> 7;
        v0 = v0 + m5;
        v0 = v0 + v4;
        v12 ^= v0;
        v12 = v12 << (32 - 8) | v12 >>> 8;
        v8 = v8 + v12;
        v4 ^= v8;
        v4 = v4 << (32 - 7) | v4 >>> 7;
        v0 = v0 + m0;
        v0 = v0 + v5;
        v15 ^= v0;
        v15 = v15 << (32 - 16) | v15 >>> 16;
        v10 = v10 + v15;
        v5 ^= v10;
        v5 = v5 << (32 - 12) | v5 >>> 12;
        v1 = v1 + m6;
        v1 = v1 + v6;
        v12 ^= v1;
        v12 = v12 << (32 - 16) | v12 >>> 16;
        v11 = v11 + v12;
        v6 ^= v11;
        v6 = v6 << (32 - 12) | v6 >>> 12;
        v2 = v2 + m9;
        v2 = v2 + v7;
        v13 ^= v2;
        v13 = v13 << (32 - 16) | v13 >>> 16;
        v8 = v8 + v13;
        v7 ^= v8;
        v7 = v7 << (32 - 12) | v7 >>> 12;
        v3 = v3 + m8;
        v3 = v3 + v4;
        v14 ^= v3;
        v14 = v14 << (32 - 16) | v14 >>> 16;
        v9 = v9 + v14;
        v4 ^= v9;
        v4 = v4 << (32 - 12) | v4 >>> 12;
        v2 = v2 + m2;
        v2 = v2 + v7;
        v13 ^= v2;
        v13 = v13 << (32 - 8) | v13 >>> 8;
        v8 = v8 + v13;
        v7 ^= v8;
        v7 = v7 << (32 - 7) | v7 >>> 7;
        v3 = v3 + m11;
        v3 = v3 + v4;
        v14 ^= v3;
        v14 = v14 << (32 - 8) | v14 >>> 8;
        v9 = v9 + v14;
        v4 ^= v9;
        v4 = v4 << (32 - 7) | v4 >>> 7;
        v1 = v1 + m3;
        v1 = v1 + v6;
        v12 ^= v1;
        v12 = v12 << (32 - 8) | v12 >>> 8;
        v11 = v11 + v12;
        v6 ^= v11;
        v6 = v6 << (32 - 7) | v6 >>> 7;
        v0 = v0 + m7;
        v0 = v0 + v5;
        v15 ^= v0;
        v15 = v15 << (32 - 8) | v15 >>> 8;
        v10 = v10 + v15;
        v5 ^= v10;
        v5 = v5 << (32 - 7) | v5 >>> 7;

        // Round 8.
        v0 = v0 + m13;
        v0 = v0 + v4;
        v12 ^= v0;
        v12 = v12 << (32 - 16) | v12 >>> 16;
        v8 = v8 + v12;
        v4 ^= v8;
        v4 = v4 << (32 - 12) | v4 >>> 12;
        v1 = v1 + m7;
        v1 = v1 + v5;
        v13 ^= v1;
        v13 = v13 << (32 - 16) | v13 >>> 16;
        v9 = v9 + v13;
        v5 ^= v9;
        v5 = v5 << (32 - 12) | v5 >>> 12;
        v2 = v2 + m12;
        v2 = v2 + v6;
        v14 ^= v2;
        v14 = v14 << (32 - 16) | v14 >>> 16;
        v10 = v10 + v14;
        v6 ^= v10;
        v6 = v6 << (32 - 12) | v6 >>> 12;
        v3 = v3 + m3;
        v3 = v3 + v7;
        v15 ^= v3;
        v15 = v15 << (32 - 16) | v15 >>> 16;
        v11 = v11 + v15;
        v7 ^= v11;
        v7 = v7 << (32 - 12) | v7 >>> 12;
        v2 = v2 + m1;
        v2 = v2 + v6;
        v14 ^= v2;
        v14 = v14 << (32 - 8) | v14 >>> 8;
        v10 = v10 + v14;
        v6 ^= v10;
        v6 = v6 << (32 - 7) | v6 >>> 7;
        v3 = v3 + m9;
        v3 = v3 + v7;
        v15 ^= v3;
        v15 = v15 << (32 - 8) | v15 >>> 8;
        v11 = v11 + v15;
        v7 ^= v11;
        v7 = v7 << (32 - 7) | v7 >>> 7;
        v1 = v1 + m14;
        v1 = v1 + v5;
        v13 ^= v1;
        v13 = v13 << (32 - 8) | v13 >>> 8;
        v9 = v9 + v13;
        v5 ^= v9;
        v5 = v5 << (32 - 7) | v5 >>> 7;
        v0 = v0 + m11;
        v0 = v0 + v4;
        v12 ^= v0;
        v12 = v12 << (32 - 8) | v12 >>> 8;
        v8 = v8 + v12;
        v4 ^= v8;
        v4 = v4 << (32 - 7) | v4 >>> 7;
        v0 = v0 + m5;
        v0 = v0 + v5;
        v15 ^= v0;
        v15 = v15 << (32 - 16) | v15 >>> 16;
        v10 = v10 + v15;
        v5 ^= v10;
        v5 = v5 << (32 - 12) | v5 >>> 12;
        v1 = v1 + m15;
        v1 = v1 + v6;
        v12 ^= v1;
        v12 = v12 << (32 - 16) | v12 >>> 16;
        v11 = v11 + v12;
        v6 ^= v11;
        v6 = v6 << (32 - 12) | v6 >>> 12;
        v2 = v2 + m8;
        v2 = v2 + v7;
        v13 ^= v2;
        v13 = v13 << (32 - 16) | v13 >>> 16;
        v8 = v8 + v13;
        v7 ^= v8;
        v7 = v7 << (32 - 12) | v7 >>> 12;
        v3 = v3 + m2;
        v3 = v3 + v4;
        v14 ^= v3;
        v14 = v14 << (32 - 16) | v14 >>> 16;
        v9 = v9 + v14;
        v4 ^= v9;
        v4 = v4 << (32 - 12) | v4 >>> 12;
        v2 = v2 + m6;
        v2 = v2 + v7;
        v13 ^= v2;
        v13 = v13 << (32 - 8) | v13 >>> 8;
        v8 = v8 + v13;
        v7 ^= v8;
        v7 = v7 << (32 - 7) | v7 >>> 7;
        v3 = v3 + m10;
        v3 = v3 + v4;
        v14 ^= v3;
        v14 = v14 << (32 - 8) | v14 >>> 8;
        v9 = v9 + v14;
        v4 ^= v9;
        v4 = v4 << (32 - 7) | v4 >>> 7;
        v1 = v1 + m4;
        v1 = v1 + v6;
        v12 ^= v1;
        v12 = v12 << (32 - 8) | v12 >>> 8;
        v11 = v11 + v12;
        v6 ^= v11;
        v6 = v6 << (32 - 7) | v6 >>> 7;
        v0 = v0 + m0;
        v0 = v0 + v5;
        v15 ^= v0;
        v15 = v15 << (32 - 8) | v15 >>> 8;
        v10 = v10 + v15;
        v5 ^= v10;
        v5 = v5 << (32 - 7) | v5 >>> 7;

        // Round 9.
        v0 = v0 + m6;
        v0 = v0 + v4;
        v12 ^= v0;
        v12 = v12 << (32 - 16) | v12 >>> 16;
        v8 = v8 + v12;
        v4 ^= v8;
        v4 = v4 << (32 - 12) | v4 >>> 12;
        v1 = v1 + m14;
        v1 = v1 + v5;
        v13 ^= v1;
        v13 = v13 << (32 - 16) | v13 >>> 16;
        v9 = v9 + v13;
        v5 ^= v9;
        v5 = v5 << (32 - 12) | v5 >>> 12;
        v2 = v2 + m11;
        v2 = v2 + v6;
        v14 ^= v2;
        v14 = v14 << (32 - 16) | v14 >>> 16;
        v10 = v10 + v14;
        v6 ^= v10;
        v6 = v6 << (32 - 12) | v6 >>> 12;
        v3 = v3 + m0;
        v3 = v3 + v7;
        v15 ^= v3;
        v15 = v15 << (32 - 16) | v15 >>> 16;
        v11 = v11 + v15;
        v7 ^= v11;
        v7 = v7 << (32 - 12) | v7 >>> 12;
        v2 = v2 + m3;
        v2 = v2 + v6;
        v14 ^= v2;
        v14 = v14 << (32 - 8) | v14 >>> 8;
        v10 = v10 + v14;
        v6 ^= v10;
        v6 = v6 << (32 - 7) | v6 >>> 7;
        v3 = v3 + m8;
        v3 = v3 + v7;
        v15 ^= v3;
        v15 = v15 << (32 - 8) | v15 >>> 8;
        v11 = v11 + v15;
        v7 ^= v11;
        v7 = v7 << (32 - 7) | v7 >>> 7;
        v1 = v1 + m9;
        v1 = v1 + v5;
        v13 ^= v1;
        v13 = v13 << (32 - 8) | v13 >>> 8;
        v9 = v9 + v13;
        v5 ^= v9;
        v5 = v5 << (32 - 7) | v5 >>> 7;
        v0 = v0 + m15;
        v0 = v0 + v4;
        v12 ^= v0;
        v12 = v12 << (32 - 8) | v12 >>> 8;
        v8 = v8 + v12;
        v4 ^= v8;
        v4 = v4 << (32 - 7) | v4 >>> 7;
        v0 = v0 + m12;
        v0 = v0 + v5;
        v15 ^= v0;
        v15 = v15 << (32 - 16) | v15 >>> 16;
        v10 = v10 + v15;
        v5 ^= v10;
        v5 = v5 << (32 - 12) | v5 >>> 12;
        v1 = v1 + m13;
        v1 = v1 + v6;
        v12 ^= v1;
        v12 = v12 << (32 - 16) | v12 >>> 16;
        v11 = v11 + v12;
        v6 ^= v11;
        v6 = v6 << (32 - 12) | v6 >>> 12;
        v2 = v2 + m1;
        v2 = v2 + v7;
        v13 ^= v2;
        v13 = v13 << (32 - 16) | v13 >>> 16;
        v8 = v8 + v13;
        v7 ^= v8;
        v7 = v7 << (32 - 12) | v7 >>> 12;
        v3 = v3 + m10;
        v3 = v3 + v4;
        v14 ^= v3;
        v14 = v14 << (32 - 16) | v14 >>> 16;
        v9 = v9 + v14;
        v4 ^= v9;
        v4 = v4 << (32 - 12) | v4 >>> 12;
        v2 = v2 + m4;
        v2 = v2 + v7;
        v13 ^= v2;
        v13 = v13 << (32 - 8) | v13 >>> 8;
        v8 = v8 + v13;
        v7 ^= v8;
        v7 = v7 << (32 - 7) | v7 >>> 7;
        v3 = v3 + m5;
        v3 = v3 + v4;
        v14 ^= v3;
        v14 = v14 << (32 - 8) | v14 >>> 8;
        v9 = v9 + v14;
        v4 ^= v9;
        v4 = v4 << (32 - 7) | v4 >>> 7;
        v1 = v1 + m7;
        v1 = v1 + v6;
        v12 ^= v1;
        v12 = v12 << (32 - 8) | v12 >>> 8;
        v11 = v11 + v12;
        v6 ^= v11;
        v6 = v6 << (32 - 7) | v6 >>> 7;
        v0 = v0 + m2;
        v0 = v0 + v5;
        v15 ^= v0;
        v15 = v15 << (32 - 8) | v15 >>> 8;
        v10 = v10 + v15;
        v5 ^= v10;
        v5 = v5 << (32 - 7) | v5 >>> 7;

        // Round 10.
        v0 = v0 + m10;
        v0 = v0 + v4;
        v12 ^= v0;
        v12 = v12 << (32 - 16) | v12 >>> 16;
        v8 = v8 + v12;
        v4 ^= v8;
        v4 = v4 << (32 - 12) | v4 >>> 12;
        v1 = v1 + m8;
        v1 = v1 + v5;
        v13 ^= v1;
        v13 = v13 << (32 - 16) | v13 >>> 16;
        v9 = v9 + v13;
        v5 ^= v9;
        v5 = v5 << (32 - 12) | v5 >>> 12;
        v2 = v2 + m7;
        v2 = v2 + v6;
        v14 ^= v2;
        v14 = v14 << (32 - 16) | v14 >>> 16;
        v10 = v10 + v14;
        v6 ^= v10;
        v6 = v6 << (32 - 12) | v6 >>> 12;
        v3 = v3 + m1;
        v3 = v3 + v7;
        v15 ^= v3;
        v15 = v15 << (32 - 16) | v15 >>> 16;
        v11 = v11 + v15;
        v7 ^= v11;
        v7 = v7 << (32 - 12) | v7 >>> 12;
        v2 = v2 + m6;
        v2 = v2 + v6;
        v14 ^= v2;
        v14 = v14 << (32 - 8) | v14 >>> 8;
        v10 = v10 + v14;
        v6 ^= v10;
        v6 = v6 << (32 - 7) | v6 >>> 7;
        v3 = v3 + m5;
        v3 = v3 + v7;
        v15 ^= v3;
        v15 = v15 << (32 - 8) | v15 >>> 8;
        v11 = v11 + v15;
        v7 ^= v11;
        v7 = v7 << (32 - 7) | v7 >>> 7;
        v1 = v1 + m4;
        v1 = v1 + v5;
        v13 ^= v1;
        v13 = v13 << (32 - 8) | v13 >>> 8;
        v9 = v9 + v13;
        v5 ^= v9;
        v5 = v5 << (32 - 7) | v5 >>> 7;
        v0 = v0 + m2;
        v0 = v0 + v4;
        v12 ^= v0;
        v12 = v12 << (32 - 8) | v12 >>> 8;
        v8 = v8 + v12;
        v4 ^= v8;
        v4 = v4 << (32 - 7) | v4 >>> 7;
        v0 = v0 + m15;
        v0 = v0 + v5;
        v15 ^= v0;
        v15 = v15 << (32 - 16) | v15 >>> 16;
        v10 = v10 + v15;
        v5 ^= v10;
        v5 = v5 << (32 - 12) | v5 >>> 12;
        v1 = v1 + m9;
        v1 = v1 + v6;
        v12 ^= v1;
        v12 = v12 << (32 - 16) | v12 >>> 16;
        v11 = v11 + v12;
        v6 ^= v11;
        v6 = v6 << (32 - 12) | v6 >>> 12;
        v2 = v2 + m3;
        v2 = v2 + v7;
        v13 ^= v2;
        v13 = v13 << (32 - 16) | v13 >>> 16;
        v8 = v8 + v13;
        v7 ^= v8;
        v7 = v7 << (32 - 12) | v7 >>> 12;
        v3 = v3 + m13;
        v3 = v3 + v4;
        v14 ^= v3;
        v14 = v14 << (32 - 16) | v14 >>> 16;
        v9 = v9 + v14;
        v4 ^= v9;
        v4 = v4 << (32 - 12) | v4 >>> 12;
        v2 = v2 + m12;
        v2 = v2 + v7;
        v13 ^= v2;
        v13 = v13 << (32 - 8) | v13 >>> 8;
        v8 = v8 + v13;
        v7 ^= v8;
        v7 = v7 << (32 - 7) | v7 >>> 7;
        v3 = v3 + m0;
        v3 = v3 + v4;
        v14 ^= v3;
        v14 = v14 << (32 - 8) | v14 >>> 8;
        v9 = v9 + v14;
        v4 ^= v9;
        v4 = v4 << (32 - 7) | v4 >>> 7;
        v1 = v1 + m14;
        v1 = v1 + v6;
        v12 ^= v1;
        v12 = v12 << (32 - 8) | v12 >>> 8;
        v11 = v11 + v12;
        v6 ^= v11;
        v6 = v6 << (32 - 7) | v6 >>> 7;
        v0 = v0 + m11;
        v0 = v0 + v5;
        v15 ^= v0;
        v15 = v15 << (32 - 8) | v15 >>> 8;
        v10 = v10 + v15;
        v5 ^= v10;
        v5 = v5 << (32 - 7) | v5 >>> 7;

        cfg[0] ^= v0 ^ v8;
        cfg[1] ^= v1 ^ v9;
        cfg[2] ^= v2 ^ v10;
        cfg[3] ^= v3 ^ v11;
        cfg[4] ^= v4 ^ v12;
        cfg[5] ^= v5 ^ v13;
        cfg[6] ^= v6 ^ v14;
        cfg[7] ^= v7 ^ v15;
    }

    private static class Blake2sTree {
        private int fanout = 1;
        private int maxDepth = 1;
        private long leafSize = 0;
        private int innerDigestLength = 0;
        private long nodeOffset = 0;
        private int nodeDepth = 0;
        private boolean lastNode = false;

        public Blake2sTree() {
        }

//        private Blake2sTree(int fanout, int maxDepth, long leafSize, int innerDigestLength, long nodeOffset, int nodeDepth, boolean lastNode) {
//            this.fanout = fanout;
//            this.maxDepth = maxDepth;
//            this.leafSize = leafSize;
//            this.innerDigestLength = innerDigestLength;
//            this.nodeOffset = nodeOffset;
//            this.nodeDepth = nodeDepth;
//            this.lastNode = lastNode;
//        }

        public int getFanout() {
            return this.fanout;
        }

        public int getMaxDepth() {
            return this.maxDepth;
        }

        public long getLeafSize() {
            return this.leafSize;
        }

        public int getInnerDigestLength() {
            return this.innerDigestLength;
        }

        public long getNodeOffset() {
            return this.nodeOffset;
        }

//        public void incrementNodeOffset() {
//            nodeOffset++;
//        }

        public int getNodeDepth() {
            return this.nodeDepth;
        }

        public boolean isLastNode() {
            return this.lastNode;
        }
    }
}
