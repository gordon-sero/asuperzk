/*
 * Copyright (c) [2016] [ <ether.camp> ]
 * This file is part of the ethereumJ library.
 *
 * The ethereumJ library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The ethereumJ library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the ethereumJ library. If not, see <http://www.gnu.org/licenses/>.
 */
package org.ethereum.util;

import static org.ethereum.crypto.HashUtil.sha3;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.ethereum.crypto.HashUtil;
import org.junit.Test;
import org.sero.cash.superzk.util.Arrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongycastle.crypto.engines.AESEngine;
import org.spongycastle.crypto.modes.SICBlockCipher;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.crypto.params.ParametersWithIV;
import org.spongycastle.util.encoders.Hex;

public class CryptoTest {

    private static final Logger log = LoggerFactory.getLogger("test");

    @Test
    public void test() {
        byte[] bytes1 = sha3(Arrays.concat(new byte[]{1}, new byte[]{2}));
        byte[] bytes2 = sha3(new byte[]{1}, new byte[]{2});
        assertTrue(Arrays.equals(bytes1, bytes2));
    }

    @Test
    public void test1() {

        byte[] result = HashUtil.sha3("horse".getBytes());

        assertEquals("c87f65ff3f271bf5dc8643484f66b200109caffe4bf98c4cb393dc35740b28c0",
                Hex.toHexString(result));

        result = HashUtil.sha3("cow".getBytes());

        assertEquals("c85ef7d79691fe79573b1a7064c19c1a9819ebdbd1faaab1a8ec92344438aaf4",
                Hex.toHexString(result));
    }



    @Test /* real tx hash calc */
    public void test7() {

        String txRaw = "F89D80809400000000000000000000000000000000000000008609184E72A000822710B3606956330C0D630000003359366000530A0D630000003359602060005301356000533557604060005301600054630000000C5884336069571CA07F6EB94576346488C6253197BDE6A7E59DDC36F2773672C849402AA9C402C3C4A06D254E662BF7450DD8D835160CBB053463FED0B53F2CDD7F3EA8731919C8E8CC";
        byte[] txHashB = HashUtil.sha3(Hex.decode(txRaw));
        String txHash = Hex.toHexString(txHashB);
        assertEquals("4b7d9670a92bf120d5b43400543b69304a14d767cf836a7f6abff4edde092895", txHash);
    }

    @Test /* real block hash calc */
    public void test8() {

        String blockRaw = "F885F8818080A01DCC4DE8DEC75D7AAB85B567B6CCD41AD312451B948A7413F0A142FD40D49347940000000000000000000000000000000000000000A0BCDDD284BF396739C224DBA0411566C891C32115FEB998A3E2B4E61F3F35582AA01DCC4DE8DEC75D7AAB85B567B6CCD41AD312451B948A7413F0A142FD40D4934783800000808080C0C0";

        byte[] blockHashB = HashUtil.sha3(Hex.decode(blockRaw));
        String blockHash = Hex.toHexString(blockHashB);
        System.out.println(blockHash);
    }



    @Test  // basic encryption/decryption
    public void test11() throws Throwable {

        byte[] keyBytes = sha3("...".getBytes());
        log.info("key: {}", Hex.toHexString(keyBytes));
        byte[] payload = Hex.decode("22400891000000000000000000000000");

        KeyParameter key = new KeyParameter(keyBytes);
        ParametersWithIV params = new ParametersWithIV(key, new byte[16]);

        AESEngine engine = new AESEngine();
        SICBlockCipher ctrEngine = new SICBlockCipher(engine);

        ctrEngine.init(true, params);

        byte[] cipher = new byte[16];
        ctrEngine.processBlock(payload, 0, cipher, 0);

        log.info("cipher: {}", Hex.toHexString(cipher));


        byte[] output = new byte[cipher.length];
        ctrEngine.init(false, params);
        ctrEngine.processBlock(cipher, 0, output, 0);

        assertEquals(Hex.toHexString(output), Hex.toHexString(payload));
        log.info("original: {}", Hex.toHexString(payload));
    }

    @Test  // big packet encryption
    public void test12() throws Throwable {

        AESEngine engine = new AESEngine();
        SICBlockCipher ctrEngine = new SICBlockCipher(engine);

        byte[] keyBytes = Hex.decode("a4627abc2a3c25315bff732cb22bc128f203912dd2a840f31e66efb27a47d2b1");
        byte[] ivBytes = new byte[16];
        byte[] payload    = Hex.decode("0109efc76519b683d543db9d0991bcde99cc9a3d14b1d0ecb8e9f1f66f31558593d746eaa112891b04ef7126e1dce17c9ac92ebf39e010f0028b8ec699f56f5d0c0d00");
        byte[] cipherText = Hex.decode("f9fab4e9dd9fc3e5d0d0d16da254a2ac24df81c076e3214e2c57da80a46e6ae4752f4b547889fa692b0997d74f36bb7c047100ba71045cb72cfafcc7f9a251762cdf8f");

        KeyParameter key = new KeyParameter(keyBytes);
        ParametersWithIV params = new ParametersWithIV(key, ivBytes);

        ctrEngine.init(true, params);

        byte[] in = payload;
        byte[] out = new byte[in.length];

        int i = 0;

        while(i < in.length){
            ctrEngine.processBlock(in, i, out, i);
            i += engine.getBlockSize();
            if (in.length - i  < engine.getBlockSize())
                break;
        }

        // process left bytes
        if (in.length - i > 0){
            byte[] tmpBlock = new byte[16];
            System.arraycopy(in, i, tmpBlock, 0, in.length - i);
            ctrEngine.processBlock(tmpBlock, 0, tmpBlock, 0);
            System.arraycopy(tmpBlock, 0, out, i, in.length - i);
        }

        log.info("cipher: {}", Hex.toHexString(out));

        assertEquals(Hex.toHexString(cipherText), Hex.toHexString(out));
    }

}
