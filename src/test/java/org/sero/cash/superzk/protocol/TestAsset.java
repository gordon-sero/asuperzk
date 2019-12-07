package org.sero.cash.superzk.protocol;

import static org.junit.Assert.assertTrue;

import org.junit.Test;
import org.sero.cash.superzk.crypto.ecc.Field;
import org.sero.cash.superzk.crypto.ecc.Point;
import org.sero.cash.superzk.util.Arrays;
import org.spongycastle.util.encoders.Hex;

public class TestAsset {

    @Test
    public void test() {
        byte[] currency = Arrays.rightPadBytes("SERO".getBytes(), 32);
        byte[] category = Arrays.rightPadBytes("TKT".getBytes(), 32);


        Asset asset = new Asset(
                currency,
                Field.newFR(10000),
                category,
                Hex.decode("884f0a0b9c4a3915b41f91f39e17f033ea0187584d545d1f0d22617e6592276e")
        );

        Point cc = asset.genAssetCC();
        assertTrue(Arrays.equals(cc.toBytes(), Hex.decode("cbd21d757ed94e3670bd5a52b89308ecf7cc8809c55e2ebc757da804c2535f99")));


        Field.FR ar = Field.newFR(Hex.decode("fdf3f9b96185bb286f04be9f24de5332b4163bc45bc1ee45b5cbb42b1731b905"));
        Point cm = asset.genAssetCM(ar);
        assertTrue(Arrays.equals(cm.toBytes(), Hex.decode("16e996af0e9555624baa2996da51e1883d40de6c9ad42e066893a060d9a52e01")));
    }
}
