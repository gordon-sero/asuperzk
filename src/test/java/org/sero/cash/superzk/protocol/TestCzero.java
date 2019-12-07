package org.sero.cash.superzk.protocol;

import static org.junit.Assert.assertTrue;

import org.junit.Test;
import org.sero.cash.superzk.crypto.ecc.Field;
import org.sero.cash.superzk.crypto.ecc.Point;
import org.sero.cash.superzk.protocol.czero.Account;
import org.sero.cash.superzk.protocol.czero.Czero;
import org.sero.cash.superzk.util.Arrays;
import org.sero.cash.superzk.util.HexUtils;

public class TestCzero {

    @Test
    public void test1() {
        Field.FR zsk = Field.newFR("1414125169919633338287334366411409260780824619700845100631209103383744535688");
        Field.FR vsk = Field.newFR("1187950494499907703078976114969703210152712337496432814310892304431337827743");
        AccountType.SK sk =  Account.seed2SK(Arrays.reverse(HexUtils.toBytes("1dae502b898054534f98b10e0e79adcbc7badd21cf9dd13afec6de6a68c27359")));
        assertTrue(sk.vsk.isEqualTo(vsk));
        assertTrue(sk.zsk.isEqualTo(zsk));

        AccountType.TK tk = sk.toTK();
        assertTrue(Arrays.equals(tk.zpk.toBytes(), Arrays.reverse(HexUtils.toBytes("ae07859ee67971e8120676ee315f160172843afccba86a8e5775c51af8963acb"))));


        AccountType.PK pk = tk.toPK();
        System.out.println(pk.vpk.toString());
        assertTrue(Arrays.equals(pk.vpk.toBytes(), Arrays.reverse(HexUtils.toBytes("0574b2a4a441fcc9cce9dc9a656795d3f4da56f69d0f27a605f338c11b032099"))));

        Field.FR r = Field.newFR("1171303403610082973846181280845915821240011476569395132138519856324206051995");

        AccountType.PKr pkr = pk.createPKr(r);

        assertTrue(Arrays.equals(pkr.ZPKr.toBytes(), Arrays.reverse(HexUtils.toBytes("2ec099e0946ea4f04b6b21be274a815f132e56f54f2c9578523db6da9d082a63"))));
        assertTrue(Arrays.equals(pkr.VPKr.toBytes(), Arrays.reverse(HexUtils.toBytes("0db71d23a848bb0fb467f1fa07931094491d1b32061f1f9ff5a2911b79d5d979"))));
        assertTrue(Arrays.equals(pkr.BASEr.toBytes(), Arrays.reverse(HexUtils.toBytes("121cb4164fbfe405ac9293e70bcb1f9f2a5044c64b3fa2140f6a6267c4b43724"))));
    }

    @Test
    public void test2()  {
        byte[] seed = Arrays.randomBytes(32);
        AccountType.SK sk = Account.seed2SK(seed);
        AccountType.TK tk = sk.toTK();
        AccountType.PK pk = tk.toPK();
        AccountType.PKr pkr = pk.createPKr(Field.randomFR());
        Point cm = Point.Blake2b.findPoint(Arrays.randomBytes(16), Arrays.randomBytes(32));
        Point nil = Czero.genNil(sk, cm);

        assertTrue(nil != null);

        byte[] h = Arrays.randomBytes(32);
        byte[] sign = Czero.signNil(h, sk, pkr, cm);
        assertTrue(Czero.verifyNil(h, sign, nil,pkr, cm));

        sign = Czero.signByPKr(sk, h, pkr);
        assertTrue(Czero.verifyByPKr(h, sign, pkr));


    }

    @Test
    public void test3() {
        AccountType.PKr pkr1 = new Account.PKr(Point.fromHex("0x303d861d913788f7f3d6fbc07e898c5f1e9a504a75ea2de5551e7535ff2892a0"),
                Point.fromBytes(Arrays.reverse(HexUtils.toBytes("a253dd1d0404b9250d74397ec195f315cdf54181665bcb39febc151fdd84c6d3"))),
                Point.fromBytes(Arrays.reverse(HexUtils.toBytes("896e98687f815e95c6c86f3c22a838c5b44fc419a18925e83973223a295120d1"))));

        System.out.println("pkr1 " + pkr1.toHex());


        byte[] tkn_currency = Arrays.rightPadBytes("sero".getBytes(), 32);
        byte[] tkt_category = Arrays.rightPadBytes("sero_tkt".getBytes(), 32);


        Asset asset = new Asset(
                tkn_currency,
                Field.newFR(10),
                tkt_category,
                Arrays.reverse(HexUtils.toBytes("5f30493457b08db51db4cc91643886eb5c2ac2360012e37dc5f93e92350f39b0"))
        );

        System.out.println("asset " + asset.toString());


        Field.FR rsk = Field.newFR(Arrays.reverse(HexUtils.toBytes("04a51a03abb7d84ee1e64128afc2f62cb7274ea5a9fa04bf535fd92ad30bd825")));

        byte[] memo = Arrays.reverse(HexUtils.toBytes("f8a1d963eb45c0bedd3afadb959d5d0a59c4bcbf7f27cdf3966b95e0d932937dab43c2667c594ba8bdcb029042471c1ceec3c28380d123d2477423e8c8ae0490"));

        Point rootCm = Czero.genOutCm(asset, memo, rsk, pkr1);
        System.out.println("rootCm " + rootCm.toString());
        assertTrue(rootCm != null);
        assertTrue(Arrays.equals(rootCm.toBytes(), Arrays.reverse(HexUtils.toBytes("a451f74b53fbadd4f6bc4657313523f612c8983cf5b4192066ff6897c782e78b"))));
    }


}
