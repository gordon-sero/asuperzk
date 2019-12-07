package org.sero.cash.superzk.protocol;

import java.util.List;

import org.junit.Test;
import org.sero.cash.superzk.json.JSON;
import org.sero.cash.superzk.util.Base58;

import com.fasterxml.jackson.core.JsonProcessingException;

public class TestUtxo {

    @Test
    public void test() throws JsonProcessingException {
        AccountType.TK tk = AccountType.TK.fromBytes(Base58.decode("3yPQPVVevSbz9Wh7WJS8WMWH7k6JLmAcV8NAm8ne6D3TcoJJX2NuPioC8idjXN9kGknDLsm1oPJu2TvzPZVueJEc"));
        String outz_json = "[{\"Root\":\"0xacbda0da8ea2e076cea98cadcfcea9b9ef30d71e9e71e23447c4660b21a701af\",\"State\":{\"Num\":27,\"OS\":{\"Index\":27,\"OutCM\":null,\"Out_C\":null,\"Out_O\":null,\"Out_P\":null,\"Out_Z\":{\"AssetCM\":\"0x65a120c5752d13d95c54ca5d6b5c9bd1e8364592db9bbe6c356bf031fb134e1d\",\"EInfo\":\"0x9ceb6ab7032924fa400fd7d4632001c43be58c0e15bd1cc4ea5542236ff5c1754d881670ed49038bfb1104456c94a9a9789ddfc84155328130dad573f740e7c7349db73fc54fd58a644d12d7d10604bda612329f5a7de6dca23b0cbd6d1f8d3bcaea7963abeb2553ddafc9ae1cf2603dc1e5ff68d54495e3b34fb85e7f77125c4353f3bacabd11bcd15f8728cdc79ac1b8b2208f5d9e4089075994d16b4707ef86e53646e5a483c811b688288f9d75902f3fc1abcb3f5da156120016fabbc9fd972004b5911af6502546f66f705563884c05276d2505366dfbfbc76c2f60b731\",\"OutCM\":\"0xcf562e05593fe13dd854898e965c1c48e1771c37d47d4c05450478202b9a9229\",\"PKr\":\"0x4eb56b6631d024cc17552dbcb0fc6e77712535c45d11ab3a77d21b8265a8650de9d5949aeebfed9d95312a6dd836a0af63ad3e933346e2fd4457a62d6611caa1abfb16aaceca9f0294098c3da5c1ad98e4547dbb231f3fb35ea2612304346a26\",\"Proof\":\"0x0275bbb58f987e83c7a79011c14ec912a2182be5fb2e9ccde68e3bf89ac958d51a0bc59fb7027af5fc3910c8f0cf73072d6cdc07c57cbe16a02660d242e25ec8236bb432e3c49dfea53806455cc4d1e1746ed375ce4cdf7cf4e12fb45ee8059cc90702e9defdfe4503d26635ee721a56b03f3007ec75d58ba5001b0e930abc8fa9701a\",\"RPK\":\"0x656bb81ae23744ac1a116199f04e6b75c682091ed9420486dec2ed878e3ef649\"},\"RootCM\":\"0x94a071e50910d17edd71a23ca25abcf7e47469bb5db91819d8e4723063482d1f\"},\"TxHash\":\"0x9241485f953363d7a6a0a063d56865fde2b0e02c0d1fdb45b8a64abdf0c0335a\"}}]";


        List<Types.Out> outs = JSON.fromJson(outz_json, List.class, Types.Out.class);
 
        List<Utxo> utxos = Utxo.decOut(tk, outs);

        System.out.println(JSON.toJson(utxos));
        
        String outc_jsonString="[{\"Root\":\"0x6c5ca090a586fbb12af23ad12f1212da37a79565cb55a52f74cd42ab3876ac1b\",\"State\":{\"Num\":182,\"OS\":{\"Index\":0,\"OutCM\":null,\"Out_C\":{\"AssetCM\":\"0xf389ea41ebafb6c5ad370275ec8f00209ac2e509f02e11176709ecddc8e4ff2c\",\"EInfo\":\"0x733fe279dd318510c252c61fefe4b591888734aa2852664fe3235496b1b7fadae83f7f8723c02ad6e35b8415f4da4f2738c5a786574be90809265571e094adf4119a195c50d0f40c7d6e945f4ceb2e0ddab36bdeca95ebd9d7260b95c3baac345a346749273ada6d0c6f5327a7afd8be938e35212e9336d732b4c5d8b58bccfc11e2dc71597580b677fe784ae31e6f077a75734e19c5e89921fa91a93a0a700feaf2e7f11fa39f66abf01190120e26eeed0273f20acd77eca598da31a27fba09e9ada49042eb40befb4cf8bff9ae658bc16ecb9622653b1aa9e5a0280ab8c446\",\"PKr\":\"0x97d8058100479041468673b832a4b6736c87b5dbc486d6773b982244fbdb63096fc7c35bd537c50abd605e2132810b5026fa77e54c32a66856ea83ec64dfc9ace0b42886335c87981f8e30d84e461eef83ab51d769d58c9a3adfe65e9c9f4bef\",\"Proof\":\"0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\",\"RPK\":\"0x5e43db982614e6d918ac48cb74e178094ef936357c2f9dfb740b4e181478fb09\"},\"Out_O\":null,\"Out_P\":null,\"Out_Z\":null,\"RootCM\":\"0x49e6120fe191a4a142a92d73ccdcbe55c9dfd583d0bf6259122de2608be8010d\"},\"TxHash\":\"0x3923ddd458abd53ee2f1e063bcdc371d435d6f0c772b5fda701d85c475c162e5\"}}]s";
        outs = JSON.fromJson(outc_jsonString, List.class, Types.Out.class);
        utxos = Utxo.decOut(tk, outs);

        System.out.println(JSON.toJson(utxos));
        
    }
}
