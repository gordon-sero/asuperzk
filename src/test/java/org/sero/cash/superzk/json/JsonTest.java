package org.sero.cash.superzk.json;

import org.junit.Test;
import org.sero.cash.superzk.crypto.ecc.Point;
import org.spongycastle.util.encoders.Hex;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;

public class JsonTest {

    @Test
    public void test() throws JsonProcessingException {
        User user = new User();
        user.name = "小民";
        user.age = 20;
        user.key = Hex.decode("4325491eae1136dd99fbbcc4c2748fff7ed1ff4f4b3e93ef173e34b33fd30e4a");
        user.point = Point.fromHex("0x12e773062fe4445b1b4fd99a71e6925fddc0be9d4dc1c6ded4eb590c43595d28");
        System.out.println(user.point.toString());
        ObjectMapper mapper = new ObjectMapper();


        SimpleModule module = new SimpleModule();
        module.addDeserializer(byte[].class, new BytesDeserializer());
        module.addSerializer(byte[].class, new BytesSerializer());
        module.addSerializer(HexType.class, new HexTypeSerializer());
        module.addDeserializer(Point.class, new PointDeserializer());

        mapper.registerModule(module);
        String json = mapper.writeValueAsString(user);
        System.out.println(json);

        User obj = mapper.readValue(json, User.class);
        System.out.println(obj);
    }

}
