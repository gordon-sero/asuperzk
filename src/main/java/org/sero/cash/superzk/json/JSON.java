package org.sero.cash.superzk.json;

import org.sero.cash.superzk.crypto.ecc.Point;
import org.sero.cash.superzk.protocol.AccountType;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.module.SimpleModule;

public class JSON {

    private static ObjectMapper mapper;

    static {
        mapper = new ObjectMapper();
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        mapper.disable(SerializationFeature.FAIL_ON_EMPTY_BEANS);
        SimpleModule module = new SimpleModule();
        mapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
        module.addSerializer(byte[].class, new BytesSerializer());
        module.addSerializer(HexType.class, new HexTypeSerializer());

        module.addDeserializer(byte[].class, new BytesDeserializer());
        module.addDeserializer(AccountType.PKr.class, new PKrDeserializer());
        module.addDeserializer(AccountType.SK.class, new SKDeserializer());
        module.addDeserializer(Point.class, new PointDeserializer());
        
        mapper.registerModule(module);
    }

    public static <T> String toJson(T t) throws JsonProcessingException {
        return mapper.writeValueAsString(t);
    }

    public static <T> T fromJson(String json, Class<T> clazz) throws JsonProcessingException {
        return mapper.readValue(json, clazz);
    }

    public static <T> T fromJson(String json, Class<?> listType, Class<?> beanType) throws JsonProcessingException {
        JavaType clazz = mapper.getTypeFactory().constructParametricType(listType, beanType);
        return mapper.readValue(json, clazz);
    }

}
