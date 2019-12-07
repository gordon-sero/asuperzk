package org.sero.cash.superzk.json;

import java.io.IOException;

import org.sero.cash.superzk.util.HexUtils;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;

public class HexTypeSerializer extends JsonSerializer<HexType> {

    @Override
    public void serialize(HexType value, JsonGenerator gen, SerializerProvider serializers) throws IOException {
        gen.writeString(HexUtils.toHex(value.toBytes()));
    }
}
