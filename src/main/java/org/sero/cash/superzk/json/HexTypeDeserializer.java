package org.sero.cash.superzk.json;

import java.io.IOException;

import org.sero.cash.superzk.crypto.ecc.Point;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;

public class HexTypeDeserializer extends JsonDeserializer<HexType> {

    @Override
    public HexType deserialize(JsonParser p, DeserializationContext ctxt) throws IOException, JsonProcessingException {
        return Point.randomPt();
    }
}
