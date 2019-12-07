package org.sero.cash.superzk.json;

import java.io.IOException;

import org.sero.cash.superzk.protocol.AccountType;
import org.sero.cash.superzk.protocol.Param;
import org.sero.cash.superzk.protocol.superzk.Account;
import org.sero.cash.superzk.util.HexUtils;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;

public class PKrDeserializer extends JsonDeserializer<AccountType.PKr> {
    @Override
    public AccountType.PKr deserialize(JsonParser p, DeserializationContext ctxt) throws IOException, JsonProcessingException {
        byte[] data = HexUtils.toBytes(p.getValueAsString());
        if (Param.isFlagSet(data)) {
            return new Account.PKr(data);
        } else {
            return new org.sero.cash.superzk.protocol.czero.Account.PKr(data);
        }
    }
}
