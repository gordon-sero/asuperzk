package org.sero.cash.superzk.util;

import java.math.BigInteger;
import java.util.List;

import org.ethereum.util.DecodeResult;
import org.ethereum.util.RLP;
import org.junit.Test;
import org.sero.cash.superzk.json.JSON;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.google.common.collect.Lists;

public class TestRLP {
	
	@Test
	public void test() throws JsonProcessingException {
		List<byte[]> lists = Lists.newArrayList();
		lists.add(new BigInteger("1000000000").toByteArray());
		lists.add(new BigInteger("25000").toByteArray());
		lists.add(new byte[0]);
		
		Object[] list = new Object[3];
		list[0] = new BigInteger("1000000000");
		list[1] = new BigInteger("25000");
		list[2] = new byte[0];
		
		System.out.println(new BigInteger("1000000000").toString(16));
		DecodeResult ret = RLP.decode(HexUtils.toBytes("c9843b9aca008261a880"), 0);
		System.out.println(JSON.toJson(ret));
		byte[] data = RLP.encode(list);
		System.out.println(HexUtils.toHex(data));
		
	}

}
