package org.sero.cash.superzk.util;

import java.math.BigInteger;
import java.util.List;
import java.util.Random;

public class Arrays {

	public static void println(int[] data) {
		StringBuilder b = new StringBuilder();
		b.append('[');
		for (int i = 0; i < data.length; i++) {
			byte[] bytes = intToBytes(data[i]);
			b.append(HexUtils.toHex(bytes));
			if (i == data.length) {
				b.append(']').toString();
			} else {
				b.append(", ");
			}
		}
		System.out.println(b.toString());
	}

	public static byte[] intToBytes(int val) {
		byte[] ret = new byte[4];
		ret[3] = (byte) val;
		val >>>= 8;
		ret[2] = (byte) val;
		val >>>= 8;
		ret[1] = (byte) val;
		val >>>= 8;
		ret[0] = (byte) val;
		return ret;
	}

	public static void println(byte[] data) {

		StringBuilder b = new StringBuilder();
		b.append('[');
		for (int i = 0; i < data.length; i++) {
			int v = data[i] & 0xFF;
			b.append(Integer.toHexString(v));
			if (i == data.length) {
				b.append(']').toString();
			} else {
				b.append(", ");
			}
		}
		System.out.println(b.toString());
	}

	public static byte[] intToByteLE(int num) {
		byte[] bytes = new byte[32];
		bytes[0] = (byte) (num & 0xff);
		bytes[1] = (byte) ((num >> 8) & 0xff);
		bytes[2] = (byte) ((num >> 16) & 0xff);
		bytes[3] = (byte) ((num >> 24) & 0xff);
		return bytes;
	}

	public static byte[] intToByteBE(int num) {
		byte[] bytes = new byte[32];
		bytes[0] = (byte) ((num >> 24) & 0xff);
		bytes[1] = (byte) ((num >> 16) & 0xff);
		bytes[2] = (byte) ((num >> 8) & 0xff);
		bytes[3] = (byte) (num & 0xff);
		return bytes;
	}

	public static BigInteger toBigInteger(byte[] data) {
		return new BigInteger(data);
	}

	public static boolean equals(byte[] b1, byte[] b2) {
		return java.util.Arrays.equals(b1, b2);
	}

	public static byte[] stringToByte32(String str) {
		return Arrays.leftPadBytes(str.getBytes(), 32);
	}

	public static String byte32ToString(byte[] bytes) {
		assert bytes.length == 32;
		return new String(bytes).trim();
	}

	public static byte[] randomBytes(int size) {
		byte[] b = new byte[size];
		new Random().nextBytes(b);
		return b;
	}

	public static byte[] slice(byte[] data, int start, int end) {
		byte[] buf = new byte[end - start];
		System.arraycopy(data, start, buf, 0, buf.length);
		return buf;
	}

	public static byte[] copy(byte[] data) {
		byte[] buf = new byte[data.length];
		System.arraycopy(data, 0, buf, 0, data.length);
		return buf;
	}

	public static byte[] concat(List<byte[]> datas) {
		int len = 0;
		for (int i = 0; i < datas.size(); i++) {
			len += datas.get(i).length;
		}
		byte[] buf = new byte[len];
		int countLength = 0;
		for (int i = 0; i < datas.size(); i++) {
			byte[] data = datas.get(i);
			System.arraycopy(data, 0, buf, countLength, data.length);
			countLength += data.length;
		}
		return buf;
	}

	public static byte[] concat(byte[]... datas) {
		int len = 0;
		for (int i = 0; i < datas.length; i++) {
			len += datas[i].length;
		}
		byte[] buf = new byte[len];
		int countLength = 0;
		for (int i = 0; i < datas.length; i++) {
			byte[] data = datas[i];
			System.arraycopy(data, 0, buf, countLength, data.length);
			countLength += data.length;
		}
		return buf;
	}

	public static byte[] reverse(byte[] data) {
		for (int i = 0; i < data.length / 2; i++) {
			byte temp = data[data.length - i - 1];
			data[data.length - i - 1] = data[i];
			data[i] = temp;
		}
		return data;
	}

	public static String byteToHex(byte b) {
		String hex = Integer.toHexString(b & 0xFF);
		if (hex.length() < 2) {
			hex = "0" + hex;
		}
		return hex;
	}

	public static byte[] leftPadBytes(byte[] data, int len) {
		if (data.length >= len) {
			return data;
		}
		byte[] buf = new byte[len];
		System.arraycopy(data, 0, buf, len - data.length, data.length);
		return buf;
	}

	public static byte[] rightPadBytes(byte[] data, int len) {
		if (data.length == len) {
			return data;
		}
		int length = Math.min(data.length, len);
		byte[] buf = new byte[len];
		System.arraycopy(data, 0, buf, 0, length);
		return buf;
	}
}
