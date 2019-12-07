package org.sero.cash.superzk.json;

import java.util.StringJoiner;

import org.sero.cash.superzk.crypto.ecc.Point;
import org.sero.cash.superzk.util.HexUtils;

public class User {
    public String name;
    public int age;

    public byte[] key;
    public Point point;


    @Override
    public String toString() {
        return new StringJoiner(", ", User.class.getSimpleName() + "[", "]")
                .add("name='" + name + "'")
                .add("age=" + age)
                .add("key=" + HexUtils.toHex(key))
                .add("point=" + point.toString())
                .toString();
    }
}
