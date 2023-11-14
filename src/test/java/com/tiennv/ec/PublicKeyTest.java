package com.tiennv.ec;

import com.google.common.io.BaseEncoding;
import org.junit.Test;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;

import static org.junit.Assert.assertEquals;

public class PublicKeyTest {

    @Test
    public void publicKeyTest() {

        // public is a 33-byte value
        for (int i = 0; i < 10; i++) {

            PrivateKey privateKey = Secp256k1.generateKeyPair(256);
            PublicKey publicKey = privateKey.getPublicKey();
            String keyPublicKey = publicKey.getPublicKey();
            System.out.println(keyPublicKey);
            System.out.println(publicKey.getBytes());
            System.out.println(publicKey.toBase58());
        }
    }

    @Test
    public void x2yTest() {

        for (int i = 0; i < 1000; i++) {

            PrivateKey privateKey = Secp256k1.generateKeyPair(256);
            PublicKey publicKey = privateKey.getPublicKey();
            String keyPublicKey = publicKey.getPublicKey();
            Point point = publicKey.getPoint();

            PublicKey publicKey1 = new PublicKey(keyPublicKey);
            Point point1 = publicKey1.getPoint();

            assertEquals(point, point1);
        }
    }

    @Test
    public void hexWithLeadingZerosTest() {
        BigInteger x = new BigInteger("33b79f13ad1844aa9530a530f29df9552099b7f32dd7f3db3a39f02540e0de9cb", 16);
        String hexAddress = String.format("%066x", x);
        System.out.println(hexAddress);
        System.out.println(hexAddress.length());
    }
}