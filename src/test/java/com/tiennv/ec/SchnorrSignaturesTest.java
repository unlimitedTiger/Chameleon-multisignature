package com.tiennv.ec;

import org.junit.Test;

import java.math.BigInteger;

import static org.junit.Assert.assertTrue;

public class SchnorrSignaturesTest {
    @Test
    public void SchnorrSignatures() {
        SchnorrSignatures signatures = new SchnorrSignatures();

        BigInteger key = new BigInteger("0000000000000000000000000000000000000000000000000000000000000001", 16);
        PrivateKey privateKey = new PrivateKey(key);
        Point pk = privateKey.getPublicKey().getPoint();
        System.out.println("pk: " + pk.toString());

//        PrivateKey privateKey = signatures.generateKeyPair();

        Signature sig = signatures.sign(privateKey, "hello".getBytes());

        boolean expected = signatures.verify(privateKey.getPublicKey().getPoint(), sig, "hello".getBytes());

        assertTrue(expected);
    }
}
