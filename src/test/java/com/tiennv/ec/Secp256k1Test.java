package com.tiennv.ec;

import org.junit.Test;

import javax.crypto.KeyAgreement;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;

public class Secp256k1Test {

    @Test
    public void PTest() {
        BigInteger p = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
        System.out.println(p.toString(16));

        // p = 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
        BigInteger p4 = new BigInteger("2").pow(4);
        BigInteger p6 = new BigInteger("2").pow(6);
        BigInteger p7 = new BigInteger("2").pow(7);
        BigInteger p8 = p4.pow(2);
        BigInteger p9 = new BigInteger("2").pow(9);
        BigInteger p32 = p8.pow(4);
        BigInteger p256 = p32.pow(8);

        BigInteger px = new BigInteger("2").pow(32);

        BigInteger pc = p256.subtract(p32).subtract(p9).subtract(p8).subtract(p7).subtract(p6).subtract(p4).subtract(BigInteger.ONE);
        System.out.println("pc: " + pc.toString(16));
        System.out.println(pc.compareTo(p));

        BigInteger a = BigInteger.valueOf(0);
        BigInteger b = BigInteger.valueOf(7);
        EllipticCurve curve = new EllipticCurve(pc, a, b);

        // The base point G in compressed form
        BigInteger Gx = new BigInteger("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16);
        BigInteger Gy = new BigInteger("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16);
        System.out.println("Gx: " + Gx.bitLength());

        System.out.println("Gx: " + Gx.toString(10));
        System.out.println("Gx: " + Gx.toString(10).length()*3);

        System.out.println("Gx: " + Gx.toString(16));
        System.out.println("Gx: " + Gx.toString(16).length()*4);

        Point G = Point.newPoint(curve, Gx, Gy);
        System.out.println("G(x, y) is on the curve: " + G.isOnCurve());

        SecureRandom random = new SecureRandom();

        BigInteger k = new BigInteger(160, random);

        System.out.println("secret key: \n" + k.toString(16));
        System.out.println(k.toString());

        Point R = G.scalarMultiply(k);

        System.out.println("spublic key: \n" + R.toString(16));

        System.out.println("R(x, y) is on the curve: " + R.isOnCurve());


        PrivateKey privateKey = Secp256k1.generateKeyPair(256);
//        privateKey.getPrivateKey();
//        privateKey.getPublicKey();
//        privateKey.getPoint();

        System.out.println(privateKey.toString());

        System.out.println(Secp256k1.n.bitLength());
        System.out.println(Secp256k1.n.bitLength()/8);
        System.out.println("octet base 256? " + Secp256k1.n.toString(256).length());
        System.out.println(Secp256k1.n.mod(p).toString(16));

        System.out.println(R.toString());

        System.out.println(R.getUncompressed());
        System.out.println(R.getUncompressed().length());
        System.out.println(R.getAffineX().toString(8).length());
        System.out.println(R.getAffineY().toString(8).length());

        System.out.println(G.getUncompressed());
        System.out.println(G.getUncompressed().length());
//        System.out.println(G.getAffineX().toString().length());
//        System.out.println(G.getAffineY().toString().length());

    }

    @Test
    public void testABC() throws Exception {
        KeyPairGenerator kpg;
        kpg = KeyPairGenerator.getInstance("EC","SunEC");
        ECGenParameterSpec ecsp;

        ecsp = new ECGenParameterSpec("secp256k1");
        kpg.initialize(ecsp);

        KeyPair kpU = kpg.genKeyPair();

        java.security.PrivateKey privKeyU = kpU.getPrivate();
        PublicKey pubKeyU = kpU.getPublic();
        System.out.println("Private key 1: " + privKeyU.getEncoded());
        System.out.println("Private key: " + privKeyU.getEncoded().length);
        System.out.println("User U: " + pubKeyU.toString());

        KeyPair kpV = kpg.genKeyPair();
        java.security.PrivateKey privKeyV = kpV.getPrivate();
        PublicKey pubKeyV = kpV.getPublic();
        System.out.println("Private key " + privKeyV.toString());
        System.out.println("User V: " + pubKeyV.toString());

        KeyAgreement ecdhU = KeyAgreement.getInstance("ECDH");
        ecdhU.init(privKeyU);
        ecdhU.doPhase(pubKeyV,true);

        KeyAgreement ecdhV = KeyAgreement.getInstance("ECDH");
        ecdhV.init(privKeyV);
        ecdhV.doPhase(pubKeyU,true);

        System.out.println("Secret computed by U: 0x" +
                (new BigInteger(1, ecdhU.generateSecret()).toString(16)).toUpperCase());
        System.out.println("Secret computed by V: 0x" +
                (new BigInteger(1, ecdhV.generateSecret()).toString(16)).toUpperCase());


        BigInteger x = new BigInteger("3699dfdf73462601422ed1e1309bb624e04c6b86fcdc51618c0af69f26ec4132", 16);
        System.out.println(x.toString(16).length());
        System.out.println(x.toString().length());
        System.out.println(x.bitCount());


    }
}
