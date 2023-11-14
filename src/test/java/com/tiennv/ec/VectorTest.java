package com.tiennv.ec;

import org.junit.Test;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class VectorTest {

    @Test
    public void oneSecretKey() {
        BigInteger key = new BigInteger("0000000000000000000000000000000000000000000000000000000000000001", 16);
        PrivateKey privateKey = new PrivateKey(key);
        PublicKey publicKey = privateKey.getPublicKey();
        System.out.println(publicKey.getPublicKey());
        assertEquals("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", publicKey.getPublicKey());

        String m = "0000000000000000000000000000000000000000000000000000000000000000";


    }

    @Test
    public void oneSigner() {

        BigInteger key = new BigInteger("0000000000000000000000000000000000000000000000000000000000000001", 16);
        PrivateKey privateKey = new PrivateKey(key) ;//Secp256k1.generateKeyPair(256);

        final MuSig cosigner = new MuSig(privateKey);

        // X2,...,Xn be the public keys of other cosigners
        List<String> pubKeys = new ArrayList<>();
        pubKeys.add(privateKey.getPublicKey().getPublicKey());

        PublicKey pointX = cosigner.computeAggPubKeys();

        // t commitment
        TCommitment tCommitment = cosigner.sendTComm();


        // R commitment
        RCommitment rCommitment = cosigner.sendRComm();


        PublicKey aggR = cosigner.computeAggR();

        // a 64-char string
        String m = "0000000000000000000000000000000000000000000000000000000000000000";

        cosigner.sign(m);

        Signing signing = cosigner.sendSig();

        MultiSignatures signatures = cosigner.multisign();
        System.out.println(cosigner.verify());

        m = "787A848E71043D280C50470E8E1532B2DD5D20EE912A45DBDD2BD1DFBF187EF67031A98831859DC34DFFEEDDA86831842CCD0079E1F92AF177F7F22CC1DCED05";

        System.out.println(m.length());


        int[] a = {1,2,3,4,5,6,7,8,9};
        int[] b = Arrays.copyOfRange(a, 0, 3);
        System.out.println(b[0]);
        System.out.println(b[1]);
        System.out.println(b[2]);
//        System.out.println(b[3]);

        int[] c = Arrays.copyOfRange(a, 8, 9);
//        System.out.println(c[0]);
//        System.out.println(c[1]);
//        System.out.println(c[2]);
//        System.out.println(c[3]);
        System.out.println(c[0]);
    }
}
