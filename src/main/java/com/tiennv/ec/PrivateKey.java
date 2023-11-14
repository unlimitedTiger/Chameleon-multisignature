package com.tiennv.ec;

import java.math.BigInteger;

import static com.tiennv.ec.Secp256k1.G;

public class PrivateKey {

    private BigInteger key;
    private PublicKey publicKey;

    public PrivateKey(BigInteger priv) {
        this.key = priv;
        Point r = G.scalarMultiply(this.key);
        this.publicKey = new PublicKey(r);
    }

    public PrivateKey(BigInteger priv, Point r) {
        this.key = priv;
        this.publicKey = new PublicKey(r);
    }

    public BigInteger getKey() {
        return key;
    }

    public PublicKey getPublicKey() {
        return this.publicKey;
    }

    @Override
    public String toString() {
        return "PrivateKey{" +
                "key=" + key +
                '}';
    }
}
