package com.tiennv.ec;

public class TCommitment {
    private final String publicKey;
    private final byte[] t;

//    public TCommitment() {}

    public TCommitment(String publicKey, byte[] t) {
        this.publicKey = publicKey;
        this.t = t;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public byte[] getT() {
        return t;
    }
}
