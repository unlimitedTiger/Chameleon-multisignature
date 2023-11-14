package com.tiennv.ec;

public class RCommitment {
    private final String pub;
    private final String pR;


    public RCommitment(String publicKey, String pR) {
        this.pub = publicKey;
        this.pR = pR;
    }

    public String getPub() {
        return pub;
    }

    public String getR() {
        return pR;
    }
}
