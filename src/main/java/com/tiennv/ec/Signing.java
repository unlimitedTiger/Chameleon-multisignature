package com.tiennv.ec;

import java.math.BigInteger;

public class Signing {
    private String publicKey;
    private BigInteger s;

    public Signing(String publicKey, BigInteger s) {
        this.publicKey = publicKey;
        this.s = s;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    public BigInteger getS() {
        return s;
    }

    public void setS(BigInteger s) {
        this.s = s;
    }
}
