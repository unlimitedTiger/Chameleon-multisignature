package com.tiennv.ec;

public class Signature {

    private final byte[] r;
    private final byte[] s;

    public Signature(byte[] r, byte[] s) {
        this.r = r;
        this.s = s;
    }

    public byte[] getR() {
        return r;
    }

    public byte[] getS() {
        return s;
    }

}
