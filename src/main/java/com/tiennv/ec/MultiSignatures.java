package com.tiennv.ec;

import java.math.BigInteger;

public class MultiSignatures {
    private Point R;
    private BigInteger s;

    public MultiSignatures(Point R, BigInteger s) {
        this.R = R;
        this.s = s;
    }

    public Point getR() {
        return R;
    }

    public void setR(Point r) {
        R = r;
    }

    public BigInteger getS() {
        return s;
    }

    public void setS(BigInteger s) {
        this.s = s;
    }
}
