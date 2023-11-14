package com.tiennv.ec;

import java.math.BigInteger;

public class EFp {

    public static final BigInteger TWO = BigInteger.valueOf(2);
    public static final BigInteger THREE = BigInteger.valueOf(3);

    public EFp() {

    }

    public Point inverse(Point p) {
        if (p.isInfinity()) return Point.POINT_INFINITY;
        assert p.isOnCurve() : "invalid point";
        return Point.newPoint(p.getEC(), p.getAffineX(), p.getAffineY().negate());
    }

    /**
     * P + Infinity = P
     *
     * P + (-P) = Infinity
     *
     * If there are two distinct points P(xp,yp) and Q(xq,yq) on the curve such that P is not –Q,
     * then R = (xr,yr), where s = (yp-yq)/(xp-xq) (mod p), xr = s^2-xp-xq (mod p),
     * and yr = -yp + s(xp-xR) (mod p).
     * s = (yp-yq)/(xp-xq) is equivalent to s = (yp-yq)*((xp-xq)^-1).
     *
     * @param p1
     * @param p2
     * @return Point
     */
    public Point add(Point p1, Point p2) {

        if (p1.isInfinity() && p2.isInfinity()) {
            return Point.POINT_INFINITY;
        }

        if (!p1.isInfinity()) {
            assert p1.isOnCurve() : "invalid point";
        }

        if (!p2.isInfinity()) {
            assert p2.isOnCurve() : "invalid point";
        }

        if (p1.isInfinity()) {
            return p2;
        }

        if (p2.isInfinity()) {
            return p1;
        }

        if (p1.equals(this.inverse(p2))) {
            return Point.POINT_INFINITY;
        }

        if (p1.equals(p2)) {
            return doubling(p1);
        }

        BigInteger xr = null;
        BigInteger yr = null;

        Point invOfp2 = this.inverse(p2);
        if (p1 != invOfp2 ) {

            //yp-yq mod p
            BigInteger yp = p1.getAffineY();
            BigInteger yq = p2.getAffineY();
            BigInteger ypq = yp.subtract(yq).mod(p1.getEC().getP());

            //((xp-xq)^-1) mod p
            BigInteger xp = p1.getAffineX();
            BigInteger xq = p2.getAffineX();
            BigInteger xpq = xp.subtract(xq).modInverse(p1.getEC().getP());

            BigInteger s = ypq.multiply(xpq).mod(p1.getEC().getP());

            xr = s.pow(2).subtract(xp).subtract(xq).mod(p1.getEC().getP());
            yr = yp.negate().add(s.multiply(xp.subtract(xr))).mod(p1.getEC().getP());
        }

        return Point.newPoint(p1.getEC(), xr, yr);
    }

    /**
     * If there is a point R = (xr,yr) with yp ≠ 0 of an elliptic curve modulo the prime p,
     * then point Q on the elliptic curve, i.e. Q = 2R has the following coordinates xq = s^2-2xr (mod p)
     * and yq = -yr+s(xr-xq) (mod p) where s = (3xr^2+a)/(2yr) (mod p).
     * s = (3xr^2+a)/(2yr) (mod p) is equivalent to s = (3xr^2+a)*((2yr)^-1) (mod p)
     *
     * If yr = 0, then 2R = O.
     *
     * @param r
     * @return 2r
     */
    public Point doubling(Point r) {

        if (r.isInfinity()) {
            return Point.POINT_INFINITY;
        }

        assert r.isOnCurve() : "The point must be on the elliptic curve.";

        BigInteger yr = r.getAffineY();

        if (yr.compareTo(BigInteger.ZERO) == 0) {
            return Point.POINT_INFINITY;
        }

        BigInteger a = r.getEC().getA();
        BigInteger p = r.getEC().getP();

        BigInteger xr = r.getAffineX();

        BigInteger yrr = THREE.multiply(xr.pow(2)).add(a).mod(p);
        BigInteger xrr = TWO.multiply(yr).modInverse(p);
        BigInteger s = yrr.multiply(xrr).mod(p);

        BigInteger xq = s.pow(2).subtract(TWO.multiply(xr)).mod(p);
        BigInteger yq = yr.negate().add(s.multiply(xr.subtract(xq))).mod(p);

        return Point.newPoint(r.getEC(), xq, yq);
    }
}
