package com.tiennv.ec;

import java.math.BigInteger;
import java.util.Objects;

/**
 * An elliptic curve over a prime field is a set of points (x,y) on the curve defined by
 * the equation y^2 ≡ x^3 + ax + b (mod p), where x, y, a, and b are elements of GF(p) for some prime p ≠ 3.
 * The points (x,y) along with point at infinity O form an Abelian group
 * with point addition operator + if 4a^3+27b^2 ≠ 0.
 */
public final class EllipticCurve {

    private final BigInteger p;
    private final BigInteger a;
    private final BigInteger b;

    // the order of a point P ∈ E as the smallest positive integer n such that [n]P = O
    private BigInteger n;

    private BigInteger numberOfPoints;

    // The trace of Frobenius or simply trace of a curve is the
    // value t satisfying #E(Fq) = q + 1 − t
    private BigInteger t;

    public EllipticCurve(final BigInteger p, final BigInteger a, final BigInteger b) {

        BigInteger delta = BigInteger.valueOf(4).multiply(a.pow(3)).add(BigInteger.valueOf(27).multiply(b.pow(2))).mod(p);
        assert delta.compareTo(BigInteger.ZERO) != 0  : "invalid elliptic curve";

        this.p = p;
        this.a = a;
        this.b = b;
    }

    public BigInteger getP() {
        return this.p;
    }

    public BigInteger getA() {
        return this.a;
    }

    public BigInteger getB() {
        return this.b;
    }

    public void setOrder(BigInteger n) {
        this.n = n;
    }

    public BigInteger getOrder() {
        return this.n;
    }

    public BigInteger getTrace() {
        t = p.add(BigInteger.ONE).subtract(this.numberOfPoints);
        return t;
    }

    public BigInteger getNumberOfPoints() {
        return numberOfPoints;
    }

    public void setNumberOfPoints(BigInteger numberOfPoints) {
        this.numberOfPoints = numberOfPoints;
    }

    @Override
    public String toString() {
        return "EllipticCurve{" +
                "p=" + p +
                ", a=" + a +
                ", b=" + b +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        EllipticCurve that = (EllipticCurve) o;
        return p.equals(that.p) &&
                a.equals(that.a) &&
                b.equals(that.b);
    }

    @Override
    public int hashCode() {
        return Objects.hash(p, a, b);
    }
}
