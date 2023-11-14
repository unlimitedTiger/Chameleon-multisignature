package com.tiennv.ec;

import com.google.common.io.BaseEncoding;
import com.tiennv.common.MyUtil;

import java.math.BigInteger;
import java.util.Objects;

public final class Point {

    public static final Point POINT_INFINITY = new Point();

    private final BigInteger affineX;
    private final BigInteger affineY;

    private final EllipticCurve ec;

    private final String uncompressed;

    private final EFp eFp = new EFp();

//    private final Point point;

    private Point() {
        this.ec = null;
        this.affineX = null;
        this.affineY = null;
        this.uncompressed = null;
    }

    private Point(EllipticCurve ec, BigInteger affineX, BigInteger affineY) {
        assert ec != null && affineX != null && affineY != null && isOnCurve(ec, affineX, affineY) == true : "invalid parameters";
        this.ec = ec;
        this.affineX = affineX.mod(Secp256k1.p);
        this.affineY = affineY.mod(Secp256k1.p);
        this.uncompressed = "0x04".concat(this.affineX.toString()).concat(this.affineY.toString());
    }

    public static Point newPoint(EllipticCurve ec, BigInteger affineX, BigInteger affineY) {
        return new Point(ec, affineX, affineY);
    }

    public Point add(Point r) {
        return eFp.add(this, r);
    }

    public Point inverse() {
        return eFp.inverse(this);
    }

    public Point scalarMultiply(BigInteger k) {
        Computation computation = new NAF();
        return computation.scalarMultiply(k, this);
    }

    public EllipticCurve getEC() {
        return ec;
    }

    public BigInteger getAffineX() {
        return affineX;
    }

    public BigInteger getAffineY() {
        return affineY;
    }

    /**
     * https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03111/BSI-TR-03111_pdf.pdf?__blob=publicationFile&v=2
     *
     * The uncompressed encoding PU is defined as PU = C k X k Y , where
     * • C = 0x04
     * • X = FE2OS(xP)
     * • Y = FE2OS(yP)
     *
     * @return
     */
    public String getUncompressed() {
        return this.uncompressed;
    }

    public boolean isOnCurve() {
        assert !this.isInfinity() : "The point must be on the elliptic curve";
        return isOnCurve(this.ec, this.affineX, this.affineY);
    }

    private boolean isOnCurve(EllipticCurve ec, BigInteger affineX, BigInteger affineY) {

        BigInteger fx = affineX.mod(ec.getP());
        BigInteger fa = ec.getA().mod(ec.getP());
        BigInteger fb = ec.getB().mod(ec.getP());
        BigInteger right = fx.pow(3).add(fx.multiply(fa)).add(fb).mod(ec.getP());

        BigInteger fy = affineY.mod(ec.getP());
        BigInteger left = fy.modPow(BigInteger.valueOf(2), ec.getP());

        return right.equals(left);
    }

    public boolean isInfinity() {
        return this.affineX == null && this.affineY == null;
    }

    public byte[] toBytes() {
        BigInteger prefix = BigInteger.valueOf(2).add(this.getAffineY().and(BigInteger.ONE));
        // a 32-byte hex number
        String hex = String.format("%064X", this.getAffineX());
        byte[] xCoor = BaseEncoding.base16().decode(hex);
        return MyUtil.concat(prefix.toByteArray(), xCoor);
    }

    public void print() {
        System.out.println(toString());
    }

    @Override
    public String toString() {
        return toString(10);
    }

    public String toString(int radix) {
        if (this.isInfinity()) {
            return "(null, null)";
        }
        return "(" + affineX.toString(radix) + "," + affineY.toString(radix) + ")";
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Point point = (Point) o;
        return Objects.equals(affineX, point.affineX) &&
                Objects.equals(affineY, point.affineY) &&
                Objects.equals(ec, point.ec);
    }

    @Override
    public int hashCode() {
        return Objects.hash(affineX, affineY, ec);
    }
}
