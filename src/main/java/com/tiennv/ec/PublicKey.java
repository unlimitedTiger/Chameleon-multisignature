package com.tiennv.ec;

import com.google.common.io.BaseEncoding;
import com.tiennv.common.Base58;
import com.tiennv.common.MyUtil;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki
 *
 */
public class PublicKey {

    private Point q;
    private BigInteger x, y;
    private byte[] pubKeyBytes;
    private String publicKey;

    public PublicKey(String pubKey) {

        String value = pubKey.substring(2);
        this.x = new BigInteger(value, 16);

        BigInteger right = this.x.modPow(BigInteger.valueOf(3), Secp256k1.p).add(Secp256k1.b).mod(Secp256k1.p);

        this.y = MyUtil.squareRoot(right, Secp256k1.p);

        BigInteger prefix = new BigInteger(pubKey.substring(0,2), 16).and(BigInteger.ONE);
        if (!this.y.and(BigInteger.ONE).equals(prefix)) {
            this.y = this.y.negate().mod(Secp256k1.p);
        }

        this.q = Point.newPoint(Secp256k1.Secp256k1, this.x, this.y);
    }

    public PublicKey(byte[] publicKey) {

        this.x = new BigInteger(Arrays.copyOfRange(publicKey, 1, publicKey.length));
        BigInteger right = this.x.modPow(BigInteger.valueOf(3), Secp256k1.p).add(Secp256k1.b).mod(Secp256k1.p);
        this.y = MyUtil.squareRoot(right, Secp256k1.p);

        BigInteger prefix = new BigInteger(Arrays.copyOfRange(publicKey, 0, 1)).and(BigInteger.ONE);
        if (!this.y.and(BigInteger.ONE).equals(prefix)) {
            this.y = this.y.negate().mod(Secp256k1.p);
        }

        this.q = Point.newPoint(Secp256k1.Secp256k1, this.x, this.y);
    }

    public PublicKey(Point q) {
//        this.x = q.getAffineX();
//        this.y = q.getAffineY();
        this.q = q;

        BigInteger prefix = BigInteger.valueOf(2).add(this.q.getAffineY().and(BigInteger.ONE));

        // a 32-byte hex number
        String hex = String.format("%064X", this.q.getAffineX());

        byte[] xCoor = BaseEncoding.base16().decode(hex);
        this.pubKeyBytes = MyUtil.concat(prefix.toByteArray(), xCoor);
        System.out.println("pubKeyBytes: " + this.pubKeyBytes.length );

        // The public key pk: a 33-byte array
        this.publicKey = String.format("%066X", new BigInteger(this.pubKeyBytes));
    }

    public String getPublicKey() {
        return this.publicKey;
    }

    public Point getPoint() {
        return this.q;
    }

    /**
     * The function bytes(P), where P is a point, returns bytes(0x02 + (y(P) & 1)) || bytes(x(P))
     *
     * This matches the compressed encoding for elliptic curve points used in Bitcoin already,
     * following section 2.3.3 of the SEC 1 standard (http://www.secg.org/sec1-v2.pdf).
     *
     * @return
     */
    public byte[] getBytes() {
        return this.pubKeyBytes;
    }

    public String toBase58() {
        return Base58.encode(getBytes());
    }
}
