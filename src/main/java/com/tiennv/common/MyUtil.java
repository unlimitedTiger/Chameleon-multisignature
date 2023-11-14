package com.tiennv.common;

import com.google.common.io.BaseEncoding;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

public final class MyUtil {


    /**
     * INPUT: A positive integer k.
     * OUTPUT: NAF(k).
     *        i←0.
     *        While k≥1 do
     *              If k is odd then: ki ←2−(k mod 4), k←k−ki;
     *              Else: ki ←0.
     *              k←k/2, i←i+1.
     * Return(ki−1, ki−2,..., k1, k0).
     *
     * Example:
     * 7  -> 0100-1
     * 14 -> 100-10
     *
     * @param k
     */
    public static List<BigInteger> NAF(BigInteger k) {
        List<BigInteger> naf = new ArrayList<>();

        int i = 0;
        BigInteger ki;
        while (k.compareTo(BigInteger.ZERO) == 1) {
            if (k.mod(BigInteger.valueOf(2)).compareTo(BigInteger.ONE) == 0) {
                ki = BigInteger.valueOf(2).subtract(k.mod(BigInteger.valueOf(4)));
                k = k.subtract(ki);
            } else {
                ki = BigInteger.ZERO;
            }
            naf.add(ki);

            k = k.divide(BigInteger.valueOf(2));
            i = i + 1;


        }
//        System.out.println(naf);

        return naf;
    }

    public static BigInteger generateKey(int numBits) {
        SecureRandom random = new SecureRandom();
        BigInteger k = new BigInteger(numBits, random);
        return k;
    }

    public static byte[] concat(final byte[] a, final byte[] b) {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try {
            outputStream.write(a);
            outputStream.write(b);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return outputStream.toByteArray();
    }

    // Utility function to do modular exponentiation.
// It returns (x^y) % p.
    static BigInteger power(BigInteger x, BigInteger y, BigInteger p)
    {
        BigInteger res = BigInteger.ONE; // Initialize result
        x = x.mod(p); // Update x if it is more than or
        // equal to p

        while (y.compareTo(BigInteger.ZERO) > 0) {
            // If y is odd, multiply x with result
            if (y.and(BigInteger.ONE).equals(BigInteger.ONE)) {
                res = res.multiply(x).mod(p);
            }

            // y must be even now
            y = y.shiftRight(1); // y = y/2
            x = x.multiply(x).mod(p);
        }
        return res;
    }

    // Returns true if square root of n under modulo p exists
// Assumption: p is of the form 3*i + 4 where i >= 1
    public static BigInteger squareRoot(BigInteger n, BigInteger p)
    {
        if (!p.mod(BigInteger.valueOf(4)).equals(BigInteger.valueOf(3))) {
            System.out.print("Invalid Input");
            return BigInteger.ZERO;
        }

        // Try "+(n^((p + 1)/4))"
        n = n.mod(p);
//        BigInteger x = power(n, (p.add(BigInteger.ONE)).divide(BigInteger.valueOf(4)), p);
        BigInteger x = n.modPow(p.add(BigInteger.ONE).divide(BigInteger.valueOf(4)), p);

        if (x.multiply(x).mod(p).equals(n)) {
//            System.out.println("Square root is " + x);
//            System.out.println("Square root is " + x.signum());
//            System.out.println("Square root is " + x.abs());

            return x;
        }

        // Try "-(n ^ ((p + 1)/4))"
        /*x = p.subtract(x);
        if (x.multiply(x).mod(p).equals(n)) {
            System.out.println("Square root is11 " + x);
            System.out.println("Square root is11 " + x.signum());
            return x;
        }*/

        // If none of the above two work, then
        // square root doesn't exist
        System.out.print("Square root doesn't exist ");
        return BigInteger.ZERO;
    }

    public static String toHex(byte[] input) {
        return BaseEncoding.base16().encode(input);
    }
}
