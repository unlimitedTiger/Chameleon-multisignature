package com.tiennv.ec;

import com.tiennv.common.MyUtil;

import java.math.BigInteger;
import java.util.List;

public class NAF extends EFp implements Computation {

    /**
     * INPUT: Positive integer k, P ∈ E(Fq).
     * OUTPUT: k ⋅ P.
     *        Based on previous algorithm compute NAF(k) =∑(l−1)(i=0)ki⋅2i.
     *        Q←∞.
     *        For i from l−1 down to 0 do
     *              Q←2Q.
     *              If ki  = 1 then Q←Q+P.
     *              If ki  = −1 thenQ←Q−P.
     * Return(Q).
     *
     * @param k
     * @param r
     */
    @Override
    public Point scalarMultiply(BigInteger k, Point r) {
        List<BigInteger> naf = MyUtil.NAF(k);
        int size = naf.size();
//        System.out.println(size);
        if (size == 0) {
            return Point.POINT_INFINITY;
        }
        Point q = Point.POINT_INFINITY;
        for (int i = size -1; i >= 0; i--) {
            q = doubling(q);
            if (naf.get(i).equals(BigInteger.ONE)) {
                q = add(q, r);
            }

            if (naf.get(i).equals(BigInteger.valueOf(-1))) {
                q = add(q, inverse(r));
            }
        }

        return q;
    }
}
