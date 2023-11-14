package com.tiennv.ec;

import java.math.BigInteger;

public interface Computation {
//    Point inverse(Point r);
//    Point add(Point p1, Point p2);
//    Point doubling(Point r);
    Point scalarMultiply(BigInteger k, Point r);
}
