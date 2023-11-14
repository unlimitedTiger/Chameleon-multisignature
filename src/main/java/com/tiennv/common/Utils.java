/*
 * Copyright 2011 Google Inc.
 * Copyright 2014 Andreas Schildbach
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.tiennv.common;

import com.google.common.io.BaseEncoding;

/**
 * A collection of various utility methods that are helpful for working with the Bitcoin protocol.
 * To enable debug logging from the library, run with -Dbitcoinj.logging=true on your command line.
 */
public class Utils {

    /** Joiner for concatenating words with a space inbetween. */
//    public static final Joiner SPACE_JOINER = Joiner.on(" ");
    /** Splitter for splitting words on whitespaces. */
//    public static final Splitter WHITESPACE_SPLITTER = Splitter.on(Pattern.compile("\\s+"));
    /** Hex encoding used throughout the framework. Use with HEX.encode(byte[]) or HEX.decode(CharSequence). */
    public static final BaseEncoding HEX = BaseEncoding.base16().lowerCase();

    /**
     * Returns a copy of the given byte array in reverse order.
     */
    public static byte[] reverseBytes(byte[] bytes) {
        // We could use the XOR trick here but it's easier to understand if we don't. If we find this is really a
        // performance issue the matter can be revisited.
        byte[] buf = new byte[bytes.length];
        for (int i = 0; i < bytes.length; i++)
            buf[i] = bytes[bytes.length - 1 - i];
        return buf;
    }
}