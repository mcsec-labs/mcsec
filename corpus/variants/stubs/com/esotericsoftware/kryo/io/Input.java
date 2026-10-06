package com.esotericsoftware.kryo.io;

import java.io.InputStream;

/**
 * Compile-only stand-in for Kryo's Input.
 */
public class Input {

    public Input(byte[] buffer) {
        throw new UnsupportedOperationException();
    }

    public Input(InputStream in) {
        throw new UnsupportedOperationException();
    }
}
