package com.caucho.hessian.io;

import java.io.InputStream;

/**
 * Compile-only stand-in for Hessian's version 1 reader.
 */
public class HessianInput {

    public HessianInput(InputStream in) {
        throw new UnsupportedOperationException();
    }

    public Object readObject() {
        throw new UnsupportedOperationException();
    }
}
