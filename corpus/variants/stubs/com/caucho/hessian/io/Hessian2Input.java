package com.caucho.hessian.io;

import java.io.InputStream;

/**
 * Compile-only stand-in for Hessian's version 2 reader.
 */
public class Hessian2Input {

    public Hessian2Input(InputStream in) {
        throw new UnsupportedOperationException();
    }

    public Object readObject() {
        throw new UnsupportedOperationException();
    }

    public Object readObject(Class<?> expected) {
        throw new UnsupportedOperationException();
    }
}
