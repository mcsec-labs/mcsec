package com.esotericsoftware.kryo;

import com.esotericsoftware.kryo.io.Input;

/**
 * Compile-only stand-in for Kryo.
 */
public class Kryo {

    public Kryo() {
        throw new UnsupportedOperationException();
    }

    public void setRegistrationRequired(boolean required) {
        throw new UnsupportedOperationException();
    }

    public void register(Class<?> type) {
        throw new UnsupportedOperationException();
    }

    public Object readClassAndObject(Input input) {
        throw new UnsupportedOperationException();
    }

    public <T> T readObject(Input input, Class<T> type) {
        throw new UnsupportedOperationException();
    }
}
