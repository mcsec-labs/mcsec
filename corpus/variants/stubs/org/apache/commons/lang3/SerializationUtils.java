package org.apache.commons.lang3;

import java.io.InputStream;
import java.io.Serializable;

/**
 * Compile-only stand-in for Commons Lang 3's SerializationUtils.
 */
public class SerializationUtils {

    public static <T> T deserialize(byte[] data) {
        throw new UnsupportedOperationException();
    }

    public static <T> T deserialize(InputStream in) {
        throw new UnsupportedOperationException();
    }

    public static byte[] serialize(Serializable object) {
        throw new UnsupportedOperationException();
    }
}
