package org.apache.commons.lang;

/**
 * Compile-only stand-in for Commons Lang 2's SerializationUtils.
 */
public class SerializationUtils {

    public static Object deserialize(byte[] data) {
        throw new UnsupportedOperationException();
    }
}
