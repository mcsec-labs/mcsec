package shaded.org.apache.commons.lang3;

/**
 * Compile-only stand-in for a copy of Commons Lang 3's SerializationUtils that
 * shading moved under another package.
 */
public class SerializationUtils {

    public static <T> T deserialize(byte[] data) {
        throw new UnsupportedOperationException();
    }
}
