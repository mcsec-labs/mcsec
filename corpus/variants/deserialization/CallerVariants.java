package variants.deserialization;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufInputStream;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Deserialization in helper methods. A helper that deserializes whatever it is
 * passed is a Notice on its own, and each caller that passes it network data,
 * directly or through other helpers, is Critical.
 */
public class CallerVariants {

    // EXPECT notice caller
    static Object readBytes(byte[] data) throws Exception {
        return new ObjectInputStream(new ByteArrayInputStream(data)).readObject();
    }

    // EXPECT notice caller
    static Object readStream(InputStream in) throws Exception {
        return new ObjectInputStream(in).readObject();
    }

    // EXPECT none
    static Object forward(byte[] data) throws Exception {
        return readBytes(data);
    }

    // EXPECT notice caller
    static Object readNested(byte[] data, int depth) throws Exception {
        if (depth > 0) {
            return readNested(data, depth - 1);
        }
        return new ObjectInputStream(new ByteArrayInputStream(data)).readObject();
    }

    // EXPECT notice allowlist
    static Object readAllowlisted(byte[] data) throws Exception {
        return new ResolveClassVariants.SetAllowlistStream(new ByteArrayInputStream(data)).readObject();
    }

    // EXPECT notice caller
    Object decode(byte[] data) throws Exception {
        return new ObjectInputStream(new ByteArrayInputStream(data)).readObject();
    }

    private static byte[] bytes(ByteBuf buf) {
        byte[] data = new byte[buf.readableBytes()];
        buf.readBytes(data);
        return data;
    }

    // EXPECT critical network
    public static Object handleDirect(ByteBuf buf) throws Exception {
        return readBytes(bytes(buf));
    }

    // EXPECT critical network
    public static Object handleStream(ByteBuf buf) throws Exception {
        return readStream(new ByteBufInputStream(buf));
    }

    // EXPECT critical network
    public static Object handleThroughForward(ByteBuf buf) throws Exception {
        return forward(bytes(buf));
    }

    // EXPECT critical network
    public static Object handleRecursive(ByteBuf buf) throws Exception {
        return readNested(bytes(buf), 3);
    }

    // EXPECT critical network
    public Object handleInstance(ByteBuf buf) throws Exception {
        return decode(bytes(buf));
    }

    // EXPECT none
    public static Object handleAllowlisted(ByteBuf buf) throws Exception {
        return readAllowlisted(bytes(buf));
    }

    // EXPECT none
    public static Object handleLocalFile(Path path) throws Exception {
        return readBytes(Files.readAllBytes(path));
    }
}
