package variants.deserialization;

import io.netty.buffer.ByteBuf;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;

/**
 * Paths that look like untrusted data reaching a deserializer but cannot run,
 * each beside a twin that can and must still be reported.
 */
public class PrecisionVariants {

    static byte[] bytes(ByteBuf buf) {
        byte[] data = new byte[buf.readableBytes()];
        buf.readBytes(data);
        return data;
    }

    // EXPECT notice caller
    static Object decode(byte[] data) throws Exception {
        return new ObjectInputStream(new ByteArrayInputStream(data)).readObject();
    }

    /**
     * Looks a value up by key. One subclass treats the key as serialized bytes.
     */
    abstract static class Attribute {

        abstract Object value(Object key) throws Exception;
    }

    static class DeserializingAttribute extends Attribute {

        @Override
        Object value(Object key) throws Exception {
            return decode((byte[]) key);
        }
    }

    static Object lookup(Attribute attribute, Object key) throws Exception {
        return attribute.value(key);
    }

    // A number can never be the byte array the deserializing subclass needs.
    // EXPECT none
    static Object lookupByNumber(Attribute attribute, ByteBuf buf) throws Exception {
        return lookup(attribute, Integer.valueOf(buf.readInt()));
    }

    // EXPECT critical network
    static Object lookupByBytes(Attribute attribute, ByteBuf buf) throws Exception {
        return lookup(attribute, bytes(buf));
    }

    // An array nothing writes holds only zeros, which fail before any class is
    // created.
    // EXPECT none
    static Object zeroFilled(ByteBuf buf) throws Exception {
        byte[] data = new byte[buf.readInt()];
        return new ObjectInputStream(new ByteArrayInputStream(data)).readObject();
    }

    // EXPECT none
    static void zeroFilledInLoop(ByteBuf buf) throws Exception {
        int count = buf.readInt();
        for (int i = 0; i < count; i++) {
            byte[] data = new byte[buf.readInt()];
            new ObjectInputStream(new ByteArrayInputStream(data)).readObject();
        }
    }

    // EXPECT critical network
    static void filledInLoop(ByteBuf buf) throws Exception {
        int count = buf.readInt();
        for (int i = 0; i < count; i++) {
            byte[] data = new byte[buf.readInt()];
            buf.readBytes(data);
            new ObjectInputStream(new ByteArrayInputStream(data)).readObject();
        }
    }

    static InputStream source;

    // The array from the previous pass was filled from a stream the analysis
    // cannot trace, so it is not empty even though a new one was just made.
    // EXPECT warning untraced
    static Object previousPass() throws Exception {
        byte[] previous = null;
        Object last = null;
        for (int i = 0; i < 2; i++) {
            byte[] data = new byte[16];
            if (previous != null) {
                last = new ObjectInputStream(new ByteArrayInputStream(previous)).readObject();
            }
            source.read(data);
            previous = data;
        }
        return last;
    }

    // Packet bytes put into a buffer a call returned stay with that buffer.
    // EXPECT critical network
    static Object throughByteBuffer(ByteBuf buf) throws Exception {
        ByteBuffer buffer = ByteBuffer.allocate(64);
        buffer.put(bytes(buf));
        return new ObjectInputStream(new ByteArrayInputStream(buffer.array())).readObject();
    }

    static void putName(ByteBuffer buffer, String name) {
        buffer.put(name.getBytes());
    }

    static byte[] craft(String name) {
        ByteBuffer buffer = ByteBuffer.allocate(64);
        putName(buffer, name);
        byte[] out = new byte[buffer.remaining()];
        buffer.get(out);
        return out;
    }

    // The bytes craft returns carry the name its caller passes, written into
    // the buffer by a helper.
    // EXPECT notice caller
    static Object fromCrafted(String name) throws Exception {
        return new ObjectInputStream(new ByteArrayInputStream(craft(name))).readObject();
    }

    static final Map<Object, ObjectInputStream> STREAMS = new HashMap<>();

    // The stream is either one a cache returns or one created here over the
    // caller's input, so the method can create it.
    // EXPECT notice caller
    static Object cachedOrCreated(Object key, InputStream in) throws Exception {
        ObjectInputStream stream = STREAMS.get(key);
        if (stream == null) {
            stream = new ObjectInputStream(in);
            STREAMS.put(key, stream);
        }
        return stream.readObject();
    }

    /**
     * Keeps an object as the bytes the mod serialized it into.
     */
    static final class Entry {

        final byte[] bytes;

        Entry(Object value) throws Exception {
            this.bytes = serialize(value);
        }

        static byte[] serialize(Object value) throws Exception {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            ObjectOutputStream stream = new ObjectOutputStream(out);
            stream.writeObject(value);
            stream.close();
            return out.toByteArray();
        }

        // The stored bytes are what serialize wrote from the object, so they
        // only name the object's own classes.
        // EXPECT none
        Object read() throws Exception {
            return decode(bytes);
        }
    }

    static Entry cache(ByteBuf buf) throws Exception {
        return new Entry(bytes(buf));
    }

    /**
     * Keeps the bytes it is handed as they are.
     */
    static final class RawEntry {

        final byte[] bytes;

        RawEntry(byte[] bytes) {
            this.bytes = bytes;
        }

        // EXPECT critical network
        Object read() throws Exception {
            return decode(bytes);
        }
    }

    static RawEntry cacheRaw(ByteBuf buf) {
        return new RawEntry(bytes(buf));
    }
}
