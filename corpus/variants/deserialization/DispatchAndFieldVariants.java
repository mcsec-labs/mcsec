package variants.deserialization;

import io.netty.buffer.ByteBuf;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Network data that reaches a sink through a field another method fills, or
 * through a call that dispatches to an override.
 */
public class DispatchAndFieldVariants {

    static byte[] bytes(ByteBuf buf) {
        byte[] data = new byte[buf.readableBytes()];
        buf.readBytes(data);
        return data;
    }

    /**
     * A packet that keeps the bytes it was sent and decodes them later.
     */
    static class Message {

        private final byte[] data;

        Message(ByteBuf buf) {
            this.data = bytes(buf);
        }

        // EXPECT critical network
        Object getData() throws Exception {
            return new ObjectInputStream(new ByteArrayInputStream(data)).readObject();
        }
    }

    /**
     * Keeps the bytes of a local file.
     */
    static class Cache {

        private byte[] data;

        void load(Path path) throws Exception {
            data = Files.readAllBytes(path);
        }

        // EXPECT notice localFile
        Object restore() throws Exception {
            return new ObjectInputStream(new ByteArrayInputStream(data)).readObject();
        }
    }

    /**
     * Keeps whatever stream it was constructed with.
     */
    static class Wrapper {

        private final InputStream in;

        Wrapper(InputStream in) {
            this.in = in;
        }

        // EXPECT warning untraced
        Object read() throws Exception {
            return new ObjectInputStream(in).readObject();
        }
    }

    abstract static class Packet {

        abstract void read(byte[] data) throws Exception;
    }

    static class SerializedPacket extends Packet {

        Object value;

        // EXPECT notice caller
        @Override
        void read(byte[] data) throws Exception {
            value = new ObjectInputStream(new ByteArrayInputStream(data)).readObject();
        }
    }

    interface Handler {

        Object handle(byte[] data) throws Exception;
    }

    static class SerializedHandler implements Handler {

        // EXPECT notice caller
        @Override
        public Object handle(byte[] data) throws Exception {
            return new ObjectInputStream(new ByteArrayInputStream(data)).readObject();
        }
    }

    // EXPECT critical network
    static Object throughOutputStream(ByteBuf buf) throws Exception {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        out.write(bytes(buf));
        return new ObjectInputStream(new ByteArrayInputStream(out.toByteArray())).readObject();
    }

    // EXPECT notice caller
    static Object copyThroughSerialization(java.io.Serializable value) throws Exception {
        java.io.ByteArrayOutputStream bytes = new java.io.ByteArrayOutputStream();
        java.io.ObjectOutputStream out = new java.io.ObjectOutputStream(bytes);
        out.writeObject(value);
        out.close();
        return new ObjectInputStream(new ByteArrayInputStream(bytes.toByteArray())).readObject();
    }

    // EXPECT critical network
    static Object networkThroughWrapper(ByteBuf buf) throws Exception {
        java.io.ByteArrayOutputStream bytes = new java.io.ByteArrayOutputStream();
        java.io.DataOutputStream out = new java.io.DataOutputStream(bytes);
        out.write(bytes(buf));
        return new ObjectInputStream(new ByteArrayInputStream(bytes.toByteArray())).readObject();
    }

    // EXPECT critical network
    static void dispatchToOverride(Packet packet, ByteBuf buf) throws Exception {
        packet.read(bytes(buf));
    }

    // EXPECT critical network
    static Object dispatchToInterface(Handler handler, ByteBuf buf) throws Exception {
        return handler.handle(bytes(buf));
    }
}
