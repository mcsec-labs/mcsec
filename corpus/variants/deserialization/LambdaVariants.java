package variants.deserialization;

import io.netty.buffer.ByteBuf;
import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import java.util.function.Function;

/**
 * Network data captured by a lambda or method reference whose body passes it to
 * a deserializer later, as packet handlers do when they hand work to the main
 * thread. The method that creates the lambda is Critical.
 */
public class LambdaVariants {

    interface Task {

        void run() throws Exception;
    }

    static void later(Task task) {
    }

    static byte[] bytes(ByteBuf buf) {
        byte[] data = new byte[buf.readableBytes()];
        buf.readBytes(data);
        return data;
    }

    // EXPECT notice caller
    static Object decode(byte[] data) throws Exception {
        return new ObjectInputStream(new ByteArrayInputStream(data)).readObject();
    }

    Object last;

    void keep(byte[] data) throws Exception {
        last = decode(data);
    }

    // EXPECT critical network
    static void capturedByLambda(ByteBuf buf) {
        byte[] data = bytes(buf);
        later(() -> decode(data));
    }

    // EXPECT critical network
    void capturedWithReceiver(ByteBuf buf) {
        byte[] data = bytes(buf);
        later(() -> keep(data));
    }

    // EXPECT critical network
    static void capturedByNestedLambda(ByteBuf buf) {
        byte[] data = bytes(buf);
        later(() -> later(() -> decode(data)));
    }

    static class Decoder {

        Object last;

        void accept(byte[] data) throws Exception {
            last = decode(data);
        }
    }

    // EXPECT critical network
    static void capturedAfterAnotherValue(ByteBuf buf) {
        Decoder decoder = new Decoder();
        byte[] data = bytes(buf);
        later(() -> decoder.accept(data));
    }

    // EXPECT none
    static void capturedConstant() {
        byte[] data = {1, 2, 3};
        later(() -> decode(data));
    }

    interface Reader {

        Object read(byte[] data) throws Exception;
    }

    static void readWith(Reader reader) {
    }

    interface BoundReader {

        Object read(Sink sink, byte[] data) throws Exception;
    }

    static void readWith(BoundReader reader) {
    }

    /**
     * Keeps the network data it was built from, and decodes whatever it is
     * passed.
     */
    static class Sink {

        final byte[] seen;

        Sink(byte[] seen) {
            this.seen = seen;
        }

        Object accept(byte[] data) throws Exception {
            return decode(data);
        }
    }

    // The reference captures the sink as its receiver. The data accept decodes
    // comes from whoever calls the reader later, not from this method.
    // EXPECT none
    static void boundReference(ByteBuf buf) {
        Sink sink = new Sink(bytes(buf));
        readWith(sink::accept);
    }

    // EXPECT none
    static void unboundReference() {
        readWith(Sink::accept);
    }

    /**
     * A packet decoded through a constructor reference used as its codec.
     */
    static class Message {

        static final Function<ByteBuf, Message> DECODER = Message::new;

        final byte[] data;

        Message(ByteBuf buf) {
            this.data = bytes(buf);
        }

        // EXPECT critical network
        Object open() throws Exception {
            return decode(data);
        }
    }
}
