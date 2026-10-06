package variants.deserialization;

import io.netty.buffer.ByteBuf;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.Queue;
import java.util.function.Function;

/**
 * A payload decoded by a codec built from a lambda, whose bytes the handler
 * collects across batches and queues, and a tick method later deserializes. The
 * data passes through a constructor, an accessor, a list, and a queue before it
 * reaches the sink.
 */
public class PayloadVariants {

    static byte[] bytes(ByteBuf buf) {
        byte[] data = new byte[buf.readableBytes()];
        buf.readBytes(data);
        return data;
    }

    static final class Payload {

        private final byte[] bytes;
        private final int remaining;

        Payload(byte[] bytes, int remaining) {
            this.bytes = bytes;
            this.remaining = remaining;
        }

        byte[] bytes() {
            return bytes;
        }

        int remaining() {
            return remaining;
        }
    }

    static final Function<ByteBuf, Payload> DECODER = buf -> new Payload(bytes(buf), buf.readInt());

    static final List<byte[]> PARTS = new ArrayList<>();
    static final Queue<byte[]> UPDATES = new ArrayDeque<>();

    static byte[] combine(List<byte[]> parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] part : parts) {
            out.write(part, 0, part.length);
        }
        return out.toByteArray();
    }

    static void receive(Payload payload) {
        PARTS.add(payload.bytes());
        if (payload.remaining() == 0) {
            UPDATES.offer(combine(PARTS));
            PARTS.clear();
        }
    }

    // EXPECT notice caller
    static Object apply(byte[] update) throws Exception {
        return new ObjectInputStream(new ByteArrayInputStream(update)).readObject();
    }

    // EXPECT critical network
    static void tick() throws Exception {
        if (!UPDATES.isEmpty()) {
            apply(UPDATES.poll());
        }
    }

    // The stream hands back what Payload::bytes returns for each payload.
    // EXPECT critical network
    static Object firstThroughStream(List<Payload> payloads) throws Exception {
        byte[] data = payloads.stream().map(Payload::bytes).findFirst().get();
        return new ObjectInputStream(new ByteArrayInputStream(data)).readObject();
    }

    static byte[] header(Payload payload) {
        return new byte[]{1, 2, 3};
    }

    // The function only returns a constant header, so no packet bytes come
    // back. The stream itself still comes from the caller's list.
    // EXPECT notice caller
    static Object headerThroughStream(List<Payload> payloads) throws Exception {
        byte[] data = payloads.stream().map(PayloadVariants::header).findFirst().get();
        return new ObjectInputStream(new ByteArrayInputStream(data)).readObject();
    }
}
