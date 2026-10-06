package variants.deserialization;

import io.netty.buffer.ByteBuf;
import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;

/**
 * Data parked in a collection that a field holds, then deserialized by a
 * different method, as a packet handler does when it queues work for the next
 * tick. Adding to the collection counts as storing in the field.
 */
public class CollectionFieldVariants {

    static final Queue<byte[]> PENDING = new ConcurrentLinkedQueue<>();
    static final Queue<byte[]> HANDED = new ArrayDeque<>();
    static final Queue<byte[]> SAVED = new ArrayDeque<>();
    static final List<byte[]> FIXED = new ArrayList<>();

    final Map<String, byte[]> received = new HashMap<>();

    static byte[] bytes(ByteBuf buf) {
        byte[] data = new byte[buf.readableBytes()];
        buf.readBytes(data);
        return data;
    }

    static void receive(ByteBuf buf) {
        PENDING.offer(bytes(buf));
    }

    // EXPECT critical network
    static Object drain() throws Exception {
        return new ObjectInputStream(new ByteArrayInputStream(PENDING.poll())).readObject();
    }

    void collect(String key, ByteBuf buf) {
        received.put(key, bytes(buf));
    }

    // EXPECT critical network
    Object lookup(String key) throws Exception {
        return new ObjectInputStream(new ByteArrayInputStream(received.get(key))).readObject();
    }

    static void enqueue(byte[] data) {
        HANDED.add(data);
    }

    static void receiveThroughHelper(ByteBuf buf) {
        enqueue(bytes(buf));
    }

    // EXPECT critical network
    static Object drainHanded() throws Exception {
        return new ObjectInputStream(new ByteArrayInputStream(HANDED.poll())).readObject();
    }

    static void remember(Path path) throws Exception {
        SAVED.add(Files.readAllBytes(path));
    }

    // EXPECT notice localFile
    static Object restore() throws Exception {
        return new ObjectInputStream(new ByteArrayInputStream(SAVED.peek())).readObject();
    }

    static void fill() {
        FIXED.add(new byte[]{1, 2, 3});
    }

    // FIXED only ever holds constants, so it stays free of network and file
    // data. A field the analysis cannot trace is reported as untraced, the
    // same as any other field never given untrusted data.
    // EXPECT warning untraced
    static Object fixed() throws Exception {
        return new ObjectInputStream(new ByteArrayInputStream(FIXED.get(0))).readObject();
    }
}
