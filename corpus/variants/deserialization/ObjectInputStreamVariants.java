package variants.deserialization;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufInputStream;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.zip.GZIPInputStream;
import net.minecraft.network.PacketBuffer;

/**
 * Ways of writing ObjectInputStream deserialization, each marked with what
 * MCSec should report. KNOWN-GAP marks the right answer for a case the engine
 * cannot reach yet. The variants test counts those instead of failing on them.
 */
public class ObjectInputStreamVariants implements Serializable {

    private ByteBuf storedBuffer;
    private transient List<Object> cache;

    // EXPECT critical network
    public static Object direct(ByteBuf buf) throws Exception {
        return new ObjectInputStream(new ByteBufInputStream(buf)).readObject();
    }

    // EXPECT critical
    public static Object copiedIntoArray(ByteBuf buf) throws Exception {
        byte[] bytes = new byte[buf.readableBytes()];
        buf.readBytes(bytes);
        return new ObjectInputStream(new ByteArrayInputStream(bytes)).readObject();
    }

    // EXPECT critical
    public static Object copiedWithGetBytes(ByteBuf buf) throws Exception {
        byte[] bytes = new byte[buf.readableBytes()];
        buf.getBytes(buf.readerIndex(), bytes);
        return new ObjectInputStream(new ByteArrayInputStream(bytes)).readObject();
    }

    // EXPECT critical
    public static Object backingArray(ByteBuf buf) throws Exception {
        return new ObjectInputStream(new ByteArrayInputStream(buf.array())).readObject();
    }

    // EXPECT critical
    public static Object copiedTwice(ByteBuf buf) throws Exception {
        byte[] first = new byte[buf.readableBytes()];
        buf.readBytes(first);
        byte[] second = Arrays.copyOf(first, first.length);
        return new ObjectInputStream(new ByteArrayInputStream(second)).readObject();
    }

    // EXPECT critical
    public static Object copiedWithArraycopy(ByteBuf buf) throws Exception {
        byte[] first = new byte[buf.readableBytes()];
        buf.readBytes(first);
        byte[] second = new byte[first.length];
        System.arraycopy(first, 0, second, 0, first.length);
        return new ObjectInputStream(new ByteArrayInputStream(second)).readObject();
    }

    // EXPECT critical
    public static Object copiedByteByByte(ByteBuf buf) throws Exception {
        byte[] bytes = new byte[buf.readableBytes()];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = buf.readByte();
        }
        return new ObjectInputStream(new ByteArrayInputStream(bytes)).readObject();
    }

    // EXPECT critical
    public static Object packetBufferByteArray(PacketBuffer buf) throws Exception {
        return new ObjectInputStream(new ByteArrayInputStream(buf.readByteArray())).readObject();
    }

    // EXPECT critical
    public static Object throughObjectInput(ByteBuf buf) throws Exception {
        ObjectInput in = new ObjectInputStream(new ByteBufInputStream(buf));
        return in.readObject();
    }

    // EXPECT critical
    public static Object tryWithResources(ByteBuf buf) throws Exception {
        try (ObjectInputStream in = new ObjectInputStream(new ByteBufInputStream(buf))) {
            return in.readObject();
        }
    }

    // EXPECT critical
    public static Object wrappedStreams(ByteBuf buf) throws Exception {
        InputStream in = new BufferedInputStream(new GZIPInputStream(new ByteBufInputStream(buf)));
        return new ObjectInputStream(in).readObject();
    }

    // EXPECT critical
    public static Object unshared(ByteBuf buf) throws Exception {
        return new ObjectInputStream(new ByteBufInputStream(buf)).readUnshared();
    }

    // EXPECT critical
    public static Object oneBranchFromNetwork(ByteBuf buf, InputStream fallback, boolean network) throws Exception {
        InputStream in = network ? new ByteBufInputStream(buf) : fallback;
        return new ObjectInputStream(in).readObject();
    }

    // EXPECT critical
    public static List<Object> readsInALoop(ByteBuf buf, int count) throws Exception {
        List<Object> out = new ArrayList<>();
        ObjectInputStream in = new ObjectInputStream(new ByteBufInputStream(buf));
        for (int i = 0; i < count; i++) {
            out.add(in.readObject());
        }
        return out;
    }

    // EXPECT critical
    public static Object readInCatch(ByteBuf buf) throws Exception {
        ObjectInputStream in = new ObjectInputStream(new ByteBufInputStream(buf));
        try {
            return buf.readInt();
        } catch (IndexOutOfBoundsException e) {
            return in.readObject();
        }
    }

    // EXPECT critical network
    public Object fromStoredField() throws Exception {
        return new ObjectInputStream(new ByteBufInputStream(storedBuffer)).readObject();
    }

    // EXPECT critical
    public static Object fromHelperStream(ByteBuf buf) throws Exception {
        return new ObjectInputStream(openStream(buf)).readObject();
    }

    // EXPECT none
    private static InputStream openStream(ByteBuf buf) {
        return new ByteBufInputStream(buf);
    }

    // EXPECT notice localFile
    public static Object fromFile(File file) throws Exception {
        try (ObjectInputStream in = new ObjectInputStream(new FileInputStream(file))) {
            return in.readObject();
        }
    }

    // EXPECT notice caller
    public static Object fromAnyStream(InputStream in) throws Exception {
        return new ObjectInputStream(in).readObject();
    }

    // EXPECT notice caller
    public static Object networkPresentButNotUsed(ByteBuf buf, InputStream other) throws Exception {
        int size = buf.readInt();
        return size > 0 ? new ObjectInputStream(other).readObject() : null;
    }

    // EXPECT notice allowlist
    public static Object allowlistedSubclass(ByteBuf buf) throws Exception {
        return new AllowlistStream(new ByteBufInputStream(buf)).readObject();
    }

    // EXPECT none
    private void readObject(ObjectInputStream in) throws Exception {
        in.defaultReadObject();
        cache = new ArrayList<>();
    }

    // EXPECT none
    public static Object receivedStream(ObjectInputStream in) throws Exception {
        return in.readObject();
    }

    // EXPECT none
    public static void createdButNeverRead(ByteBuf buf) throws Exception {
        new ObjectInputStream(new ByteBufInputStream(buf)).close();
    }

    // EXPECT none
    public static byte[] writingIsSafe(Object value) throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ObjectOutputStream out = new ObjectOutputStream(bytes)) {
            out.writeObject(value);
        }
        return bytes.toByteArray();
    }

    // EXPECT none
    public static int plainDataStream(ByteBuf buf) throws Exception {
        return new DataInputStream(new ByteBufInputStream(buf)).readInt();
    }
}
