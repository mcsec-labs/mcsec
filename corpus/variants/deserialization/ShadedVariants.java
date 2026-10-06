package variants.deserialization;

import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import shaded.io.netty.buffer.ByteBuf;
import shaded.org.apache.commons.lang3.SerializationUtils;

/**
 * Libraries that a mod shaded under its own package, which keep their original
 * names after the added prefix.
 */
public class ShadedVariants {

    // EXPECT critical network
    public static Object shadedBuffer(ByteBuf buf) throws Exception {
        byte[] data = new byte[buf.readableBytes()];
        buf.readBytes(data);
        return new ObjectInputStream(new ByteArrayInputStream(data)).readObject();
    }

    // EXPECT critical network
    public static Object shadedSerializationUtils(ByteBuf buf) {
        byte[] data = new byte[buf.readableBytes()];
        buf.readBytes(data);
        return SerializationUtils.deserialize(data);
    }
}
