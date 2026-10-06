package variants.deserialization;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufInputStream;
import java.io.Serializable;
import java.nio.file.Files;
import java.nio.file.Path;
import net.minecraft.network.PacketBuffer;
import org.apache.commons.lang3.SerializationUtils;

/**
 * Commons Lang's SerializationUtils, which Minecraft puts on every mod's
 * classpath.
 */
public class SerializationUtilsVariants {

    // EXPECT critical
    public static Object copiedBytes(ByteBuf buf) {
        byte[] bytes = new byte[buf.readableBytes()];
        buf.readBytes(bytes);
        return SerializationUtils.deserialize(bytes);
    }

    // EXPECT critical
    public static Object wrappedStream(ByteBuf buf) {
        return SerializationUtils.deserialize(new ByteBufInputStream(buf));
    }

    // EXPECT critical
    public static Object packetByteArray(PacketBuffer buf) {
        return SerializationUtils.deserialize(buf.readByteArray());
    }

    // EXPECT critical
    public static Object commonsLang2(ByteBuf buf) {
        byte[] bytes = new byte[buf.readableBytes()];
        buf.readBytes(bytes);
        return org.apache.commons.lang.SerializationUtils.deserialize(bytes);
    }

    // EXPECT warning
    public static Object fromFile(Path path) throws Exception {
        return SerializationUtils.deserialize(Files.readAllBytes(path));
    }

    // EXPECT none
    public static byte[] serializeOnly(Serializable value) {
        return SerializationUtils.serialize(value);
    }
}
