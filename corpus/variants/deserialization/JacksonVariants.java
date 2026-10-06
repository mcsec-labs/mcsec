package variants.deserialization;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.jsontype.PolymorphicTypeValidator;
import com.fasterxml.jackson.databind.jsontype.impl.LaissezFaireSubTypeValidator;
import io.netty.buffer.ByteBuf;
import java.nio.charset.StandardCharsets;

/**
 * Jackson, which only becomes unsafe once default typing is turned on.
 */
public class JacksonVariants {

    private static final ObjectMapper SHARED = new ObjectMapper();

    /**
     * A validator that only allows the mod's own types.
     */
    public static class OwnTypesOnly extends PolymorphicTypeValidator {

        @Override
        public boolean allows(String className) {
            return className.startsWith("variants.");
        }
    }

    private static byte[] bytes(ByteBuf buf) {
        byte[] bytes = new byte[buf.readableBytes()];
        buf.readBytes(bytes);
        return bytes;
    }

    // EXPECT none
    public static Object defaults(ByteBuf buf) {
        byte[] bytes = new byte[buf.readableBytes()];
        buf.readBytes(bytes);
        return new ObjectMapper().readValue(bytes, Object.class);
    }

    // EXPECT critical
    public static Object defaultTyping(ByteBuf buf) {
        byte[] bytes = new byte[buf.readableBytes()];
        buf.readBytes(bytes);
        ObjectMapper mapper = new ObjectMapper();
        mapper.enableDefaultTyping();
        return mapper.readValue(new String(bytes, StandardCharsets.UTF_8), Object.class);
    }

    // EXPECT critical
    public static Object chainedDefaultTyping(ByteBuf buf) {
        byte[] bytes = new byte[buf.readableBytes()];
        buf.readBytes(bytes);
        return new ObjectMapper().enableDefaultTyping().readValue(bytes, Object.class);
    }

    // EXPECT critical
    public static Object laissezFaire(ByteBuf buf) {
        byte[] bytes = new byte[buf.readableBytes()];
        buf.readBytes(bytes);
        ObjectMapper mapper = new ObjectMapper();
        mapper.activateDefaultTyping(LaissezFaireSubTypeValidator.instance);
        return mapper.readValue(bytes, Object.class);
    }

    // EXPECT none
    public static Object ownValidator(ByteBuf buf) {
        byte[] bytes = new byte[buf.readableBytes()];
        buf.readBytes(bytes);
        ObjectMapper mapper = new ObjectMapper();
        mapper.activateDefaultTyping(new OwnTypesOnly());
        return mapper.readValue(bytes, Object.class);
    }

    // EXPECT warning
    public static Object defaultTypingFromString(String json) {
        ObjectMapper mapper = new ObjectMapper();
        mapper.enableDefaultTyping();
        return mapper.readValue(json, Object.class);
    }

    // EXPECT none
    public static Object sharedInstance(ByteBuf buf) {
        byte[] bytes = new byte[buf.readableBytes()];
        buf.readBytes(bytes);
        return SHARED.readValue(bytes, Object.class);
    }

    // EXPECT critical
    public static Object bytesFromHelper(ByteBuf buf) {
        ObjectMapper mapper = new ObjectMapper();
        mapper.enableDefaultTyping();
        return mapper.readValue(bytes(buf), Object.class);
    }
}
