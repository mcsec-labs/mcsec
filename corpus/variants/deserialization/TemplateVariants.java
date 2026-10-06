package variants.deserialization;

import io.netty.buffer.ByteBuf;
import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import java.util.Arrays;
import org.apache.commons.lang3.SerializationUtils;

/**
 * Deserializing a serialized object the mod embeds as a constant, a way to
 * build an object without calling its constructor. The template fixes the
 * classes the stream names unless untrusted data is mixed in.
 */
public class TemplateVariants {

    /**
     * The start of a serialized java.util.Date, with its fields left for code
     * to fill in.
     */
    private static final byte[] DATE_TEMPLATE = {
        (byte) 0xAC, (byte) 0xED, 0x00, 0x05, 0x73, 0x72, 0x00, 0x0E,
        'j', 'a', 'v', 'a', '.', 'u', 't', 'i', 'l', '.', 'D', 'a', 't', 'e'
    };

    /**
     * Constant bytes that are not a serialized object.
     */
    private static final byte[] LOOKUP_TABLE = {1, 2, 3, 4, 5, 6, 7, 8};

    /**
     * A template held by another class.
     */
    static class Templates {

        static final byte[] DATE = {(byte) 0xAC, (byte) 0xED, 0x00, 0x05, 0x73, 0x72};
    }

    // EXPECT notice embeddedTemplate
    public static Object filledTemplate(byte[] value) throws Exception {
        byte[] data = new byte[DATE_TEMPLATE.length + value.length];
        System.arraycopy(DATE_TEMPLATE, 0, data, 0, DATE_TEMPLATE.length);
        System.arraycopy(value, 0, data, DATE_TEMPLATE.length, value.length);
        return new ObjectInputStream(new ByteArrayInputStream(data)).readObject();
    }

    // EXPECT notice embeddedTemplate
    public static Object clonedTemplate(byte value) throws Exception {
        byte[] data = DATE_TEMPLATE.clone();
        data[data.length - 1] = value;
        return new ObjectInputStream(new ByteArrayInputStream(data)).readObject();
    }

    // EXPECT notice embeddedTemplate
    public static Object copiedTemplateFromAnotherClass(long time) {
        byte[] data = Arrays.copyOf(Templates.DATE, Templates.DATE.length + 8);
        for (int i = 0; i < 8; i++) {
            data[Templates.DATE.length + i] = (byte) (time >>> (56 - 8 * i));
        }
        return SerializationUtils.deserialize(data);
    }

    // EXPECT critical network
    public static Object templateWithNetworkData(ByteBuf buf) throws Exception {
        byte[] value = new byte[buf.readableBytes()];
        buf.readBytes(value);
        byte[] data = new byte[DATE_TEMPLATE.length + value.length];
        System.arraycopy(DATE_TEMPLATE, 0, data, 0, DATE_TEMPLATE.length);
        System.arraycopy(value, 0, data, DATE_TEMPLATE.length, value.length);
        return new ObjectInputStream(new ByteArrayInputStream(data)).readObject();
    }

    // EXPECT notice caller
    public static Object otherConstant(byte[] value) throws Exception {
        byte[] data = new byte[LOOKUP_TABLE.length + value.length];
        System.arraycopy(LOOKUP_TABLE, 0, data, 0, LOOKUP_TABLE.length);
        System.arraycopy(value, 0, data, LOOKUP_TABLE.length, value.length);
        return new ObjectInputStream(new ByteArrayInputStream(data)).readObject();
    }
}
