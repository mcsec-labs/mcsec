package variants.deserialization;

import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.security.AnyTypePermission;
import com.thoughtworks.xstream.security.NoTypePermission;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufInputStream;
import java.nio.charset.StandardCharsets;

/**
 * XStream, whose default accepts any type before 1.4.18. No XStream version is
 * bundled here, so defaults count as unsafe.
 */
public class XStreamVariants {

    private static final XStream SHARED = new XStream();

    // EXPECT critical
    public static Object defaults(ByteBuf buf) {
        return new XStream().fromXML(new ByteBufInputStream(buf));
    }

    // EXPECT critical
    public static Object decodedString(ByteBuf buf) {
        byte[] bytes = new byte[buf.readableBytes()];
        buf.readBytes(bytes);
        String xml = new String(bytes, StandardCharsets.UTF_8);
        return new XStream().fromXML(xml);
    }

    // EXPECT notice
    public static Object defaultSecurity(ByteBuf buf) {
        XStream xstream = new XStream();
        XStream.setupDefaultSecurity(xstream);
        return xstream.fromXML(new ByteBufInputStream(buf));
    }

    // EXPECT notice
    public static Object noTypesThenAllowlist(ByteBuf buf) {
        XStream xstream = new XStream();
        xstream.addPermission(NoTypePermission.NONE);
        xstream.allowTypes(new String[]{"variants.deserialization.XStreamVariants"});
        return xstream.fromXML(new ByteBufInputStream(buf));
    }

    // EXPECT critical
    public static Object anyTypeAfterSecurity(ByteBuf buf) {
        XStream xstream = new XStream();
        XStream.setupDefaultSecurity(xstream);
        xstream.addPermission(AnyTypePermission.ANY);
        return xstream.fromXML(new ByteBufInputStream(buf));
    }

    // EXPECT warning
    public static Object fromString(String xml) {
        return new XStream().fromXML(xml);
    }

    // EXPECT warning
    public static Object sharedInstance(ByteBuf buf) {
        return SHARED.fromXML(new ByteBufInputStream(buf));
    }

    // EXPECT none
    public static Object sharedInstanceLocalData(String xml) {
        return SHARED.fromXML(xml);
    }
}
