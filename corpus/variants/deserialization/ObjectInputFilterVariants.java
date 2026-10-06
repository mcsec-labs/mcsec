// REQUIRES java 9
package variants.deserialization;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufInputStream;
import java.io.ObjectInputFilter;
import java.io.ObjectInputStream;

/**
 * ObjectInputFilter, which only exists from Java 9 on.
 */
public class ObjectInputFilterVariants {

    // EXPECT notice setting
    public static Object filtered(ByteBuf buf) throws Exception {
        ObjectInputStream in = new ObjectInputStream(new ByteBufInputStream(buf));
        in.setObjectInputFilter(ObjectInputFilter.Config.createFilter("java.util.HashMap;!*"));
        return in.readObject();
    }

    // EXPECT critical
    public static Object filterOnAnotherStream(ByteBuf buf, ObjectInputStream other) throws Exception {
        ObjectInputStream in = new ObjectInputStream(new ByteBufInputStream(buf));
        other.setObjectInputFilter(ObjectInputFilter.Config.createFilter("!*"));
        return in.readObject();
    }
}
