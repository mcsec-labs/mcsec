package variants.deserialization;

import com.esotericsoftware.kryo.Kryo;
import com.esotericsoftware.kryo.io.Input;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufInputStream;

/**
 * Kryo, which does not require class registration by default before 5.0. No
 * Kryo version is bundled here, so defaults count as unsafe.
 */
public class KryoVariants {

    private static final Kryo SHARED = new Kryo();

    public static class Message {
    }

    // EXPECT critical
    public static Object defaults(ByteBuf buf) {
        return new Kryo().readClassAndObject(new Input(new ByteBufInputStream(buf)));
    }

    // EXPECT critical
    public static Object registrationOff(ByteBuf buf) {
        Kryo kryo = new Kryo();
        kryo.setRegistrationRequired(false);
        return kryo.readClassAndObject(new Input(new ByteBufInputStream(buf)));
    }

    // EXPECT notice
    public static Message registrationOn(ByteBuf buf) {
        byte[] bytes = new byte[buf.readableBytes()];
        buf.readBytes(bytes);
        Kryo kryo = new Kryo();
        kryo.setRegistrationRequired(true);
        kryo.register(Message.class);
        return kryo.readObject(new Input(bytes), Message.class);
    }

    // EXPECT critical
    public static Object registrationOnThenOff(ByteBuf buf) {
        Kryo kryo = new Kryo();
        kryo.setRegistrationRequired(true);
        kryo.setRegistrationRequired(false);
        return kryo.readClassAndObject(new Input(new ByteBufInputStream(buf)));
    }

    // EXPECT critical
    public static Object registrationFromParameter(ByteBuf buf, boolean required) {
        Kryo kryo = new Kryo();
        kryo.setRegistrationRequired(required);
        return kryo.readClassAndObject(new Input(new ByteBufInputStream(buf)));
    }

    // EXPECT critical
    public static Object registrationFromBranch(ByteBuf buf) {
        boolean required = buf.readableBytes() < 64;
        Kryo kryo = new Kryo();
        kryo.setRegistrationRequired(required);
        return kryo.readClassAndObject(new Input(new ByteBufInputStream(buf)));
    }

    // EXPECT warning
    public static Object sharedInstance(ByteBuf buf) {
        return SHARED.readClassAndObject(new Input(new ByteBufInputStream(buf)));
    }
}
