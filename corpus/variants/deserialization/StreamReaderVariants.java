package variants.deserialization;

import com.caucho.hessian.io.Hessian2Input;
import com.caucho.hessian.io.HessianInput;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufInputStream;
import java.beans.XMLDecoder;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;

/**
 * XMLDecoder and Hessian, which read like ObjectInputStream.
 */
public class StreamReaderVariants {

    // EXPECT critical network
    public static Object xmlFromNetwork(ByteBuf buf) {
        return new XMLDecoder(new ByteBufInputStream(buf)).readObject();
    }

    // EXPECT critical
    public static Object xmlFromCopiedBytes(ByteBuf buf) {
        byte[] bytes = new byte[buf.readableBytes()];
        buf.readBytes(bytes);
        XMLDecoder decoder = new XMLDecoder(new ByteArrayInputStream(bytes));
        try {
            return decoder.readObject();
        } finally {
            decoder.close();
        }
    }

    // EXPECT notice localFile
    public static Object xmlFromFile(File file) throws Exception {
        return new XMLDecoder(new FileInputStream(file)).readObject();
    }

    // EXPECT none
    public static Object xmlDecoderParameter(XMLDecoder decoder) {
        return decoder.readObject();
    }

    // EXPECT critical
    public static Object hessianFromNetwork(ByteBuf buf) {
        return new HessianInput(new ByteBufInputStream(buf)).readObject();
    }

    // EXPECT critical
    public static Object hessian2TypedFromNetwork(ByteBuf buf) {
        Hessian2Input in = new Hessian2Input(new ByteBufInputStream(buf));
        return in.readObject(String.class);
    }

    // EXPECT notice localFile
    public static Object hessian2FromFile(File file) throws Exception {
        return new Hessian2Input(new FileInputStream(file)).readObject();
    }

    // EXPECT none
    public static Object hessianParameter(Hessian2Input in) {
        return in.readObject();
    }
}
