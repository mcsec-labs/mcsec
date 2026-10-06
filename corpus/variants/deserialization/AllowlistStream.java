package variants.deserialization;

import java.io.IOException;
import java.io.InputStream;
import java.io.InvalidClassException;
import java.io.ObjectInputStream;
import java.io.ObjectStreamClass;

/** The allowlisting stream pattern EnderCore and BdLib used to fix BleedingPipe. */
public class AllowlistStream extends ObjectInputStream {
    public AllowlistStream(InputStream in) throws IOException {
        super(in);
    }

    // EXPECT none
    @Override
    protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
        if (!desc.getName().equals("java.util.HashMap")) {
            throw new InvalidClassException("disallowed class", desc.getName());
        }
        return super.resolveClass(desc);
    }
}
