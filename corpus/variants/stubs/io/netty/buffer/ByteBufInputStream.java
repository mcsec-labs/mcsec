package io.netty.buffer;

import java.io.InputStream;

/** Compile-only stand-in for Netty's ByteBufInputStream. */
public class ByteBufInputStream extends InputStream {
    public ByteBufInputStream(ByteBuf buffer) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int read() {
        throw new UnsupportedOperationException();
    }
}
