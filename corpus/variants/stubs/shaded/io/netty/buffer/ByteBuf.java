package shaded.io.netty.buffer;

/**
 * Compile-only stand-in for a copy of Netty's ByteBuf that shading moved under
 * another package.
 */
public abstract class ByteBuf {

    public abstract int readableBytes();

    public abstract ByteBuf readBytes(byte[] destination);
}
