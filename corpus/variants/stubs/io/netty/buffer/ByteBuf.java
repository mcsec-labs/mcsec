package io.netty.buffer;

/** Compile-only stand-in for Netty's ByteBuf, with the methods the variants use. */
public abstract class ByteBuf {
    public abstract int readableBytes();

    public abstract int readerIndex();

    public abstract int readInt();

    public abstract byte readByte();

    public abstract ByteBuf readBytes(byte[] destination);

    public abstract ByteBuf getBytes(int index, byte[] destination);

    public abstract byte[] array();
}
