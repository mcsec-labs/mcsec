package net.minecraft.network;

import io.netty.buffer.ByteBuf;

/** Compile-only stand-in for Minecraft's packet buffer under its Forge 1.12 name. */
public abstract class PacketBuffer extends ByteBuf {
    public abstract byte[] readByteArray();
}
