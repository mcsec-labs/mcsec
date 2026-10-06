package net.minecraftforge.fml.common.network.simpleimpl;

import io.netty.buffer.ByteBuf;

/**
 * Compile-only stand-in for Forge 1.12's message.
 */
public interface IMessage {

    void fromBytes(ByteBuf buf);

    void toBytes(ByteBuf buf);
}
