package net.minecraftforge.fml.common.network.simpleimpl;

/**
 * Compile-only stand-in for Forge 1.12's message handler.
 */
public interface IMessageHandler<REQ extends IMessage, REPLY extends IMessage> {

    REPLY onMessage(REQ message, Object context);
}
