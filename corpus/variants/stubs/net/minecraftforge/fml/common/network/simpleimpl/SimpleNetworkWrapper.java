package net.minecraftforge.fml.common.network.simpleimpl;

import net.minecraftforge.fml.relauncher.Side;

/**
 * Compile-only stand-in for Forge 1.12's message channel.
 */
public class SimpleNetworkWrapper {

    public <REQ extends IMessage, REPLY extends IMessage> void registerMessage(
            Class<? extends IMessageHandler<REQ, REPLY>> handler, Class<REQ> message, int discriminator, Side side) {
        throw new UnsupportedOperationException();
    }
}
