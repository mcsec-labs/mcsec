package net.fabricmc.fabric.api.networking.v1;

import net.minecraft.network.PacketBuffer;

/**
 * Compile-only stand-in for Fabric's receivers of packets from players.
 */
public final class ServerPlayNetworking {

    public interface PlayChannelHandler {

        void receive(Object server, Object player, Object handler, PacketBuffer buf, Object sender);
    }

    public static boolean registerGlobalReceiver(Object channel, PlayChannelHandler handler) {
        throw new UnsupportedOperationException();
    }
}
