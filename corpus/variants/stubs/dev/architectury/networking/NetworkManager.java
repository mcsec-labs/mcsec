package dev.architectury.networking;

import net.minecraft.network.PacketBuffer;

/**
 * Compile-only stand-in for Architectury's packet receivers.
 */
public final class NetworkManager {

    public enum Side {
        S2C,
        C2S
    }

    public interface NetworkReceiver {

        void receive(PacketBuffer buf, Object context);
    }

    public static void registerReceiver(Side side, Object id, NetworkReceiver receiver) {
        throw new UnsupportedOperationException();
    }
}
