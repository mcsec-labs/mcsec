package net.neoforged.neoforge.network.registration;

import java.util.function.BiConsumer;

/**
 * Compile-only stand-in for NeoForge's payload registration.
 */
public class PayloadRegistrar {

    public <T> PayloadRegistrar playToServer(Object type, Object codec, BiConsumer<T, Object> handler) {
        throw new UnsupportedOperationException();
    }

    public <T> PayloadRegistrar playToClient(Object type, Object codec, BiConsumer<T, Object> handler) {
        throw new UnsupportedOperationException();
    }
}
