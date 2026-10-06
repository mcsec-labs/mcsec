package variants.deserialization;

import dev.architectury.networking.NetworkManager;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufInputStream;
import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Function;
import net.fabricmc.fabric.api.client.networking.v1.ClientPlayNetworking;
import net.fabricmc.fabric.api.networking.v1.ServerPlayNetworking;
import net.minecraft.network.PacketBuffer;
import net.minecraftforge.fml.common.network.simpleimpl.IMessage;
import net.minecraftforge.fml.common.network.simpleimpl.IMessageHandler;
import net.minecraftforge.fml.common.network.simpleimpl.SimpleNetworkWrapper;
import net.minecraftforge.fml.relauncher.Side;
import net.neoforged.neoforge.network.registration.PayloadRegistrar;

/**
 * Packet data whose exposure follows from how each loader registers the packet,
 * which decides whether a player or a server can send it.
 */
public class ExposureVariants {

    static byte[] bytes(ByteBuf buf) {
        byte[] data = new byte[buf.readableBytes()];
        buf.readBytes(data);
        return data;
    }

    // EXPECT notice caller
    static Object decode(byte[] data) throws Exception {
        return new ObjectInputStream(new ByteArrayInputStream(data)).readObject();
    }

    /**
     * Forge 1.12 decodes a registered message on both sides.
     */
    static class ConfigMessage implements IMessage {

        Object config;

        // EXPECT critical network anyPlayer
        @Override
        public void fromBytes(ByteBuf buf) {
            try {
                config = decode(bytes(buf));
            } catch (Exception e) {
                config = null;
            }
        }

        @Override
        public void toBytes(ByteBuf buf) {
        }
    }

    static class ConfigHandler implements IMessageHandler<ConfigMessage, IMessage> {

        @Override
        public IMessage onMessage(ConfigMessage message, Object context) {
            return null;
        }
    }

    static void registerForge(SimpleNetworkWrapper channel) {
        channel.registerMessage(ConfigHandler.class, ConfigMessage.class, 0, Side.CLIENT);
    }

    static void registerFabric() {
        ServerPlayNetworking.registerGlobalReceiver("from_player", ExposureVariants::onPlayerPacket);
        ServerPlayNetworking.registerGlobalReceiver("helped", ExposureVariants::onHelpedPacket);
        ClientPlayNetworking.registerGlobalReceiver("from_server", ExposureVariants::onServerPacket);
    }

    // EXPECT critical network anyPlayer
    static Object onPlayerPacket(Object server, Object player, Object handler, PacketBuffer buf, Object sender) {
        try {
            return new ObjectInputStream(new ByteBufInputStream(buf)).readObject();
        } catch (Exception e) {
            return null;
        }
    }

    static void onHelpedPacket(Object server, Object player, Object handler, PacketBuffer buf, Object sender) {
        helper(buf);
    }

    // EXPECT critical network anyPlayer
    static void helper(ByteBuf buf) {
        try {
            decode(bytes(buf));
        } catch (Exception e) {
            return;
        }
    }

    // EXPECT critical network anyServer
    static Object onServerPacket(Object client, Object handler, PacketBuffer buf, Object sender) {
        try {
            return new ObjectInputStream(new ByteBufInputStream(buf)).readObject();
        } catch (Exception e) {
            return null;
        }
    }

    static void registerArchitectury() {
        NetworkManager.registerReceiver(NetworkManager.Side.S2C, "sync", ExposureVariants::onSync);
    }

    // EXPECT critical network anyServer
    static void onSync(PacketBuffer buf, Object context) {
        try {
            decode(buf.readByteArray());
        } catch (Exception e) {
            return;
        }
    }

    /**
     * A NeoForge payload whose codec reads the buffer in the payload class.
     */
    static final class SyncPayload {

        static final Object TYPE = new Object();
        static final Function<PacketBuffer, SyncPayload> STREAM_CODEC = SyncPayload::read;

        final byte[] data;

        SyncPayload(byte[] data) {
            this.data = data;
        }

        static SyncPayload read(PacketBuffer buf) {
            return new SyncPayload(buf.readByteArray());
        }

        // EXPECT critical network anyServer
        Object open() throws Exception {
            return decode(data);
        }
    }

    static void registerNeoForge(PayloadRegistrar registrar) {
        registrar.playToClient(SyncPayload.TYPE, SyncPayload.STREAM_CODEC, (payload, context) -> {
        });
    }

    // EXPECT critical network noExposure
    static Object unregistered(ByteBuf buf) throws Exception {
        return decode(bytes(buf));
    }

    /**
     * A mod's own channel, which the scanner does not recognize, dispatching
     * packets by id to handlers registered with it. Its handlers are reachable,
     * so their exposure is unknown rather than unwired.
     */
    static final class CustomChannel {

        final Map<Integer, Consumer<ByteBuf>> handlers = new HashMap<>();

        void register(int id, Consumer<ByteBuf> handler) {
            handlers.put(id, handler);
        }

        void dispatch(ByteBuf buf) {
            handlers.get(buf.readInt()).accept(buf);
        }
    }

    static void registerCustom(CustomChannel channel) {
        channel.register(1, ExposureVariants::onCustomPacket);
    }

    // EXPECT critical network noExposure
    static void onCustomPacket(ByteBuf buf) {
        try {
            decode(bytes(buf));
        } catch (Exception e) {
            return;
        }
    }

    // EXPECT notice localFile localUser
    static Object restore(Path path) throws Exception {
        return new ObjectInputStream(Files.newInputStream(path)).readObject();
    }
}
