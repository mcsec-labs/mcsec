package variants.deserialization;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufInputStream;
import java.io.Reader;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;
import org.yaml.snakeyaml.constructor.SafeConstructor;

/**
 * SnakeYAML, which honors global tags by default before 2.0. No SnakeYAML
 * version is bundled here, so defaults count as unsafe.
 */
public class SnakeYamlVariants {

    private static final Yaml SHARED = new Yaml();

    public static class Settings {
    }

    // EXPECT critical
    public static Object defaults(ByteBuf buf) {
        return new Yaml().load(new ByteBufInputStream(buf));
    }

    // EXPECT critical
    public static Settings typedConstructor(ByteBuf buf) {
        Yaml yaml = new Yaml(new Constructor(Settings.class));
        return yaml.loadAs(new ByteBufInputStream(buf), Settings.class);
    }

    // EXPECT notice
    public static Object safeConstructor(ByteBuf buf) {
        return new Yaml(new SafeConstructor()).load(new ByteBufInputStream(buf));
    }

    // EXPECT notice
    public static Object safeConstructorInLocal(ByteBuf buf) {
        SafeConstructor constructor = new SafeConstructor();
        Yaml yaml = new Yaml(constructor);
        return yaml.load(new ByteBufInputStream(buf));
    }

    // EXPECT warning
    public static Object configFile(Reader reader) {
        return new Yaml().load(reader);
    }

    // EXPECT warning
    public static Object sharedInstance(ByteBuf buf) {
        return SHARED.load(new ByteBufInputStream(buf));
    }
}
