package variants.deserialization;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InvalidClassException;
import java.io.ObjectInputStream;
import java.io.ObjectStreamClass;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * ObjectInputStream subclasses judged by what their resolveClass override does.
 * Only an override that throws for classes it does not find counts as
 * restricting, whatever its name or how it looks the class up.
 */
public class ResolveClassVariants {

    /**
     * Resolves every name through a class loader.
     */
    static class LoaderStream extends ObjectInputStream {

        LoaderStream(InputStream in) throws IOException {
            super(in);
        }

        @Override
        protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
            return Class.forName(desc.getName(), false, LoaderStream.class.getClassLoader());
        }
    }

    /**
     * Looks names up through a resolver whose code is not visible here.
     */
    interface Resolver {

        Class<?> resolve(String name) throws ClassNotFoundException;
    }

    /**
     * Hands every name to its resolver, the way Netty's
     * CompactObjectInputStream does.
     */
    static class ResolverStream extends ObjectInputStream {

        private final Resolver resolver;

        ResolverStream(InputStream in, Resolver resolver) throws IOException {
            super(in);
            this.resolver = resolver;
        }

        @Override
        protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
            try {
                return resolver.resolve(desc.getName());
            } catch (ClassNotFoundException e) {
                return super.resolveClass(desc);
            }
        }
    }

    /**
     * Maps one primitive name itself and passes every other name on.
     */
    static class PrimitiveStream extends ObjectInputStream {

        PrimitiveStream(InputStream in) throws IOException {
            super(in);
        }

        @Override
        protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
            if ("int".equals(desc.getName())) {
                return int.class;
            }
            return super.resolveClass(desc);
        }
    }

    /**
     * Overrides a different hook and leaves resolveClass alone.
     */
    static class HeaderStream extends ObjectInputStream {

        HeaderStream(InputStream in) throws IOException {
            super(in);
        }

        @Override
        protected void readStreamHeader() throws IOException {
            super.readStreamHeader();
        }
    }

    /**
     * Rejects one family of known gadget classes and accepts the rest.
     */
    static class BlocklistStream extends ObjectInputStream {

        BlocklistStream(InputStream in) throws IOException {
            super(in);
        }

        @Override
        protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
            if (desc.getName().startsWith("org.apache.commons.collections.functors.")) {
                throw new InvalidClassException("blocked class", desc.getName());
            }
            return super.resolveClass(desc);
        }
    }

    /**
     * Accepts only names in a set.
     */
    static class SetAllowlistStream extends ObjectInputStream {

        private static final Set<String> ALLOWED = new HashSet<>(Arrays.asList("java.util.HashMap", "java.lang.Integer"));

        SetAllowlistStream(InputStream in) throws IOException {
            super(in);
        }

        @Override
        protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
            if (!ALLOWED.contains(desc.getName())) {
                throw new InvalidClassException("not allowed", desc.getName());
            }
            return super.resolveClass(desc);
        }
    }

    /**
     * Accepts only names a map holds, returning the mapped class.
     */
    static class MapAllowlistStream extends ObjectInputStream {

        private static final Map<String, Class<?>> ALLOWED = new HashMap<>();

        static {
            ALLOWED.put("java.util.HashMap", HashMap.class);
        }

        MapAllowlistStream(InputStream in) throws IOException {
            super(in);
        }

        @Override
        protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
            Class<?> type = ALLOWED.get(desc.getName());
            if (type == null) {
                throw new InvalidClassException("not allowed", desc.getName());
            }
            return type;
        }
    }

    /**
     * Checks the name in a helper that throws.
     */
    static class HelperAllowlistStream extends ObjectInputStream {

        HelperAllowlistStream(InputStream in) throws IOException {
            super(in);
        }

        static void check(String name) throws InvalidClassException {
            if (!name.startsWith("java.util.")) {
                throw new InvalidClassException("not allowed", name);
            }
        }

        @Override
        protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
            check(desc.getName());
            return super.resolveClass(desc);
        }
    }

    /**
     * Inherits an allowlist without overriding anything.
     */
    static class InheritedAllowlistStream extends SetAllowlistStream {

        InheritedAllowlistStream(InputStream in) throws IOException {
            super(in);
        }
    }

    /**
     * Allows one more class itself, then defers to its allowlisting parent.
     */
    static class WideningAllowlistStream extends SetAllowlistStream {

        WideningAllowlistStream(InputStream in) throws IOException {
            super(in);
        }

        @Override
        protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
            if ("java.util.ArrayList".equals(desc.getName())) {
                return java.util.ArrayList.class;
            }
            return super.resolveClass(desc);
        }
    }

    /**
     * Accepts only the names a string switch lists.
     */
    static class SwitchAllowlistStream extends ObjectInputStream {

        SwitchAllowlistStream(InputStream in) throws IOException {
            super(in);
        }

        @Override
        protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
            switch (desc.getName()) {
                case "java.util.HashMap":
                case "java.lang.Integer":
                    return super.resolveClass(desc);
                default:
                    throw new InvalidClassException("not allowed", desc.getName());
            }
        }
    }

    /**
     * Sets a flag from two prefix checks and throws when it is unset.
     */
    static class FlagAllowlistStream extends ObjectInputStream {

        FlagAllowlistStream(InputStream in) throws IOException {
            super(in);
        }

        @Override
        protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
            String name = desc.getName();
            boolean allowed = name.startsWith("java.util.") || name.startsWith("java.lang.");
            if (!allowed) {
                throw new InvalidClassException("not allowed", name);
            }
            return super.resolveClass(desc);
        }
    }

    /**
     * Tries each allowed prefix in turn and throws when none matches.
     */
    static class LoopAllowlistStream extends ObjectInputStream {

        private static final String[] PREFIXES = {"java.util.", "java.lang."};

        LoopAllowlistStream(InputStream in) throws IOException {
            super(in);
        }

        @Override
        protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
            for (String prefix : PREFIXES) {
                if (desc.getName().startsWith(prefix)) {
                    return super.resolveClass(desc);
                }
            }
            throw new InvalidClassException("not allowed", desc.getName());
        }
    }

    /**
     * Tries each blocked prefix in turn and accepts any name none matches.
     */
    static class LoopBlocklistStream extends ObjectInputStream {

        private static final String[] BLOCKED = {"org.apache.commons.collections.", "org.codehaus.groovy."};

        LoopBlocklistStream(InputStream in) throws IOException {
            super(in);
        }

        @Override
        protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
            for (String prefix : BLOCKED) {
                if (desc.getName().startsWith(prefix)) {
                    throw new InvalidClassException("blocked class", desc.getName());
                }
            }
            return super.resolveClass(desc);
        }
    }

    /**
     * Asks a class loader first and checks its map only when that fails, the
     * way Commons Lang's ClassLoaderAwareObjectInputStream does.
     */
    static class LoaderThenMapStream extends ObjectInputStream {

        private static final Map<String, Class<?>> PRIMITIVES = new HashMap<>();

        static {
            PRIMITIVES.put("int", int.class);
        }

        LoaderThenMapStream(InputStream in) throws IOException {
            super(in);
        }

        @Override
        protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
            String name = desc.getName();
            try {
                return Class.forName(name, false, LoaderThenMapStream.class.getClassLoader());
            } catch (ClassNotFoundException e) {
                Class<?> type = PRIMITIVES.get(name);
                if (type != null) {
                    return type;
                }
                throw e;
            }
        }
    }

    /**
     * Calls a helper named like a check that checks nothing.
     */
    static class EmptyHelperStream extends ObjectInputStream {

        EmptyHelperStream(InputStream in) throws IOException {
            super(in);
        }

        private static void check(String name) {
            System.out.println(name);
        }

        @Override
        protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
            check(desc.getName());
            return super.resolveClass(desc);
        }
    }

    /**
     * Runs a real check but catches and ignores its rejection.
     */
    static class SwallowedCheckStream extends ObjectInputStream {

        SwallowedCheckStream(InputStream in) throws IOException {
            super(in);
        }

        @Override
        protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
            try {
                HelperAllowlistStream.check(desc.getName());
            } catch (InvalidClassException e) {
                System.out.println(e);
            }
            return super.resolveClass(desc);
        }
    }

    /**
     * Checks every name, but rejects a missing one only when blocking is on.
     */
    static class ConfigurableAllowlistStream extends ObjectInputStream {

        static boolean blocking = true;

        private static final Set<String> ALLOWED = new HashSet<>(Arrays.asList("java.util.HashMap"));

        ConfigurableAllowlistStream(InputStream in) throws IOException {
            super(in);
        }

        @Override
        protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
            if (!ALLOWED.contains(desc.getName())) {
                System.err.println("not allowed " + desc.getName());
                if (blocking) {
                    throw new InvalidClassException("not allowed", desc.getName());
                }
            }
            return super.resolveClass(desc);
        }
    }

    /**
     * Runs the same conditional check in a helper first.
     */
    static class ConfigurableHelperStream extends ObjectInputStream {

        ConfigurableHelperStream(InputStream in) throws IOException {
            super(in);
        }

        static void precheck(ObjectStreamClass desc) throws ClassNotFoundException {
            if (!desc.getName().startsWith("java.util.")) {
                System.err.println("not allowed " + desc.getName());
                if (ConfigurableAllowlistStream.blocking) {
                    throw new ClassNotFoundException(desc.getName());
                }
            }
        }

        @Override
        protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
            precheck(desc);
            return super.resolveClass(desc);
        }
    }

    /**
     * Checks every name but only logs a missing one.
     */
    static class LogOnlyStream extends ObjectInputStream {

        LogOnlyStream(InputStream in) throws IOException {
            super(in);
        }

        @Override
        protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
            if (!desc.getName().startsWith("java.util.")) {
                System.err.println("unexpected class " + desc.getName());
            }
            return super.resolveClass(desc);
        }
    }

    // EXPECT notice allowlist
    public static Object configurableAllowlist(ByteBuf buf) throws Exception {
        return new ConfigurableAllowlistStream(new ByteBufInputStream(buf)).readObject();
    }

    // EXPECT notice allowlist
    public static Object configurableHelper(ByteBuf buf) throws Exception {
        return new ConfigurableHelperStream(new ByteBufInputStream(buf)).readObject();
    }

    // EXPECT critical network
    public static Object logOnly(ByteBuf buf) throws Exception {
        return new LogOnlyStream(new ByteBufInputStream(buf)).readObject();
    }

    // EXPECT critical
    public static Object classLoader(ByteBuf buf) throws Exception {
        return new LoaderStream(new ByteBufInputStream(buf)).readObject();
    }

    // EXPECT critical
    public static Object delegatedResolver(ByteBuf buf, Resolver resolver) throws Exception {
        return new ResolverStream(new ByteBufInputStream(buf), resolver).readObject();
    }

    // EXPECT critical
    public static Object primitiveMapping(ByteBuf buf) throws Exception {
        return new PrimitiveStream(new ByteBufInputStream(buf)).readObject();
    }

    // EXPECT critical
    public static Object otherHookOnly(ByteBuf buf) throws Exception {
        return new HeaderStream(new ByteBufInputStream(buf)).readObject();
    }

    // EXPECT critical network
    public static Object blocklist(ByteBuf buf) throws Exception {
        return new BlocklistStream(new ByteBufInputStream(buf)).readObject();
    }

    // EXPECT notice allowlist
    public static Object setAllowlist(ByteBuf buf) throws Exception {
        return new SetAllowlistStream(new ByteBufInputStream(buf)).readObject();
    }

    // EXPECT notice
    public static Object mapAllowlist(ByteBuf buf) throws Exception {
        return new MapAllowlistStream(new ByteBufInputStream(buf)).readObject();
    }

    // EXPECT notice
    public static Object helperAllowlist(ByteBuf buf) throws Exception {
        return new HelperAllowlistStream(new ByteBufInputStream(buf)).readObject();
    }

    // EXPECT notice
    public static Object inheritedAllowlist(ByteBuf buf) throws Exception {
        return new InheritedAllowlistStream(new ByteBufInputStream(buf)).readObject();
    }

    // EXPECT notice
    public static Object wideningAllowlist(ByteBuf buf) throws Exception {
        return new WideningAllowlistStream(new ByteBufInputStream(buf)).readObject();
    }

    // EXPECT notice allowlist
    public static Object switchAllowlist(ByteBuf buf) throws Exception {
        return new SwitchAllowlistStream(new ByteBufInputStream(buf)).readObject();
    }

    // EXPECT notice
    public static Object flagAllowlist(ByteBuf buf) throws Exception {
        return new FlagAllowlistStream(new ByteBufInputStream(buf)).readObject();
    }

    // EXPECT notice allowlist
    public static Object loopAllowlist(ByteBuf buf) throws Exception {
        return new LoopAllowlistStream(new ByteBufInputStream(buf)).readObject();
    }

    // EXPECT critical
    public static Object loopBlocklist(ByteBuf buf) throws Exception {
        return new LoopBlocklistStream(new ByteBufInputStream(buf)).readObject();
    }

    // EXPECT critical
    public static Object loaderThenMap(ByteBuf buf) throws Exception {
        return new LoaderThenMapStream(new ByteBufInputStream(buf)).readObject();
    }

    // EXPECT critical
    public static Object emptyHelper(ByteBuf buf) throws Exception {
        return new EmptyHelperStream(new ByteBufInputStream(buf)).readObject();
    }

    // EXPECT critical
    public static Object swallowedCheck(ByteBuf buf) throws Exception {
        return new SwallowedCheckStream(new ByteBufInputStream(buf)).readObject();
    }
}
