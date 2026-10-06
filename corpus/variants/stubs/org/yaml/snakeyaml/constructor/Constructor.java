package org.yaml.snakeyaml.constructor;

/**
 * Compile-only stand-in for SnakeYAML's Constructor, which honors global tags.
 */
public class Constructor extends SafeConstructor {

    public Constructor(Class<?> root) {
        throw new UnsupportedOperationException();
    }
}
