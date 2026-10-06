package org.yaml.snakeyaml;

import java.io.InputStream;
import java.io.Reader;
import org.yaml.snakeyaml.constructor.BaseConstructor;

/**
 * Compile-only stand-in for SnakeYAML's entry point.
 */
public class Yaml {

    public Yaml() {
        throw new UnsupportedOperationException();
    }

    public Yaml(BaseConstructor constructor) {
        throw new UnsupportedOperationException();
    }

    public <T> T load(String yaml) {
        throw new UnsupportedOperationException();
    }

    public <T> T load(InputStream input) {
        throw new UnsupportedOperationException();
    }

    public <T> T load(Reader reader) {
        throw new UnsupportedOperationException();
    }

    public <T> T loadAs(InputStream input, Class<T> type) {
        throw new UnsupportedOperationException();
    }
}
