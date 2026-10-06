package com.fasterxml.jackson.databind;

import com.fasterxml.jackson.databind.jsontype.PolymorphicTypeValidator;

/**
 * Compile-only stand-in for Jackson's ObjectMapper.
 */
public class ObjectMapper {

    public ObjectMapper() {
        throw new UnsupportedOperationException();
    }

    public ObjectMapper enableDefaultTyping() {
        throw new UnsupportedOperationException();
    }

    public ObjectMapper activateDefaultTyping(PolymorphicTypeValidator validator) {
        throw new UnsupportedOperationException();
    }

    public <T> T readValue(String content, Class<T> type) {
        throw new UnsupportedOperationException();
    }

    public <T> T readValue(byte[] content, Class<T> type) {
        throw new UnsupportedOperationException();
    }
}
