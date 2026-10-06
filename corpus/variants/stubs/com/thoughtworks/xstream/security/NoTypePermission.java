package com.thoughtworks.xstream.security;

/**
 * Compile-only stand-in for XStream's NoTypePermission.
 */
public class NoTypePermission implements TypePermission {

    public static final TypePermission NONE = new NoTypePermission();

    @Override
    public boolean allows(Class<?> type) {
        return false;
    }
}
