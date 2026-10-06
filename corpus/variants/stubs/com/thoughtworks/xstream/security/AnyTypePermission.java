package com.thoughtworks.xstream.security;

/**
 * Compile-only stand-in for XStream's AnyTypePermission.
 */
public class AnyTypePermission implements TypePermission {

    public static final TypePermission ANY = new AnyTypePermission();

    @Override
    public boolean allows(Class<?> type) {
        return true;
    }
}
