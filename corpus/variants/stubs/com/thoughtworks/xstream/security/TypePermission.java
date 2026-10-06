package com.thoughtworks.xstream.security;

/**
 * Compile-only stand-in for XStream's TypePermission.
 */
public interface TypePermission {

    boolean allows(Class<?> type);
}
