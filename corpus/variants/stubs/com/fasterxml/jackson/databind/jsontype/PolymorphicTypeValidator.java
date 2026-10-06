package com.fasterxml.jackson.databind.jsontype;

/**
 * Compile-only stand-in for Jackson's PolymorphicTypeValidator.
 */
public abstract class PolymorphicTypeValidator {

    public abstract boolean allows(String className);
}
