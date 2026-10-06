package com.fasterxml.jackson.databind.jsontype.impl;

import com.fasterxml.jackson.databind.jsontype.PolymorphicTypeValidator;

/**
 * Compile-only stand-in for Jackson's validator that allows every class.
 */
public class LaissezFaireSubTypeValidator extends PolymorphicTypeValidator {

    public static final LaissezFaireSubTypeValidator instance = new LaissezFaireSubTypeValidator();

    @Override
    public boolean allows(String className) {
        return true;
    }
}
