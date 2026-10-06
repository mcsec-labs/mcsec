package com.thoughtworks.xstream;

import com.thoughtworks.xstream.security.TypePermission;
import java.io.InputStream;

/**
 * Compile-only stand-in for XStream.
 */
public class XStream {

    public XStream() {
        throw new UnsupportedOperationException();
    }

    public static void setupDefaultSecurity(XStream xstream) {
        throw new UnsupportedOperationException();
    }

    public void addPermission(TypePermission permission) {
        throw new UnsupportedOperationException();
    }

    public void allowTypes(String[] names) {
        throw new UnsupportedOperationException();
    }

    public Object fromXML(String xml) {
        throw new UnsupportedOperationException();
    }

    public Object fromXML(InputStream input) {
        throw new UnsupportedOperationException();
    }
}
