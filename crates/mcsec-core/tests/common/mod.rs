//! Builders for class files and jars assembled in memory, shared by the
//! integration tests.

// Each test file uses a different subset of these helpers.
#![allow(dead_code)]

use std::io::{Cursor, Write};

use zip::ZipWriter;
use zip::write::SimpleFileOptions;

/// Assembles class files with a hand built constant pool.
#[derive(Default)]
pub struct ClassBuilder {
    pool: Vec<u8>,
    next_index: u16,
    fields: Vec<u8>,
    field_count: u16,
    methods: Vec<u8>,
    method_count: u16,
    attributes: Vec<u8>,
    attribute_count: u16,
}

impl ClassBuilder {
    pub fn new() -> Self {
        Self {
            next_index: 1,
            ..Self::default()
        }
    }

    fn push(&mut self, bytes: &[u8], slots: u16) -> u16 {
        let index = self.next_index;
        self.pool.extend(bytes);
        self.next_index += slots;
        index
    }

    pub fn raw_utf8(&mut self, bytes: &[u8]) -> u16 {
        let mut entry = vec![1];
        entry.extend((bytes.len() as u16).to_be_bytes());
        entry.extend(bytes);
        self.push(&entry, 1)
    }

    pub fn utf8(&mut self, text: &str) -> u16 {
        self.raw_utf8(text.as_bytes())
    }

    pub fn class(&mut self, name: &str) -> u16 {
        let name = self.utf8(name);
        let mut entry = vec![7];
        entry.extend(name.to_be_bytes());
        self.push(&entry, 1)
    }

    pub fn string(&mut self, text: &str) -> u16 {
        let text = self.utf8(text);
        let mut entry = vec![8];
        entry.extend(text.to_be_bytes());
        self.push(&entry, 1)
    }

    pub fn long(&mut self, value: i64) -> u16 {
        let mut entry = vec![5];
        entry.extend(value.to_be_bytes());
        self.push(&entry, 2)
    }

    fn member_ref(&mut self, tag: u8, class: &str, name: &str, descriptor: &str) -> u16 {
        let class = self.class(class);
        let name = self.utf8(name);
        let descriptor = self.utf8(descriptor);
        let mut name_and_type = vec![12];
        name_and_type.extend(name.to_be_bytes());
        name_and_type.extend(descriptor.to_be_bytes());
        let name_and_type = self.push(&name_and_type, 1);
        let mut entry = vec![tag];
        entry.extend(class.to_be_bytes());
        entry.extend(name_and_type.to_be_bytes());
        self.push(&entry, 1)
    }

    pub fn method_ref(&mut self, class: &str, name: &str, descriptor: &str) -> u16 {
        self.member_ref(10, class, name, descriptor)
    }

    pub fn interface_method_ref(&mut self, class: &str, name: &str, descriptor: &str) -> u16 {
        self.member_ref(11, class, name, descriptor)
    }

    pub fn attribute(&mut self, name: &str, body: &[u8]) -> Vec<u8> {
        let mut out = self.utf8(name).to_be_bytes().to_vec();
        out.extend((body.len() as u32).to_be_bytes());
        out.extend(body);
        out
    }

    pub fn code_attribute(&mut self, bytecode: &[u8]) -> Vec<u8> {
        let mut body = vec![0, 8, 0, 8];
        body.extend((bytecode.len() as u32).to_be_bytes());
        body.extend(bytecode);
        body.extend([0, 0, 0, 0]);
        self.attribute("Code", &body)
    }

    fn member(&mut self, name: &str, descriptor: &str, attributes: &[Vec<u8>]) -> Vec<u8> {
        let mut out = vec![0x00, 0x09];
        out.extend(self.utf8(name).to_be_bytes());
        out.extend(self.utf8(descriptor).to_be_bytes());
        out.extend((attributes.len() as u16).to_be_bytes());
        for attribute in attributes {
            out.extend(attribute);
        }
        out
    }

    pub fn field(&mut self, name: &str, descriptor: &str, attributes: &[Vec<u8>]) {
        let field = self.member(name, descriptor, attributes);
        self.fields.extend(field);
        self.field_count += 1;
    }

    pub fn method(&mut self, name: &str, descriptor: &str, attributes: &[Vec<u8>]) {
        let method = self.member(name, descriptor, attributes);
        self.methods.extend(method);
        self.method_count += 1;
    }

    pub fn method_with_code(&mut self, name: &str, bytecode: &[u8]) {
        self.method_with_descriptor(name, "()V", bytecode);
    }

    pub fn method_with_descriptor(&mut self, name: &str, descriptor: &str, bytecode: &[u8]) {
        let code = self.code_attribute(bytecode);
        self.method(name, descriptor, &[code]);
    }

    pub fn build(self, name: &str) -> Vec<u8> {
        self.build_extending(name, "java/lang/Object")
    }

    pub fn build_extending(mut self, name: &str, super_name: &str) -> Vec<u8> {
        let this_class = self.class(name);
        let super_class = self.class(super_name);
        let interface = self.class("java/io/Serializable");

        let mut out = vec![0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 65];
        out.extend(self.next_index.to_be_bytes());
        out.extend(&self.pool);
        out.extend([0x00, 0x21]);
        out.extend(this_class.to_be_bytes());
        out.extend(super_class.to_be_bytes());
        out.extend([0, 1]);
        out.extend(interface.to_be_bytes());
        out.extend(self.field_count.to_be_bytes());
        out.extend(&self.fields);
        out.extend(self.method_count.to_be_bytes());
        out.extend(&self.methods);
        out.extend(self.attribute_count.to_be_bytes());
        out.extend(&self.attributes);
        out
    }
}

/// Builds a jar from (entry name, bytes) pairs.
pub fn jar(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    for (name, data) in entries {
        writer
            .start_file(*name, SimpleFileOptions::default())
            .unwrap();
        writer.write_all(data).unwrap();
    }
    writer.finish().unwrap().into_inner()
}
