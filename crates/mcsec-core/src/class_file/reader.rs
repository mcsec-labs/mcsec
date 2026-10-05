//! Bounds checked big-endian reads over class file bytes.

use super::ClassParseError;

pub(crate) struct ByteReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> ByteReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    pub fn bytes(&mut self, len: usize) -> Result<&'a [u8], ClassParseError> {
        let end = self
            .pos
            .checked_add(len)
            .filter(|&end| end <= self.data.len())
            .ok_or(ClassParseError::Truncated { offset: self.pos })?;
        let out = &self.data[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    pub fn skip(&mut self, len: usize) -> Result<(), ClassParseError> {
        self.bytes(len).map(|_| ())
    }

    pub fn u8(&mut self) -> Result<u8, ClassParseError> {
        Ok(self.bytes(1)?[0])
    }

    pub fn u16(&mut self) -> Result<u16, ClassParseError> {
        let b = self.bytes(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    pub fn u32(&mut self) -> Result<u32, ClassParseError> {
        let b = self.bytes(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn i8(&mut self) -> Result<i8, ClassParseError> {
        Ok(self.u8()? as i8)
    }

    pub fn i16(&mut self) -> Result<i16, ClassParseError> {
        Ok(self.u16()? as i16)
    }

    pub fn i32(&mut self) -> Result<i32, ClassParseError> {
        Ok(self.u32()? as i32)
    }

    /// Capacity for `count` items of at least `min_size` bytes each, capped
    /// by what the remaining bytes could hold. A forged count cannot force a
    /// large allocation this way.
    pub fn capacity_for(&self, count: usize, min_size: usize) -> usize {
        count.min(self.remaining() / min_size.max(1))
    }
}
