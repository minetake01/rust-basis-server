use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireError(pub String);

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for WireError {}

pub type WireResult<T> = Result<T, WireError>;

#[derive(Default, Clone)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn with_capacity(cap: usize) -> Self {
        Self {
            buf: Vec::with_capacity(cap),
        }
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.buf
    }

    pub fn clear(&mut self) {
        self.buf.clear();
    }

    pub fn put_u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    pub fn put_bool(&mut self, v: bool) {
        self.put_u8(if v { 1 } else { 0 });
    }

    pub fn put_u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn put_i32(&mut self, v: i32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn put_u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn put_i64(&mut self, v: i64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn put_u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn put_f32(&mut self, v: f32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn put_bytes(&mut self, v: &[u8]) {
        self.buf.extend_from_slice(v);
    }

    /// NetDataWriter string framing: empty = 0, otherwise byte length + 1.
    pub fn put_string(&mut self, s: &str) {
        if s.is_empty() {
            self.put_u16(0);
            return;
        }
        let bytes = s.as_bytes();
        if bytes.len() > u16::MAX as usize - 1 {
            // The C# side has a ushort ceiling; truncate at a char boundary defensively.
            let mut end = u16::MAX as usize - 1;
            while end > 0 && !s.is_char_boundary(end) {
                end -= 1;
            }
            self.put_u16((end + 1) as u16);
            self.put_bytes(&bytes[..end]);
        } else {
            self.put_u16((bytes.len() + 1) as u16);
            self.put_bytes(bytes);
        }
    }

    /// NetDataWriter.PutArray(array, 1): ushort element count, then raw bytes.
    pub fn put_bytes_with_length(&mut self, bytes: &[u8]) {
        let len = bytes.len().min(u16::MAX as usize);
        self.put_u16(len as u16);
        self.put_bytes(&bytes[..len]);
    }
}

#[derive(Clone)]
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn set_position(&mut self, pos: usize) -> WireResult<()> {
        if pos > self.data.len() {
            return Err(WireError("position out of range".into()));
        }
        self.pos = pos;
        Ok(())
    }

    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    pub fn raw(&self) -> &'a [u8] {
        self.data
    }

    pub fn peek_u8(&self) -> WireResult<u8> {
        self.data
            .get(self.pos)
            .copied()
            .ok_or_else(|| WireError("unexpected end of data".into()))
    }

    pub fn get_u8(&mut self) -> WireResult<u8> {
        let v = self.peek_u8()?;
        self.pos += 1;
        Ok(v)
    }

    pub fn get_bool(&mut self) -> WireResult<bool> {
        Ok(self.get_u8()? != 0)
    }

    pub fn get_u16(&mut self) -> WireResult<u16> {
        if self.remaining() < 2 {
            return Err(WireError("unexpected end of data (u16)".into()));
        }
        let v = u16::from_le_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    pub fn get_i32(&mut self) -> WireResult<i32> {
        if self.remaining() < 4 {
            return Err(WireError("unexpected end of data (i32)".into()));
        }
        let mut b = [0u8; 4];
        b.copy_from_slice(&self.data[self.pos..self.pos + 4]);
        self.pos += 4;
        Ok(i32::from_le_bytes(b))
    }

    pub fn get_u32(&mut self) -> WireResult<u32> {
        Ok(self.get_i32()? as u32)
    }

    pub fn get_i64(&mut self) -> WireResult<i64> {
        if self.remaining() < 8 {
            return Err(WireError("unexpected end of data (i64)".into()));
        }
        let mut b = [0u8; 8];
        b.copy_from_slice(&self.data[self.pos..self.pos + 8]);
        self.pos += 8;
        Ok(i64::from_le_bytes(b))
    }

    pub fn get_u64(&mut self) -> WireResult<u64> {
        Ok(self.get_i64()? as u64)
    }

    pub fn get_f32(&mut self) -> WireResult<f32> {
        if self.remaining() < 4 {
            return Err(WireError("unexpected end of data (f32)".into()));
        }
        let mut b = [0u8; 4];
        b.copy_from_slice(&self.data[self.pos..self.pos + 4]);
        self.pos += 4;
        Ok(f32::from_le_bytes(b))
    }

    pub fn get_bytes(&mut self, len: usize) -> WireResult<&'a [u8]> {
        if self.remaining() < len {
            return Err(WireError(format!(
                "unexpected end of data: need {len}, have {}",
                self.remaining()
            )));
        }
        let out = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Ok(out)
    }

    pub fn get_string(&mut self) -> WireResult<String> {
        let framed = self.get_u16()? as usize;
        if framed == 0 {
            return Ok(String::new());
        }
        let len = framed - 1;
        let bytes = self.get_bytes(len)?;
        Ok(String::from_utf8_lossy(bytes).into_owned())
    }

    pub fn get_bytes_with_length(&mut self) -> WireResult<&'a [u8]> {
        let len = self.get_u16()? as usize;
        self.get_bytes(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_round_trip_matches_netdatawriter_framing() {
        let mut w = Writer::new();
        w.put_string("default_password");
        assert_eq!(&w.as_slice()[..2], &[17, 0]);
        let mut r = Reader::new(w.as_slice());
        assert_eq!(r.get_string().unwrap(), "default_password");
        assert!(r.is_empty());
    }

    #[test]
    fn empty_string_is_zero_length() {
        let mut w = Writer::new();
        w.put_string("");
        assert_eq!(w.as_slice(), &[0, 0]);
        let mut r = Reader::new(w.as_slice());
        assert_eq!(r.get_string().unwrap(), "");
    }
}
