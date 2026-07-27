use std::collections::BTreeMap;

use crate::error::{AppError, Result};

#[derive(Debug, Clone, PartialEq)]
pub enum MsgValue {
    Nil,
    Bool(bool),
    Int(i64),
    UInt(u64),
    Float(f64),
    String(String),
    Array(Vec<MsgValue>),
    Map(BTreeMap<String, MsgValue>),
}

impl MsgValue {
    pub fn get(&self, key: &str) -> Option<&MsgValue> {
        match self {
            MsgValue::Map(map) => map.get(key),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            MsgValue::String(value) => Some(value.as_str()),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[MsgValue]> {
        match self {
            MsgValue::Array(values) => Some(values.as_slice()),
            _ => None,
        }
    }

    pub fn as_map(&self) -> Option<&BTreeMap<String, MsgValue>> {
        match self {
            MsgValue::Map(map) => Some(map),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            MsgValue::UInt(value) => Some(*value),
            MsgValue::Int(value) if *value >= 0 => Some(*value as u64),
            _ => None,
        }
    }
}

pub fn encode(value: &MsgValue) -> Vec<u8> {
    let mut buffer = Vec::new();
    encode_value(value, &mut buffer);
    buffer
}

pub fn decode(bytes: &[u8]) -> Result<MsgValue> {
    let (value, consumed) = decode_value(bytes, 0)?;
    if consumed != bytes.len() {
        return Err(AppError::Msgpack(
            "trailing bytes in msgpack payload".to_string(),
        ));
    }
    Ok(value)
}

fn encode_value(value: &MsgValue, buffer: &mut Vec<u8>) {
    match value {
        MsgValue::Nil => buffer.push(0xc0),
        MsgValue::Bool(false) => buffer.push(0xc2),
        MsgValue::Bool(true) => buffer.push(0xc3),
        MsgValue::Int(value) => encode_int(*value, buffer),
        MsgValue::UInt(value) => encode_uint(*value, buffer),
        MsgValue::Float(value) => {
            buffer.push(0xcb);
            buffer.extend_from_slice(&value.to_be_bytes());
        }
        MsgValue::String(value) => encode_str(value, buffer),
        MsgValue::Array(values) => encode_array(values, buffer),
        MsgValue::Map(map) => encode_map(map, buffer),
    }
}

fn encode_uint(value: u64, buffer: &mut Vec<u8>) {
    match value {
        0..=127 => buffer.push(value as u8),
        128..=255 => {
            buffer.push(0xcc);
            buffer.push(value as u8);
        }
        256..=65_535 => {
            buffer.push(0xcd);
            buffer.extend_from_slice(&(value as u16).to_be_bytes());
        }
        65_536..=4_294_967_295 => {
            buffer.push(0xce);
            buffer.extend_from_slice(&(value as u32).to_be_bytes());
        }
        _ => {
            buffer.push(0xcf);
            buffer.extend_from_slice(&value.to_be_bytes());
        }
    }
}

fn encode_int(value: i64, buffer: &mut Vec<u8>) {
    if (-32..=127).contains(&value) {
        if value >= 0 {
            buffer.push(value as u8);
        } else {
            buffer.push((value as i8) as u8);
        }
        return;
    }

    if (-128..=-33).contains(&value) {
        buffer.push(0xd0);
        buffer.push(value as i8 as u8);
    } else if (-32_768..=-129).contains(&value) {
        buffer.push(0xd1);
        buffer.extend_from_slice(&(value as i16).to_be_bytes());
    } else if (-2_147_483_648..=-32_769).contains(&value) {
        buffer.push(0xd2);
        buffer.extend_from_slice(&(value as i32).to_be_bytes());
    } else {
        buffer.push(0xd3);
        buffer.extend_from_slice(&value.to_be_bytes());
    }
}

fn encode_str(value: &str, buffer: &mut Vec<u8>) {
    let bytes = value.as_bytes();
    let len = bytes.len();
    if len <= 31 {
        buffer.push(0xa0 | (len as u8));
    } else if len <= 255 {
        buffer.push(0xd9);
        buffer.push(len as u8);
    } else if len <= 65_535 {
        buffer.push(0xda);
        buffer.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        buffer.push(0xdb);
        buffer.extend_from_slice(&(len as u32).to_be_bytes());
    }
    buffer.extend_from_slice(bytes);
}

fn encode_array(values: &[MsgValue], buffer: &mut Vec<u8>) {
    let len = values.len();
    if len <= 15 {
        buffer.push(0x90 | (len as u8));
    } else if len <= 65_535 {
        buffer.push(0xdc);
        buffer.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        buffer.push(0xdd);
        buffer.extend_from_slice(&(len as u32).to_be_bytes());
    }
    for value in values {
        encode_value(value, buffer);
    }
}

fn encode_map(map: &BTreeMap<String, MsgValue>, buffer: &mut Vec<u8>) {
    let len = map.len();
    if len <= 15 {
        buffer.push(0x80 | (len as u8));
    } else if len <= 65_535 {
        buffer.push(0xde);
        buffer.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        buffer.push(0xdf);
        buffer.extend_from_slice(&(len as u32).to_be_bytes());
    }
    for (key, value) in map {
        encode_str(key, buffer);
        encode_value(value, buffer);
    }
}

fn decode_value(bytes: &[u8], index: usize) -> Result<(MsgValue, usize)> {
    let prefix = *bytes
        .get(index)
        .ok_or_else(|| AppError::Msgpack("unexpected end of msgpack payload".to_string()))?;

    match prefix {
        0xc0 => Ok((MsgValue::Nil, index + 1)),
        0xc2 => Ok((MsgValue::Bool(false), index + 1)),
        0xc3 => Ok((MsgValue::Bool(true), index + 1)),
        0xc4 => {
            let len = read_u8(bytes, index + 1)? as usize;
            let slice = bytes
                .get(index + 2..index + 2 + len)
                .ok_or_else(|| {
                    AppError::Msgpack("unexpected end of msgpack binary data".to_string())
                })?;
            let value = String::from_utf8_lossy(slice).into_owned();
            Ok((MsgValue::String(value), index + 2 + len))
        }
        0xc5 => {
            let len = read_u16(bytes, index + 1)? as usize;
            let slice = bytes
                .get(index + 3..index + 3 + len)
                .ok_or_else(|| {
                    AppError::Msgpack("unexpected end of msgpack binary data".to_string())
                })?;
            let value = String::from_utf8_lossy(slice).into_owned();
            Ok((MsgValue::String(value), index + 3 + len))
        }
        0xc6 => {
            let len = read_u32(bytes, index + 1)? as usize;
            let slice = bytes
                .get(index + 5..index + 5 + len)
                .ok_or_else(|| {
                    AppError::Msgpack("unexpected end of msgpack binary data".to_string())
                })?;
            let value = String::from_utf8_lossy(slice).into_owned();
            Ok((MsgValue::String(value), index + 5 + len))
        }
        0xca => {
            let end = index + 5;
            let slice = bytes
                .get(index + 1..end)
                .ok_or_else(|| AppError::Msgpack("unexpected end of msgpack payload".to_string()))?;
            let value = f32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]);
            Ok((MsgValue::Float(value as f64), end))
        }
        0xcb => {
            let end = index + 9;
            let slice = bytes
                .get(index + 1..end)
                .ok_or_else(|| AppError::Msgpack("unexpected end of msgpack payload".to_string()))?;
            let value = f64::from_be_bytes([
                slice[0], slice[1], slice[2], slice[3],
                slice[4], slice[5], slice[6], slice[7],
            ]);
            Ok((MsgValue::Float(value), end))
        }
        0xcc => {
            let value = read_u8(bytes, index + 1)? as u64;
            Ok((MsgValue::UInt(value), index + 2))
        }
        0xcd => {
            let value = read_u16(bytes, index + 1)? as u64;
            Ok((MsgValue::UInt(value), index + 3))
        }
        0xce => {
            let value = read_u32(bytes, index + 1)? as u64;
            Ok((MsgValue::UInt(value), index + 5))
        }
        0xcf => {
            let value = read_u64(bytes, index + 1)?;
            Ok((MsgValue::UInt(value), index + 9))
        }
        0xd0 => {
            let value = read_i8(bytes, index + 1)? as i64;
            Ok((MsgValue::Int(value), index + 2))
        }
        0xd1 => {
            let value = read_i16(bytes, index + 1)? as i64;
            Ok((MsgValue::Int(value), index + 3))
        }
        0xd2 => {
            let value = read_i32(bytes, index + 1)? as i64;
            Ok((MsgValue::Int(value), index + 5))
        }
        0xd3 => {
            let value = read_i64(bytes, index + 1)?;
            Ok((MsgValue::Int(value), index + 9))
        }
        0xd9 => {
            let len = read_u8(bytes, index + 1)? as usize;
            decode_str(bytes, index + 2, len)
        }
        0xda => {
            let len = read_u16(bytes, index + 1)? as usize;
            decode_str(bytes, index + 3, len)
        }
        0xdb => {
            let len = read_u32(bytes, index + 1)? as usize;
            decode_str(bytes, index + 5, len)
        }
        0xdc => {
            let len = read_u16(bytes, index + 1)? as usize;
            decode_array(bytes, index + 3, len)
        }
        0xdd => {
            let len = read_u32(bytes, index + 1)? as usize;
            decode_array(bytes, index + 5, len)
        }
        0xde => {
            let len = read_u16(bytes, index + 1)? as usize;
            decode_map(bytes, index + 3, len)
        }
        0xdf => {
            let len = read_u32(bytes, index + 1)? as usize;
            decode_map(bytes, index + 5, len)
        }
        0x80..=0x8f => {
            let len = (prefix & 0x0f) as usize;
            decode_map(bytes, index + 1, len)
        }
        0x90..=0x9f => {
            let len = (prefix & 0x0f) as usize;
            decode_array(bytes, index + 1, len)
        }
        0xa0..=0xbf => {
            let len = (prefix & 0x1f) as usize;
            decode_str(bytes, index + 1, len)
        }
        0xe0..=0xff => Ok((MsgValue::Int((prefix as i8) as i64), index + 1)),
        0x00..=0x7f => Ok((MsgValue::UInt(prefix as u64), index + 1)),
        _ => Err(AppError::Msgpack(format!(
            "unsupported msgpack prefix: 0x{prefix:02x}"
        ))),
    }
}

fn decode_str(bytes: &[u8], index: usize, len: usize) -> Result<(MsgValue, usize)> {
    let end = index
        .checked_add(len)
        .ok_or_else(|| AppError::Msgpack("msgpack string length overflow".to_string()))?;
    let slice = bytes
        .get(index..end)
        .ok_or_else(|| AppError::Msgpack("unexpected end of msgpack string".to_string()))?;
    let value = String::from_utf8(slice.to_vec())
        .map_err(|e| AppError::Msgpack(format!("invalid utf-8 string: {e}")))?;
    Ok((MsgValue::String(value), end))
}

fn decode_array(bytes: &[u8], mut index: usize, len: usize) -> Result<(MsgValue, usize)> {
    let mut values = Vec::with_capacity(len);
    for _ in 0..len {
        let (value, next) = decode_value(bytes, index)?;
        values.push(value);
        index = next;
    }
    Ok((MsgValue::Array(values), index))
}

fn decode_map(bytes: &[u8], mut index: usize, len: usize) -> Result<(MsgValue, usize)> {
    let mut map = BTreeMap::new();
    for _ in 0..len {
        let (key_value, next_key) = decode_value(bytes, index)?;
        index = next_key;
        let key = key_value
            .as_str()
            .ok_or_else(|| AppError::Msgpack("msgpack map key was not a string".to_string()))?;
        let (value, next_value) = decode_value(bytes, index)?;
        index = next_value;
        map.insert(key.to_string(), value);
    }
    Ok((MsgValue::Map(map), index))
}

fn read_u8(bytes: &[u8], index: usize) -> Result<u8> {
    bytes
        .get(index)
        .copied()
        .ok_or_else(|| AppError::Msgpack("unexpected end of msgpack payload".to_string()))
}

fn read_i8(bytes: &[u8], index: usize) -> Result<i8> {
    Ok(read_u8(bytes, index)? as i8)
}

fn read_u16(bytes: &[u8], index: usize) -> Result<u16> {
    let end = index + 2;
    let slice = bytes
        .get(index..end)
        .ok_or_else(|| AppError::Msgpack("unexpected end of msgpack payload".to_string()))?;
    Ok(u16::from_be_bytes([slice[0], slice[1]]))
}

fn read_i16(bytes: &[u8], index: usize) -> Result<i16> {
    Ok(i16::from_be_bytes(read_u16(bytes, index)?.to_be_bytes()))
}

fn read_u32(bytes: &[u8], index: usize) -> Result<u32> {
    let end = index + 4;
    let slice = bytes
        .get(index..end)
        .ok_or_else(|| AppError::Msgpack("unexpected end of msgpack payload".to_string()))?;
    Ok(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn read_i32(bytes: &[u8], index: usize) -> Result<i32> {
    Ok(i32::from_be_bytes(read_u32(bytes, index)?.to_be_bytes()))
}

fn read_u64(bytes: &[u8], index: usize) -> Result<u64> {
    let end = index + 8;
    let slice = bytes
        .get(index..end)
        .ok_or_else(|| AppError::Msgpack("unexpected end of msgpack payload".to_string()))?;
    Ok(u64::from_be_bytes([
        slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
    ]))
}

fn read_i64(bytes: &[u8], index: usize) -> Result<i64> {
    Ok(i64::from_be_bytes(read_u64(bytes, index)?.to_be_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_nil() {
        let v = MsgValue::Nil;
        let bytes = encode(&v);
        let decoded = decode(&bytes).unwrap();
        assert_eq!(v, decoded);
    }

    #[test]
    fn roundtrip_bool() {
        for b in [true, false] {
            let v = MsgValue::Bool(b);
            let bytes = encode(&v);
            let decoded = decode(&bytes).unwrap();
            assert_eq!(v, decoded);
        }
    }

    #[test]
    fn roundtrip_positive_fixint() {
        for i in [0u64, 1, 127] {
            let v = MsgValue::UInt(i);
            let bytes = encode(&v);
            let decoded = decode(&bytes).unwrap();
            assert_eq!(v, decoded);
        }
    }

    #[test]
    fn roundtrip_u8() {
        let v = MsgValue::UInt(200);
        let bytes = encode(&v);
        assert_eq!(bytes[0], 0xcc);
        assert_eq!(bytes[1], 200);
        let decoded = decode(&bytes).unwrap();
        assert_eq!(v, decoded);
    }

    #[test]
    fn roundtrip_u16() {
        let v = MsgValue::UInt(1000);
        let bytes = encode(&v);
        assert_eq!(bytes[0], 0xcd);
        let decoded = decode(&bytes).unwrap();
        assert_eq!(v, decoded);
    }

    #[test]
    fn roundtrip_u32() {
        let v = MsgValue::UInt(100_000);
        let bytes = encode(&v);
        assert_eq!(bytes[0], 0xce);
        let decoded = decode(&bytes).unwrap();
        assert_eq!(v, decoded);
    }

    #[test]
    fn roundtrip_negative_fixint() {
        for i in [-1i64, -32] {
            let v = MsgValue::Int(i);
            let bytes = encode(&v);
            let decoded = decode(&bytes).unwrap();
            assert_eq!(v, decoded);
        }
    }

    #[test]
    fn roundtrip_i8() {
        let v = MsgValue::Int(-100);
        let bytes = encode(&v);
        assert_eq!(bytes[0], 0xd0);
        let decoded = decode(&bytes).unwrap();
        assert_eq!(v, decoded);
    }

    #[test]
    fn roundtrip_fixstr() {
        let v = MsgValue::String("hello".to_string());
        let bytes = encode(&v);
        assert_eq!(bytes[0], 0xa5);
        let decoded = decode(&bytes).unwrap();
        assert_eq!(v, decoded);
    }

    #[test]
    fn roundtrip_str8() {
        let s = "a".repeat(32);
        let v = MsgValue::String(s);
        let bytes = encode(&v);
        assert_eq!(bytes[0], 0xd9);
        assert_eq!(bytes[1], 32);
        let decoded = decode(&bytes).unwrap();
        assert_eq!(v, decoded);
    }

    #[test]
    fn roundtrip_fixarray() {
        let v = MsgValue::Array(vec![
            MsgValue::UInt(1),
            MsgValue::String("two".to_string()),
            MsgValue::Bool(true),
        ]);
        let bytes = encode(&v);
        assert_eq!(bytes[0], 0x93);
        let decoded = decode(&bytes).unwrap();
        assert_eq!(v, decoded);
    }

    #[test]
    fn roundtrip_fixmap() {
        let mut map = BTreeMap::new();
        map.insert("key".to_string(), MsgValue::String("value".to_string()));
        let v = MsgValue::Map(map);
        let bytes = encode(&v);
        assert_eq!(bytes[0], 0x81);
        let decoded = decode(&bytes).unwrap();
        assert_eq!(v, decoded);
    }

    #[test]
    fn decode_bin8() {
        // bin 8 format: 0xc4 <len> <bytes>
        let bytes = vec![0xc4, 0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f];
        let decoded = decode(&bytes).unwrap();
        assert_eq!(decoded, MsgValue::String("hello".to_string()));
    }

    #[test]
    fn decode_bin16() {
        // bin 16 format: 0xc5 <len_u16_be> <bytes>
        let mut bytes = vec![0xc5, 0x00, 0x05, 0x77, 0x6f, 0x72, 0x6c, 0x64];
        let decoded = decode(&bytes).unwrap();
        assert_eq!(decoded, MsgValue::String("world".to_string()));

        // Larger string
        let long = "x".repeat(300);
        bytes = vec![0xc5, 0x01, 0x2c];
        bytes.extend_from_slice(long.as_bytes());
        let decoded = decode(&bytes).unwrap();
        assert_eq!(decoded, MsgValue::String(long));
    }

    #[test]
    fn decode_bin32() {
        let long = "z".repeat(70000);
        let mut bytes = vec![0xc6, 0x00, 0x01, 0x11, 0x70];
        bytes.extend_from_slice(long.as_bytes());
        let decoded = decode(&bytes).unwrap();
        assert_eq!(decoded, MsgValue::String(long));
    }

    #[test]
    fn decode_float32() {
        let mut bytes = vec![0xca];
        bytes.extend_from_slice(&3.14f32.to_be_bytes());
        let decoded = decode(&bytes).unwrap();
        match decoded {
            MsgValue::Float(f) => assert!((f - 3.14).abs() < 0.001),
            _ => panic!("expected Float"),
        }
    }

    #[test]
    fn decode_float64() {
        let mut bytes = vec![0xcb];
        bytes.extend_from_slice(&std::f64::consts::PI.to_be_bytes());
        let decoded = decode(&bytes).unwrap();
        match decoded {
            MsgValue::Float(f) => assert!((f - std::f64::consts::PI).abs() < 1e-15),
            _ => panic!("expected Float"),
        }
    }

    #[test]
    fn decode_msf_auth_response() {
        // Simulated MSF-RPC auth.login response:
        // {"result": "success", "token": "abcd1234"}
        let mut bytes = Vec::new();
        // fixmap with 2 elements
        bytes.push(0x82);
        // bin 8 "result"
        bytes.extend_from_slice(&[0xc4, 0x06, 0x72, 0x65, 0x73, 0x75, 0x6c, 0x74]);
        // bin 8 "success"
        bytes.extend_from_slice(&[0xc4, 0x07, 0x73, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73]);
        // bin 8 "token"
        bytes.extend_from_slice(&[0xc4, 0x05, 0x74, 0x6f, 0x6b, 0x65, 0x6e]);
        // bin 8 "abcd1234"
        bytes.extend_from_slice(&[0xc4, 0x08, 0x61, 0x62, 0x63, 0x64, 0x31, 0x32, 0x33, 0x34]);

        let decoded = decode(&bytes).unwrap();
        let result = decoded.get("result").and_then(|v| v.as_str()).unwrap();
        let token = decoded.get("token").and_then(|v| v.as_str()).unwrap();
        assert_eq!(result, "success");
        assert_eq!(token, "abcd1234");
    }

    #[test]
    fn decode_msf_error_response() {
        // Simulated MSF error response using bin 8 for error_string
        // {"error": true, "error_string": "Invalid Message Format"}
        let mut bytes = Vec::new();
        bytes.push(0x82); // fixmap 2
        bytes.extend_from_slice(&[0xc4, 0x05, 0x65, 0x72, 0x72, 0x6f, 0x72]); // bin8 "error"
        bytes.push(0xc3); // true
        bytes.extend_from_slice(&[0xc4, 0x0c, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x5f, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67]); // bin8 "error_string"
        bytes.extend_from_slice(&[0xc4, 0x16, 0x49, 0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x20, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20, 0x46, 0x6f, 0x72, 0x6d, 0x61, 0x74]); // bin8 "Invalid Message Format"

        let decoded = decode(&bytes).unwrap();
        let error = decoded.get("error").unwrap();
        assert_eq!(error, &MsgValue::Bool(true));
        let error_string = decoded.get("error_string").and_then(|v| v.as_str()).unwrap();
        assert_eq!(error_string, "Invalid Message Format");
    }

    #[test]
    fn decode_trailing_bytes_fails() {
        let mut bytes = vec![0xa5, 0x68, 0x65, 0x6c, 0x6c, 0x6f]; // fixstr "hello"
        bytes.push(0x00); // extra byte
        let result = decode(&bytes);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("trailing bytes"));
    }

    #[test]
    fn encode_array_format_auth_login() {
        // Test encoding in the format the MSF server expects:
        // ["auth.login", "Mithun", "Mithun@2806"]
        let v = MsgValue::Array(vec![
            MsgValue::String("auth.login".to_string()),
            MsgValue::String("Mithun".to_string()),
            MsgValue::String("Mithun@2806".to_string()),
        ]);
        let bytes = encode(&v);
        // Should be 0x93 (fixarray 3) + 3 strings
        assert_eq!(bytes[0], 0x93);
        let decoded = decode(&bytes).unwrap();
        assert_eq!(v, decoded);
    }
}
