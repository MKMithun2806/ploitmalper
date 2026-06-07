use std::collections::BTreeMap;

use crate::error::{AppError, Result};

#[derive(Debug, Clone, PartialEq)]
pub enum MsgValue {
    Nil,
    Bool(bool),
    Int(i64),
    UInt(u64),
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
