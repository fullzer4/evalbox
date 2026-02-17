//! Parser for /etc/ld.so.cache.
//!
//! The ld.so.cache file is a binary cache of library paths used by the
//! dynamic linker. We parse it to resolve library names to paths without
//! searching the filesystem.

use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::error::ProbeError;

const LDCACHE_PATH: &str = "/etc/ld.so.cache";
const LDCACHE_MAGIC_NEW: &[u8] = b"glibc-ld.so.cache1.1";
const LDCACHE_MAGIC_OLD: &[u8] = b"ld.so-1.7.0";

#[derive(Debug, Default)]
pub struct LdCache {
    entries: HashMap<String, PathBuf>,
}

impl LdCache {
    pub fn load() -> Result<Self, ProbeError> {
        Self::load_from(Path::new(LDCACHE_PATH))
    }

    pub fn load_from(path: &Path) -> Result<Self, ProbeError> {
        let mut file = match File::open(path) {
            Ok(f) => f,
            Err(_) => {
                return Ok(Self::default());
            }
        };

        let mut data = Vec::new();
        file.read_to_end(&mut data)?;

        Self::parse(&data)
    }

    fn parse(data: &[u8]) -> Result<Self, ProbeError> {
        if data.len() < 20 {
            return Ok(Self::default());
        }

        if data.starts_with(LDCACHE_MAGIC_NEW) {
            return Self::parse_new_format(data);
        }

        if data.starts_with(LDCACHE_MAGIC_OLD) {
            return Self::parse_old_format(data);
        }

        Ok(Self::default())
    }

    fn parse_new_format(data: &[u8]) -> Result<Self, ProbeError> {
        if data.len() < 48 {
            return Ok(Self::default());
        }

        let nlibs = read_u32_le(&data[20..24]);
        let len_strings = read_u32_le(&data[24..28]);

        let header_size = 48_usize;
        let entry_size = 24_usize;
        let entries_end = header_size + (nlibs as usize) * entry_size;

        if data.len() < entries_end + len_strings as usize {
            return Ok(Self::default());
        }

        let string_table = &data[entries_end..];

        let mut entries = HashMap::new();

        for i in 0..nlibs as usize {
            let entry_offset = header_size + i * entry_size;
            let entry = &data[entry_offset..entry_offset + entry_size];

            let key_offset = read_u32_le(&entry[4..8]) as usize;
            let value_offset = read_u32_le(&entry[8..12]) as usize;

            if let (Some(name), Some(path)) = (
                read_cstring(string_table, key_offset),
                read_cstring(string_table, value_offset),
            ) {
                entries.insert(name.to_string(), PathBuf::from(path));
            }
        }

        Ok(Self { entries })
    }

    fn parse_old_format(data: &[u8]) -> Result<Self, ProbeError> {
        if data.len() < 16 {
            return Ok(Self::default());
        }

        let nlibs = read_u32_le(&data[12..16]);

        let header_size = 16_usize;
        let entry_size = 12_usize;
        let entries_end = header_size + (nlibs as usize) * entry_size;

        if data.len() < entries_end {
            return Ok(Self::default());
        }

        let mut entries = HashMap::new();

        for i in 0..nlibs as usize {
            let entry_offset = header_size + i * entry_size;
            let entry = &data[entry_offset..entry_offset + entry_size];

            let key_offset = read_u32_le(&entry[4..8]) as usize;
            let value_offset = read_u32_le(&entry[8..12]) as usize;

            if let (Some(name), Some(path)) = (
                read_cstring(data, key_offset),
                read_cstring(data, value_offset),
            ) {
                entries.insert(name.to_string(), PathBuf::from(path));
            }
        }

        Ok(Self { entries })
    }

    pub fn lookup(&self, name: &str) -> Option<PathBuf> {
        self.entries.get(name).cloned()
    }
}

fn read_u32_le(data: &[u8]) -> u32 {
    u32::from_le_bytes([data[0], data[1], data[2], data[3]])
}

fn read_cstring(data: &[u8], offset: usize) -> Option<&str> {
    if offset >= data.len() {
        return None;
    }

    let start = &data[offset..];
    let end = start.iter().position(|&b| b == 0)?;

    std::str::from_utf8(&start[..end]).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_ldcache() {
        let result = LdCache::load();
        assert!(result.is_ok(), "Should load ld.so.cache without error");
    }

    #[test]
    fn test_load_nonexistent() {
        let result = LdCache::load_from(Path::new("/nonexistent/ld.so.cache"));
        assert!(
            result.is_ok(),
            "Should return empty cache for nonexistent file"
        );
        assert!(result.unwrap().entries.is_empty());
    }

    #[test]
    fn test_lookup_libc() {
        let cache = LdCache::load().unwrap();

        if cache.entries.is_empty() {
            return;
        }

        let libc = cache.lookup("libc.so.6");
        if let Some(path) = libc {
            assert!(path.exists(), "libc path should exist: {}", path.display());
            assert!(
                path.to_string_lossy().contains("libc"),
                "Path should contain 'libc': {}",
                path.display()
            );
        }
    }

    #[test]
    fn test_lookup_nonexistent() {
        let cache = LdCache::load().unwrap();
        let result = cache.lookup("nonexistent_library_12345.so");
        assert!(
            result.is_none(),
            "Should return None for nonexistent library"
        );
    }

    #[test]
    fn test_parse_empty_data() {
        let result = LdCache::parse(&[]);
        assert!(result.is_ok());
        assert!(result.unwrap().entries.is_empty());
    }

    #[test]
    fn test_parse_invalid_magic() {
        let data = b"invalid magic header data that is long enough";
        let result = LdCache::parse(data);
        assert!(result.is_ok(), "Should handle invalid magic gracefully");
        assert!(result.unwrap().entries.is_empty());
    }

    #[test]
    fn test_read_cstring() {
        let data = b"hello\0world\0";
        assert_eq!(read_cstring(data, 0), Some("hello"));
        assert_eq!(read_cstring(data, 6), Some("world"));
        assert_eq!(read_cstring(data, 100), None);
    }

    #[test]
    fn test_read_u32_le() {
        let data = [0x01, 0x02, 0x03, 0x04];
        assert_eq!(read_u32_le(&data), 0x04030201);
    }
}
