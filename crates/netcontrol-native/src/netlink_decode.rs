use anyhow::{Result, ensure};

/// Strict, alignment-aware netlink attribute framing, usable by portable fixture tests.
pub fn attributes(mut bytes: &[u8]) -> Result<Vec<(u16, Vec<u8>)>> {
    let mut result = Vec::new();
    while !bytes.is_empty() {
        ensure!(bytes.len() >= 4, "short netlink attribute header");
        let length = u16::from_ne_bytes([bytes[0], bytes[1]]) as usize;
        let kind = u16::from_ne_bytes([bytes[2], bytes[3]]);
        ensure!(
            length >= 4 && length <= bytes.len(),
            "invalid netlink attribute length"
        );
        let aligned = (length + 3) & !3;
        ensure!(
            aligned <= bytes.len(),
            "short netlink attribute alignment padding"
        );
        result.push((kind, bytes[4..length].to_vec()));
        bytes = &bytes[aligned..];
    }
    Ok(result)
}

pub fn c_string(bytes: &[u8]) -> Result<&str> {
    ensure!(
        !bytes.is_empty() && bytes[bytes.len() - 1] == 0 && !bytes[..bytes.len() - 1].contains(&0),
        "invalid netlink string"
    );
    Ok(std::str::from_utf8(&bytes[..bytes.len() - 1])?)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn attributes_reject_truncation_and_preserve_nested_flag() {
        let mut data = Vec::new();
        data.extend(7u16.to_ne_bytes());
        data.extend(0x8001u16.to_ne_bytes());
        data.extend([1, 2, 3, 0]);
        assert_eq!(attributes(&data).unwrap(), vec![(0x8001, vec![1, 2, 3])]);
        for end in 1..data.len() {
            assert!(attributes(&data[..end]).is_err());
        }
        assert!(attributes(&[0, 0, 1, 0]).is_err());
        assert!(c_string(b"abc\0").is_ok());
        assert!(c_string(b"a\0b\0").is_err());
    }
}
