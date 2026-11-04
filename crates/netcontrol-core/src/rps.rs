use anyhow::{Result, ensure};
use std::collections::BTreeSet;

pub const MAX_CPU_ID: u32 = 8191;

pub fn parse_cpu_list(text: &str) -> Result<BTreeSet<u32>> {
    ensure!(text.len() <= 65536, "CPU list exceeds size limit");
    let mut cpus = BTreeSet::new();
    if text.is_empty() {
        return Ok(cpus);
    }
    for item in text.split(',') {
        let (first, last) = match item.split_once('-') {
            Some((first, last)) => (first.parse::<u32>()?, last.parse::<u32>()?),
            None => {
                let cpu = item.parse::<u32>()?;
                (cpu, cpu)
            }
        };
        ensure!(first <= last && last <= MAX_CPU_ID, "invalid CPU range");
        cpus.extend(first..=last);
    }
    Ok(cpus)
}

pub fn parse_cpu_mask(text: &str) -> Result<BTreeSet<u32>> {
    ensure!(
        !text.is_empty() && text.len() <= 2303,
        "invalid CPU mask size"
    );
    let mut cpus = BTreeSet::new();
    let words: Vec<_> = text.split(',').collect();
    ensure!(words.len() <= 256, "CPU mask exceeds CPU limit");
    for (word_index, word) in words.iter().rev().enumerate() {
        ensure!(
            !word.is_empty() && word.len() <= 8 && word.bytes().all(|b| b.is_ascii_hexdigit()),
            "CPU mask requires comma-separated hexadecimal words"
        );
        let bits = u32::from_str_radix(word, 16)?;
        for bit in 0..32 {
            if bits & (1 << bit) != 0 {
                cpus.insert(word_index as u32 * 32 + bit);
            }
        }
    }
    Ok(cpus)
}

pub fn cpu_mask(cpus: &BTreeSet<u32>) -> String {
    let Some(max) = cpus.last() else {
        return "0".into();
    };
    let mut words = vec![0u32; (*max / 32 + 1) as usize];
    for cpu in cpus {
        words[(*cpu / 32) as usize] |= 1 << (*cpu % 32);
    }
    let mut words = words.iter().rev();
    let mut result = format!("{:x}", words.next().unwrap());
    for word in words {
        result.push_str(&format!(",{word:08x}"));
    }
    result
}

pub fn rps_target(key: &str) -> Result<(&str, &str)> {
    let (interface, queue) = key
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("RPS key must be interface/rx-N"))?;
    let number = queue
        .strip_prefix("rx-")
        .ok_or_else(|| anyhow::anyhow!("RPS target must be an RX queue"))?;
    let index: u32 = number.parse()?;
    ensure!(
        crate::valid_interface_name(interface) && index <= 4095 && index.to_string() == number,
        "invalid RPS interface/queue"
    );
    Ok((interface, queue))
}

pub fn validate_rps(values: &std::collections::BTreeMap<String, String>) -> Result<()> {
    ensure!(values.len() <= 64, "at most 64 RPS queue settings");
    for (key, mask) in values {
        rps_target(key)?;
        ensure!(
            cpu_mask(&parse_cpu_mask(mask)?) == *mask,
            "RPS mask must be canonical lowercase hexadecimal (zero disables RPS)"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rps_masks_lists_and_queue_names_are_bounded_and_canonical() {
        let cpus = parse_cpu_list("0-2,32,63-64").unwrap();
        assert_eq!(cpu_mask(&cpus), "1,80000001,00000007");
        assert_eq!(parse_cpu_mask("00000001,80000001,00000007").unwrap(), cpus);
        assert_eq!(cpu_mask(&parse_cpu_mask("00").unwrap()), "0");
        for value in ["8192", "2-1", "0-", "0,,1", "0-8192"] {
            assert!(parse_cpu_list(value).is_err(), "{value}");
        }
        for value in ["", "-1", "0x1", "1,", "100000000"] {
            assert!(parse_cpu_mask(value).is_err(), "{value}");
        }
        for key in [
            "../rx-0",
            "eno1/tx-0",
            "eno1/rx-00",
            "eno1/rx-4096",
            "eno1/rx-0/x",
        ] {
            assert!(rps_target(key).is_err(), "{key}");
        }
        for mask in ["00", "A", "00000001", "0,00000001"] {
            assert!(validate_rps(&[("eno1/rx-0".into(), mask.into())].into()).is_err());
        }
        validate_rps(&[("eno1/rx-0".into(), "1,00000000".into())].into()).unwrap();
        let highest = parse_cpu_list("8191").unwrap();
        assert_eq!(cpu_mask(&highest).split(',').count(), 256);
        assert_eq!(parse_cpu_mask(&cpu_mask(&highest)).unwrap(), highest);
        assert!(parse_cpu_mask(&vec!["0"; 257].join(",")).is_err());
        let mut settings: std::collections::BTreeMap<_, _> = (0..64)
            .map(|queue| (format!("eno1/rx-{queue}"), "0".into()))
            .collect();
        validate_rps(&settings).unwrap();
        settings.insert("eno1/rx-64".into(), "0".into());
        assert!(validate_rps(&settings).is_err());
    }
}
