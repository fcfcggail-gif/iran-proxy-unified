//! Traffic obfuscation module for DPI evasion
//! Implements various obfuscation techniques to make proxy traffic look like legitimate HTTPS

use crate::error::{Error, Result};
use rand::Rng;

pub struct Obfuscator {
    // Add HTTP headers that make traffic look legitimate
    common_headers: Vec<&'static str>,
}

impl Obfuscator {
    pub fn new() -> Self {
        Obfuscator {
            common_headers: vec![
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                "Accept: text/html,application/xhtml+xml,application/xml;q=0.9",
                "Accept-Language: en-US,en;q=0.9",
                "Accept-Encoding: gzip, deflate, br",
                "Cache-Control: max-age=0",
                "Upgrade-Insecure-Requests: 1",
            ],
        }
    }

    /// Obfuscate data to look like HTTP/HTTPS traffic
    pub fn obfuscate(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut result = Vec::new();

        // Add fake HTTP headers
        result.extend_from_slice(b"GET / HTTP/1.1\r\n");
        result.extend_from_slice(b"Host: example.com\r\n");

        // Add random headers
        let mut rng = rand::thread_rng();
        let num_headers = rng.gen_range(2..4);

        for i in 0..num_headers {
            if i < self.common_headers.len() {
                result.extend_from_slice(self.common_headers[i].as_bytes());
                result.extend_from_slice(b"\r\n");
            }
        }

        result.extend_from_slice(b"\r\n");

        // Add actual data
        result.extend_from_slice(data);

        // Add random padding
        let padding_size = rng.gen_range(0..256);
        let padding: Vec<u8> = (0..padding_size).map(|_| rng.gen()).collect();
        result.extend(padding);

        Ok(result)
    }

    /// Reverse obfuscation to extract original data
    pub fn deobfuscate(&self, data: &[u8]) -> Result<Vec<u8>> {
        // Try to find the separator between headers and body
        let separator = b"\r\n\r\n";

        let mut idx = 0;
        while idx + separator.len() <= data.len() {
            if &data[idx..idx + separator.len()] == separator {
                // Found headers-body separator
                let body_start = idx + separator.len();

                // Original data is somewhere in the body
                // In a real implementation, we'd need a length prefix
                // For now, return the entire body
                return Ok(data[body_start..].to_vec());
            }
            idx += 1;
        }

        // If no separator found, return original data
        Ok(data.to_vec())
    }

    /// Add noise/padding to avoid pattern matching
    pub fn add_noise(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut result = data.to_vec();
        let mut rng = rand::thread_rng();

        // Add random noise bytes
        let noise_amount = rng.gen_range(10..100);
        for _ in 0..noise_amount {
            result.push(rng.gen());
        }

        Ok(result)
    }

    /// Randomize packet size to evade DPI signatures
    pub fn randomize_size(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut rng = rand::thread_rng();

        // Fragment or pad data to random sizes
        if data.len() > 512 {
            // For large data, fragment it
            let chunk_size = rng.gen_range(100..512);
            return Ok(data[0..std::cmp::min(chunk_size, data.len())].to_vec());
        } else {
            // For small data, add padding
            let desired_size = rng.gen_range(data.len()..1024);
            let mut result = data.to_vec();
            let padding_needed = desired_size - data.len();
            for _ in 0..padding_needed {
                result.push(rng.gen());
            }
            Ok(result)
        }
    }
}

impl Default for Obfuscator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_obfuscate() {
        let obfuscator = Obfuscator::new();
        let test_data = b"test";
        let result = obfuscator.obfuscate(test_data).unwrap();
        assert!(result.len() > test_data.len());
        assert!(result.windows(4).any(|w| w == b"GET "));
    }

    #[test]
    fn test_add_noise() {
        let obfuscator = Obfuscator::new();
        let test_data = b"test";
        let result = obfuscator.add_noise(test_data).unwrap();
        assert!(result.len() >= test_data.len());
    }
}
