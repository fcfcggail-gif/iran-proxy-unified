//! Pattern rotation module for evasion of fingerprinting
//! Rotates protocol signatures and connection patterns to avoid being classified

use crate::error::{Error, Result};
use rand::Rng;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct PatternRotator {
    rotation_interval_hours: u32,
    last_rotation: u64,
    current_pattern: u32,
}

impl PatternRotator {
    pub fn new(rotation_interval_hours: u32) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        PatternRotator {
            rotation_interval_hours,
            last_rotation: now,
            current_pattern: Self::generate_pattern(),
        }
    }

    /// Rotate packet patterns based on time interval
    pub fn rotate_pattern(&self, data: &[u8]) -> Result<Vec<u8>> {
        // Check if rotation is needed
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let rotation_seconds = self.rotation_interval_hours as u64 * 3600;

        let should_rotate = (now - self.last_rotation) > rotation_seconds;

        if should_rotate {
            // Apply new pattern variations
            self.apply_pattern_variation(data)
        } else {
            Ok(self.apply_current_pattern(data))
        }
    }

    /// Reverse pattern rotation
    pub fn reverse_rotation(&self, data: &[u8]) -> Result<Vec<u8>> {
        // In a real implementation, this would reverse the pattern changes
        // For now, return the data as-is
        Ok(data.to_vec())
    }

    fn apply_pattern_variation(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut result = Vec::new();
        let mut rng = rand::thread_rng();

        // Vary packet order
        if data.len() > 100 {
            let chunk_size = rng.gen_range(10..50);
            for chunk in data.chunks(chunk_size) {
                result.extend_from_slice(chunk);
                // Insert random byte to vary pattern
                if rng.gen_bool(0.3) {
                    result.push(rng.gen());
                }
            }
        } else {
            result = data.to_vec();
        }

        Ok(result)
    }

    fn apply_current_pattern(&self, data: &[u8]) -> Vec<u8> {
        let mut result = data.to_vec();

        // Apply pattern transformations based on current_pattern
        // This is deterministic for the current interval
        let pattern_mod = self.current_pattern % 4;

        match pattern_mod {
            0 => {
                // Pattern 1: No transformation
                result
            }
            1 => {
                // Pattern 2: Xor with pattern byte
                for byte in &mut result {
                    *byte ^= (self.current_pattern % 256) as u8;
                }
                result
            }
            2 => {
                // Pattern 3: Reverse some chunks
                for chunk in result.chunks_mut(16) {
                    chunk.reverse();
                }
                result
            }
            _ => {
                // Pattern 4: Rotate bits
                for byte in &mut result {
                    *byte = byte.rotate_left(3);
                }
                result
            }
        }
    }

    fn generate_pattern() -> u32 {
        let mut rng = rand::thread_rng();
        rng.gen()
    }

    /// Get current pattern ID
    pub fn current_pattern_id(&self) -> u32 {
        self.current_pattern
    }

    /// Vary TLS handshake characteristics
    pub fn vary_tls_handshake(&self, handshake_data: &[u8]) -> Result<Vec<u8>> {
        let mut result = handshake_data.to_vec();
        let mut rng = rand::thread_rng();

        // Randomize cipher suite order
        if result.len() > 64 {
            let cipher_section_start = rng.gen_range(20..40);
            let cipher_section_end = rng.gen_range(cipher_section_start + 10..100);

            if cipher_section_end <= result.len() {
                let mut cipher_section = result[cipher_section_start..cipher_section_end].to_vec();
                cipher_section.reverse();
                result.splice(cipher_section_start..cipher_section_end, cipher_section);
            }
        }

        Ok(result)
    }

    /// Randomize connection parameters
    pub fn randomize_connection_params(&self) -> ConnectionParams {
        let mut rng = rand::thread_rng();

        ConnectionParams {
            tcp_window_size: rng.gen_range(1024..65535),
            tcp_mss: rng.gen_range(512..1460),
            ttl: rng.gen_range(32..128),
            timeout_ms: rng.gen_range(1000..10000),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConnectionParams {
    pub tcp_window_size: u16,
    pub tcp_mss: u16,
    pub ttl: u8,
    pub timeout_ms: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern_rotator_creation() {
        let rotator = PatternRotator::new(1);
        assert!(rotator.current_pattern_id() > 0);
    }

    #[test]
    fn test_rotate_pattern() {
        let rotator = PatternRotator::new(24);
        let test_data = b"test pattern data";
        let result = rotator.rotate_pattern(test_data).unwrap();
        assert!(!result.is_empty());
    }

    #[test]
    fn test_vary_tls_handshake() {
        let rotator = PatternRotator::new(1);
        let handshake = vec![0; 100];
        let result = rotator.vary_tls_handshake(&handshake).unwrap();
        assert_eq!(result.len(), handshake.len());
    }
}
