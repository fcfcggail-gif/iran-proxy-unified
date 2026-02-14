//! Iran Proxy Security Module
//!
//! Advanced DPI bypass and anti-detection module for Iranian network environment
//! Implements pattern rotation, traffic obfuscation, and AI/ML detection evasion

pub mod obfuscation;
pub mod pattern_rotation;
pub mod dpi_bypass;
pub mod detection_evasion;
pub mod config;
pub mod error;

pub use error::{Error, Result};

#[derive(Debug, Clone)]
pub struct SecurityConfig {
    pub enforce_obfuscation: bool,
    pub pattern_rotation_interval_hours: u32,
    pub max_adaptation_level: u8,
    pub decoy_traffic_percentage: u8,
    pub enable_ai_evasion: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        SecurityConfig {
            enforce_obfuscation: true,
            pattern_rotation_interval_hours: 1,
            max_adaptation_level: 5,
            decoy_traffic_percentage: 20,
            enable_ai_evasion: true,
        }
    }
}

/// Main security processor for proxy traffic
pub struct SecurityProcessor {
    config: SecurityConfig,
    obfuscator: obfuscation::Obfuscator,
    pattern_rotator: pattern_rotation::PatternRotator,
    dpi_bypasser: dpi_bypass::DPIBypass,
    detection_evader: detection_evasion::DetectionEvader,
}

impl SecurityProcessor {
    /// Create a new security processor with default configuration
    pub fn new() -> Result<Self> {
        Self::with_config(SecurityConfig::default())
    }

    /// Create a new security processor with custom configuration
    pub fn with_config(config: SecurityConfig) -> Result<Self> {
        Ok(SecurityProcessor {
            config,
            obfuscator: obfuscation::Obfuscator::new(),
            pattern_rotator: pattern_rotation::PatternRotator::new(
                config.pattern_rotation_interval_hours,
            ),
            dpi_bypasser: dpi_bypass::DPIBypass::new(),
            detection_evader: detection_evasion::DetectionEvader::new(
                config.max_adaptation_level,
            ),
        })
    }

    /// Process outgoing traffic with security enhancements
    pub fn process_outgoing(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut processed = data.to_vec();

        // Apply obfuscation
        if self.config.enforce_obfuscation {
            processed = self.obfuscator.obfuscate(&processed)?;
        }

        // Apply pattern rotation
        processed = self.pattern_rotator.rotate_pattern(&processed)?;

        // Apply DPI bypass techniques
        processed = self.dpi_bypasser.apply_evasion(&processed)?;

        // Apply detection evasion if enabled
        if self.config.enable_ai_evasion {
            processed = self.detection_evader.evade_detection(&processed)?;
        }

        Ok(processed)
    }

    /// Process incoming traffic
    pub fn process_incoming(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut processed = data.to_vec();

        // Reverse detection evasion
        if self.config.enable_ai_evasion {
            processed = self.detection_evader.reverse_evasion(&processed)?;
        }

        // Reverse DPI bypass
        processed = self.dpi_bypasser.reverse_evasion(&processed)?;

        // Reverse pattern rotation
        processed = self.pattern_rotator.reverse_rotation(&processed)?;

        // Reverse obfuscation
        if self.config.enforce_obfuscation {
            processed = self.obfuscator.deobfuscate(&processed)?;
        }

        Ok(processed)
    }

    /// Get configuration
    pub fn config(&self) -> &SecurityConfig {
        &self.config
    }

    /// Update configuration dynamically
    pub fn update_config(&mut self, config: SecurityConfig) -> Result<()> {
        self.config = config;
        self.pattern_rotator = pattern_rotation::PatternRotator::new(
            config.pattern_rotation_interval_hours,
        );
        self.detection_evader = detection_evasion::DetectionEvader::new(
            config.max_adaptation_level,
        );
        Ok(())
    }
}

impl Default for SecurityProcessor {
    fn default() -> Self {
        Self::new().expect("Failed to create default SecurityProcessor")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_processor_creation() {
        let processor = SecurityProcessor::new().unwrap();
        assert!(processor.config.enforce_obfuscation);
    }

    #[test]
    fn test_process_data() {
        let processor = SecurityProcessor::new().unwrap();
        let test_data = b"test proxy data";
        let result = processor.process_outgoing(test_data);
        assert!(result.is_ok());
    }
}
