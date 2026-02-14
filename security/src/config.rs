//! Configuration module for security settings
//! Loads and manages configuration for DPI bypass and evasion strategies

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecuritySettings {
    pub obfuscation: ObfuscationConfig,
    pub pattern_rotation: PatternRotationConfig,
    pub dpi_bypass: DPIBypassConfig,
    pub detection_evasion: DetectionEvadingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObfuscationConfig {
    pub enabled: bool,
    pub http_headers_enabled: bool,
    pub noise_injection_enabled: bool,
    pub packet_randomization: bool,
    pub min_packet_size: usize,
    pub max_packet_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternRotationConfig {
    pub enabled: bool,
    pub rotation_interval_hours: u32,
    pub tls_fingerprint_randomization: bool,
    pub connection_param_randomization: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DPIBypassConfig {
    pub enabled: bool,
    pub fragmentation_enabled: bool,
    pub tls_evasion_enabled: bool,
    pub dns_tunneling_enabled: bool,
    pub mirrored_traffic_enabled: bool,
    pub timing_randomization_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionEvadingConfig {
    pub enabled: bool,
    pub feature_scrambling_enabled: bool,
    pub behavior_randomization_enabled: bool,
    pub decoy_traffic_enabled: bool,
    pub decoy_traffic_percentage: u8,
    pub max_adaptation_level: u8,
    pub ensemble_approach_enabled: bool,
}

impl Default for SecuritySettings {
    fn default() -> Self {
        SecuritySettings {
            obfuscation: ObfuscationConfig::default(),
            pattern_rotation: PatternRotationConfig::default(),
            dpi_bypass: DPIBypassConfig::default(),
            detection_evasion: DetectionEvadingConfig::default(),
        }
    }
}

impl Default for ObfuscationConfig {
    fn default() -> Self {
        ObfuscationConfig {
            enabled: true,
            http_headers_enabled: true,
            noise_injection_enabled: true,
            packet_randomization: true,
            min_packet_size: 100,
            max_packet_size: 2048,
        }
    }
}

impl Default for PatternRotationConfig {
    fn default() -> Self {
        PatternRotationConfig {
            enabled: true,
            rotation_interval_hours: 1,
            tls_fingerprint_randomization: true,
            connection_param_randomization: true,
        }
    }
}

impl Default for DPIBypassConfig {
    fn default() -> Self {
        DPIBypassConfig {
            enabled: true,
            fragmentation_enabled: true,
            tls_evasion_enabled: true,
            dns_tunneling_enabled: true,
            mirrored_traffic_enabled: false,
            timing_randomization_enabled: true,
        }
    }
}

impl Default for DetectionEvadingConfig {
    fn default() -> Self {
        DetectionEvadingConfig {
            enabled: true,
            feature_scrambling_enabled: true,
            behavior_randomization_enabled: true,
            decoy_traffic_enabled: true,
            decoy_traffic_percentage: 20,
            max_adaptation_level: 5,
            ensemble_approach_enabled: true,
        }
    }
}

impl SecuritySettings {
    /// Load configuration from JSON
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Save configuration to JSON
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Load configuration from YAML (requires yaml feature)
    pub fn from_yaml(yaml: &str) -> Result<Self, serde_yaml::Error> {
        serde_yaml::from_str(yaml)
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<(), String> {
        if self.obfuscation.min_packet_size >= self.obfuscation.max_packet_size {
            return Err("min_packet_size must be less than max_packet_size".to_string());
        }

        if self.detection_evasion.decoy_traffic_percentage > 100 {
            return Err("decoy_traffic_percentage must be <= 100".to_string());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = SecuritySettings::default();
        assert!(config.obfuscation.enabled);
        assert!(config.pattern_rotation.enabled);
    }

    #[test]
    fn test_config_validation() {
        let config = SecuritySettings::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_json() {
        let config = SecuritySettings::default();
        let json = config.to_json().unwrap();
        let loaded = SecuritySettings::from_json(&json).unwrap();
        assert_eq!(loaded.obfuscation.enabled, config.obfuscation.enabled);
    }
}
