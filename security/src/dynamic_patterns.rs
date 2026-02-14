// Dynamic Pattern Rotation Module
// Rotates protocol signatures, TCP parameters, and connection patterns
// to evade fingerprinting-based DPI systems and AI-based detection

use rand::Rng;
use rand::seq::SliceRandom;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// TCP/IP layer session parameters
#[derive(Clone, Debug)]
pub struct SessionParameters {
    pub tcp_window_size: u16,
    pub tcp_mss: u16,
    pub ttl: u8,
    pub initial_rtt_ms: u32,
    pub packet_timing_variance: u32,
}

/// Hourly rotation patterns for signature evasion
#[derive(Clone, Debug)]
pub struct HourlyPattern {
    pub pattern_id: String,
    pub hour: u32,
    pub tcp_flags_preset: u8,
    pub initial_sequence_offset: u32,
    pub urg_pointer_enabled: bool,
}

/// Per-session connection parameters
#[derive(Clone, Debug)]
pub struct SessionState {
    pub session_id: String,
    pub created_at: Instant,
    pub parameters: SessionParameters,
    pub last_rotation: Instant,
    pub rotation_count: u32,
    pub pattern_profile: String,
}

/// Configuration for pattern rotation behavior
#[derive(Clone, Debug)]
pub struct PatternRotationConfig {
    pub rotation_interval_hours: u32,
    pub enable_hourly_patterns: bool,
    pub randomize_tcp_window: bool,
    pub randomize_ttl: bool,
    pub randomize_packet_timing: bool,
    pub session_level_variation: bool,
    pub min_tcp_window: u16,
    pub max_tcp_window: u16,
    pub min_ttl: u8,
    pub max_ttl: u8,
    pub min_rtt_ms: u32,
    pub max_rtt_ms: u32,
}

impl Default for PatternRotationConfig {
    fn default() -> Self {
        PatternRotationConfig {
            rotation_interval_hours: 1,
            enable_hourly_patterns: true,
            randomize_tcp_window: true,
            randomize_ttl: true,
            randomize_packet_timing: true,
            session_level_variation: true,
            min_tcp_window: 1024,
            max_tcp_window: 65535,
            min_ttl: 32,
            max_ttl: 128,
            min_rtt_ms: 10,
            max_rtt_ms: 500,
        }
    }
}

/// Dynamic pattern rotation engine
pub struct PatternRotator {
    config: PatternRotationConfig,
    sessions: Mutex<HashMap<String, SessionState>>,
    last_hourly_pattern: Mutex<HourlyPattern>,
}

impl PatternRotator {
    /// Create a new pattern rotator with default configuration
    pub fn new() -> Self {
        PatternRotator {
            config: PatternRotationConfig::default(),
            sessions: Mutex::new(HashMap::new()),
            last_hourly_pattern: Mutex::new(PatternRotator::generate_hourly_pattern()),
        }
    }

    /// Create a new pattern rotator with custom configuration
    pub fn with_config(config: PatternRotationConfig) -> Self {
        PatternRotator {
            config,
            sessions: Mutex::new(HashMap::new()),
            last_hourly_pattern: Mutex::new(PatternRotator::generate_hourly_pattern()),
        }
    }

    /// Generate random TCP window size
    fn generate_tcp_window(&self) -> u16 {
        let mut rng = rand::thread_rng();
        if self.config.randomize_tcp_window {
            rng.gen_range(self.config.min_tcp_window..=self.config.max_tcp_window)
        } else {
            65535
        }
    }

    /// Generate random TTL (Time To Live) value
    fn generate_ttl(&self) -> u8 {
        let mut rng = rand::thread_rng();
        if self.config.randomize_ttl {
            rng.gen_range(self.config.min_ttl..=self.config.max_ttl)
        } else {
            64
        }
    }

    /// Generate random packet timing variance
    fn generate_packet_timing_variance(&self) -> u32 {
        let mut rng = rand::thread_rng();
        if self.config.randomize_packet_timing {
            rng.gen_range(0..=50) // 0-50ms variance
        } else {
            0
        }
    }

    /// Generate random initial RTT (Round Trip Time)
    fn generate_initial_rtt(&self) -> u32 {
        let mut rng = rand::thread_rng();
        rng.gen_range(self.config.min_rtt_ms..=self.config.max_rtt_ms)
    }

    /// Generate random TCP MSS (Maximum Segment Size)
    fn generate_tcp_mss(&self) -> u16 {
        let mut rng = rand::thread_rng();
        // Common MSS values: 512, 1024, 1460, 1480
        let mss_options = [512u16, 768, 1024, 1256, 1380, 1460, 1480];
        *mss_options.choose(&mut rng).unwrap_or(&1460)
    }

    /// Generate hourly pattern for signature rotation
    fn generate_hourly_pattern() -> HourlyPattern {
        let mut rng = rand::thread_rng();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let hour = (now.as_secs() / 3600) as u32;

        HourlyPattern {
            pattern_id: format!("pattern_{:08x}", hour),
            hour,
            tcp_flags_preset: rng.gen_range(0..=255),
            initial_sequence_offset: rng.gen::<u32>(),
            urg_pointer_enabled: rng.gen_bool(0.2),
        }
    }

    /// Get or create session parameters
    pub fn get_session_parameters(&self, session_id: &str) -> SessionParameters {
        let mut sessions = self.sessions.lock().unwrap();

        if let Some(session) = sessions.get(session_id) {
            // Return existing session parameters
            return session.parameters.clone();
        }

        // Create new session with random parameters
        let params = SessionParameters {
            tcp_window_size: self.generate_tcp_window(),
            tcp_mss: self.generate_tcp_mss(),
            ttl: self.generate_ttl(),
            initial_rtt_ms: self.generate_initial_rtt(),
            packet_timing_variance: self.generate_packet_timing_variance(),
        };

        let pattern_profile = self.get_current_hourly_pattern().pattern_id.clone();

        let session = SessionState {
            session_id: session_id.to_string(),
            created_at: Instant::now(),
            parameters: params.clone(),
            last_rotation: Instant::now(),
            rotation_count: 0,
            pattern_profile,
        };

        sessions.insert(session_id.to_string(), session);
        params
    }

    /// Update session to use new parameters (rotation)
    pub fn rotate_session_parameters(
        &self,
        session_id: &str,
    ) -> Option<SessionParameters> {
        let mut sessions = self.sessions.lock().unwrap();

        if let Some(session) = sessions.get_mut(session_id) {
            let new_params = SessionParameters {
                tcp_window_size: self.generate_tcp_window(),
                tcp_mss: self.generate_tcp_mss(),
                ttl: self.generate_ttl(),
                initial_rtt_ms: self.generate_initial_rtt(),
                packet_timing_variance: self.generate_packet_timing_variance(),
            };

            session.parameters = new_params.clone();
            session.last_rotation = Instant::now();
            session.rotation_count += 1;
            session.pattern_profile = self.get_current_hourly_pattern().pattern_id.clone();

            return Some(new_params);
        }

        None
    }

    /// Check if session should be rotated based on interval
    pub fn should_rotate_session(&self, session_id: &str) -> bool {
        let sessions = self.sessions.lock().unwrap();

        if let Some(session) = sessions.get(session_id) {
            let elapsed = session.last_rotation.elapsed();
            let rotation_duration =
                Duration::from_secs((self.config.rotation_interval_hours as u64) * 3600);
            return elapsed >= rotation_duration;
        }

        false
    }

    /// Get current hourly pattern (updated every hour)
    pub fn get_current_hourly_pattern(&self) -> HourlyPattern {
        let mut last_pattern = self.last_hourly_pattern.lock().unwrap();
        let new_pattern = PatternRotator::generate_hourly_pattern();

        if new_pattern.hour != last_pattern.hour {
            *last_pattern = new_pattern.clone();
        }

        last_pattern.clone()
    }

    /// Generate TCP option sequence for mimicking specific OS
    pub fn generate_tcp_options(&self, os_profile: &str) -> Vec<u8> {
        match os_profile {
            "windows" => {
                // Windows: MSS, Window Scale, SACK Permitted, Timestamp
                vec![
                    0x02, 0x04, 0x05, 0xb4, // MSS
                    0x01,                    // NOP
                    0x03, 0x03, 0x06,       // Window Scale
                    0x02, 0x02, 0x00,       // SACK Permitted
                ]
            }
            "linux" => {
                // Linux: MSS, SACK Permitted, Timestamp, Window Scale
                vec![
                    0x02, 0x04, 0x05, 0xb4, // MSS
                    0x04, 0x02, 0x00, 0x00, // SACK Permitted
                    0x08, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Timestamp
                    0x01,                    // NOP
                    0x03, 0x03, 0x07,       // Window Scale
                ]
            }
            "macos" => {
                // macOS: MSS, Window Scale, SACK Permitted, Timestamp
                vec![
                    0x02, 0x04, 0x05, 0xb4, // MSS
                    0x01,                    // NOP
                    0x03, 0x03, 0x05,       // Window Scale
                    0x04, 0x02, 0x00, 0x00, // SACK Permitted
                ]
            }
            _ => {
                // Generic
                vec![
                    0x02, 0x04, 0x05, 0xb4, // MSS
                    0x01,                    // NOP
                    0x03, 0x03, 0x06,       // Window Scale
                ]
            }
        }
    }

    /// Create signature randomization mask
    pub fn create_signature_mask(&self) -> SignatureMask {
        let pattern = self.get_current_hourly_pattern();
        SignatureMask {
            sequence_randomizer: pattern.initial_sequence_offset,
            packet_order_shuffle: pattern.tcp_flags_preset,
            timing_jitter: pattern.urg_pointer_enabled,
            payload_padding_ratio: Self::random_padding_ratio(),
        }
    }

    /// Get random padding ratio (0.0 - 0.3 means 0-30% padding)
    fn random_padding_ratio() -> f32 {
        let mut rng = rand::thread_rng();
        rng.gen_range(0.0..=0.3)
    }

    /// Clean up old sessions (older than 24 hours)
    pub fn cleanup_old_sessions(&self) {
        let mut sessions = self.sessions.lock().unwrap();
        let now = Instant::now();
        let session_timeout = Duration::from_secs(86400); // 24 hours

        sessions.retain(|_, session| now.duration_since(session.created_at) < session_timeout);
    }

    /// Get statistics about current rotation
    pub fn get_rotation_stats(&self) -> RotationStats {
        let sessions = self.sessions.lock().unwrap();
        let total_sessions = sessions.len();

        let total_rotations: u32 = sessions.values().map(|s| s.rotation_count).sum();
        let avg_rotations = if total_sessions > 0 {
            total_rotations as f32 / total_sessions as f32
        } else {
            0.0
        };

        RotationStats {
            total_sessions,
            total_rotations,
            avg_rotations_per_session: avg_rotations,
            current_pattern: self.get_current_hourly_pattern().pattern_id,
        }
    }
}

/// Signature randomization mask
#[derive(Clone, Debug)]
pub struct SignatureMask {
    pub sequence_randomizer: u32,
    pub packet_order_shuffle: u8,
    pub timing_jitter: bool,
    pub payload_padding_ratio: f32,
}

/// Statistics about pattern rotation
#[derive(Clone, Debug)]
pub struct RotationStats {
    pub total_sessions: usize,
    pub total_rotations: u32,
    pub avg_rotations_per_session: f32,
    pub current_pattern: String,
}

impl Default for PatternRotator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_tcp_window() {
        let rotator = PatternRotator::new();
        let window = rotator.generate_tcp_window();
        assert!(window >= rotator.config.min_tcp_window);
        assert!(window <= rotator.config.max_tcp_window);
    }

    #[test]
    fn test_generate_ttl() {
        let rotator = PatternRotator::new();
        let ttl = rotator.generate_ttl();
        assert!(ttl >= rotator.config.min_ttl);
        assert!(ttl <= rotator.config.max_ttl);
    }

    #[test]
    fn test_session_parameters() {
        let rotator = PatternRotator::new();
        let params = rotator.get_session_parameters("test-session");
        assert!(params.tcp_window_size > 0);
        assert!(params.ttl > 0);
    }

    #[test]
    fn test_session_rotation() {
        let rotator = PatternRotator::new();
        let session_id = "test-session";

        let params1 = rotator.get_session_parameters(session_id);
        let params2 = rotator.rotate_session_parameters(session_id).unwrap();

        // Parameters should be different (with very high probability)
        // Note: There's a small chance they could be the same by chance
        // but it's extremely unlikely
        assert_ne!(params1.tcp_window_size, params2.tcp_window_size);
    }

    #[test]
    fn test_hourly_pattern() {
        let rotator = PatternRotator::new();
        let pattern1 = rotator.get_current_hourly_pattern();
        let pattern2 = rotator.get_current_hourly_pattern();

        assert_eq!(pattern1.hour, pattern2.hour);
        assert_eq!(pattern1.pattern_id, pattern2.pattern_id);
    }

    #[test]
    fn test_tcp_options_generation() {
        let rotator = PatternRotator::new();

        let windows_opts = rotator.generate_tcp_options("windows");
        assert!(!windows_opts.is_empty());

        let linux_opts = rotator.generate_tcp_options("linux");
        assert!(!linux_opts.is_empty());

        let macos_opts = rotator.generate_tcp_options("macos");
        assert!(!macos_opts.is_empty());

        // Different OS should have different options (with high probability)
        assert_ne!(windows_opts, linux_opts);
    }

    #[test]
    fn test_signature_mask() {
        let rotator = PatternRotator::new();
        let mask1 = rotator.create_signature_mask();
        let mask2 = rotator.create_signature_mask();

        // Masks should exist
        assert!(mask1.payload_padding_ratio >= 0.0);
        assert!(mask1.payload_padding_ratio <= 0.3);
    }

    #[test]
    fn test_rotation_stats() {
        let rotator = PatternRotator::new();
        rotator.get_session_parameters("session-1");
        rotator.get_session_parameters("session-2");

        let stats = rotator.get_rotation_stats();
        assert_eq!(stats.total_sessions, 2);
        assert!(stats.avg_rotations_per_session >= 0.0);
    }

    #[test]
    fn test_cleanup_old_sessions() {
        let rotator = PatternRotator::new();
        rotator.get_session_parameters("session-1");

        let initial_stats = rotator.get_rotation_stats();
        assert!(initial_stats.total_sessions > 0);

        // Cleanup should be safe even if no sessions are old
        rotator.cleanup_old_sessions();
    }
}
