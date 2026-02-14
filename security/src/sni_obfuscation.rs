// SNI (Server Name Indication) Obfuscation Module
// Randomizes SNI values in TLS ClientHello to evade DPI-based SNI filtering
// Includes domain rotation, capitalization randomization, and fingerprint matching

use rand::seq::SliceRandom;
use rand::Rng;

/// Comprehensive pool of legitimate global domains for SNI rotation
const FAKE_SNI_POOL: &[&str] = &[
    // Global platforms
    "google.com",
    "youtube.com",
    "facebook.com",
    "amazon.com",
    "apple.com",
    "microsoft.com",
    "netflix.com",
    "instagram.com",
    "twitter.com",
    "reddit.com",
    // Search engines
    "bing.com",
    "duckduckgo.com",
    "wikipedia.org",
    // Social networks
    "tiktok.com",
    "linkedin.com",
    "tumblr.com",
    "pinterest.com",
    "telegram.org",
    "whatsapp.com",
    // Video platforms
    "vimeo.com",
    "dailymotion.com",
    "twitch.tv",
    // News sites
    "bbc.com",
    "cnn.com",
    "nytimes.com",
    "theguardian.com",
    "reuters.com",
    "apnews.com",
    // Shopping
    "ebay.com",
    "aliexpress.com",
    "shopify.com",
    // Cloud/Dev services
    "github.com",
    "gitlab.com",
    "heroku.com",
    "aws.amazon.com",
    "storage.googleapis.com",
    "azure.microsoft.com",
    // Messaging
    "slack.com",
    "discord.com",
    "messenger.com",
    // Streaming
    "hulu.com",
    "disneyplus.com",
    "primevideo.com",
    "spotify.com",
    // Productivity
    "office.com",
    "docs.google.com",
    "notion.so",
    "figma.com",
    // Web frameworks
    "wordpress.com",
    "blogspot.com",
    "medium.com",
    // CDN/DNS
    "cloudflare.com",
    "1.1.1.1.cloudflare-dns.com",
    "quad9.net",
];

/// Browser User-Agent styles for fingerprint matching
#[derive(Clone, Copy, Debug)]
pub enum BrowserFingerprint {
    Chrome,
    Safari,
    Firefox,
    Edge,
    Opera,
}

/// SNI obfuscation strategies
#[derive(Clone, Copy, Debug)]
pub enum ObfuscationStrategy {
    /// Simple domain rotation from fake pool
    RandomDomain,
    /// Randomize capitalization (Example.Com, EXAMPLE.COM)
    CapitalizationRandomization,
    /// Insert padding in SNI extension
    SNIPadding,
    /// Combine multiple strategies
    Combined,
}

/// Configuration for SNI obfuscation
#[derive(Clone, Debug)]
pub struct SNIObfuscationConfig {
    pub strategy: ObfuscationStrategy,
    pub use_fake_sni: bool,
    pub fake_sni_pool_size: usize,
    pub randomize_capitalization: bool,
    pub add_padding: bool,
    pub max_padding_bytes: usize,
    pub browser_fingerprint: Option<BrowserFingerprint>,
}

impl Default for SNIObfuscationConfig {
    fn default() -> Self {
        SNIObfuscationConfig {
            strategy: ObfuscationStrategy::Combined,
            use_fake_sni: true,
            fake_sni_pool_size: FAKE_SNI_POOL.len(),
            randomize_capitalization: true,
            add_padding: true,
            max_padding_bytes: 50,
            browser_fingerprint: Some(BrowserFingerprint::Chrome),
        }
    }
}

/// SNI obfuscation engine
pub struct SNIObfuscator {
    config: SNIObfuscationConfig,
}

impl SNIObfuscator {
    /// Create a new SNI obfuscator with default configuration
    pub fn new() -> Self {
        SNIObfuscator {
            config: SNIObfuscationConfig::default(),
        }
    }

    /// Create a new SNI obfuscator with custom configuration
    pub fn with_config(config: SNIObfuscationConfig) -> Self {
        SNIObfuscator { config }
    }

    /// Generate a random domain from the fake SNI pool
    fn get_random_fake_sni(&self) -> String {
        let mut rng = rand::thread_rng();
        FAKE_SNI_POOL
            .choose(&mut rng)
            .unwrap_or(&"google.com")
            .to_string()
    }

    /// Randomize capitalization of a domain name
    fn randomize_capitalization(&self, domain: &str) -> String {
        let mut rng = rand::thread_rng();
        domain
            .chars()
            .map(|c| {
                if c.is_alphabetic() && rng.gen_bool(0.5) {
                    c.to_uppercase().to_string()
                } else {
                    c.to_lowercase().to_string()
                }
            })
            .collect()
    }

    /// Create a valid capitalization pattern matching browser fingerprint
    fn apply_browser_capitalization(&self, domain: &str) -> String {
        match self.config.browser_fingerprint {
            Some(BrowserFingerprint::Chrome) | Some(BrowserFingerprint::Edge) => {
                // Chrome/Edge: lowercase SNI
                domain.to_lowercase()
            }
            Some(BrowserFingerprint::Safari) => {
                // Safari: sometimes title case
                let mut rng = rand::thread_rng();
                if rng.gen_bool(0.3) {
                    Self::title_case(domain)
                } else {
                    domain.to_lowercase()
                }
            }
            Some(BrowserFingerprint::Firefox) => {
                // Firefox: lowercase SNI
                domain.to_lowercase()
            }
            Some(BrowserFingerprint::Opera) => {
                // Opera: lowercase SNI
                domain.to_lowercase()
            }
            None => domain.to_lowercase(),
        }
    }

    /// Convert string to title case
    fn title_case(s: &str) -> String {
        let mut result = String::new();
        let mut capitalize_next = true;

        for c in s.chars() {
            if c == '.' {
                result.push(c);
                capitalize_next = true;
            } else if capitalize_next && c.is_alphabetic() {
                result.push_str(&c.to_uppercase().to_string());
                capitalize_next = false;
            } else {
                result.push(c);
            }
        }

        result
    }

    /// Obfuscate SNI value
    pub fn obfuscate_sni(&self, original_sni: &str) -> String {
        match self.config.strategy {
            ObfuscationStrategy::RandomDomain => self.get_random_fake_sni(),
            ObfuscationStrategy::CapitalizationRandomization => {
                if self.config.randomize_capitalization {
                    self.randomize_capitalization(original_sni)
                } else {
                    original_sni.to_string()
                }
            }
            ObfuscationStrategy::SNIPadding => {
                // Keep original SNI but with capitalization
                self.apply_browser_capitalization(original_sni)
            }
            ObfuscationStrategy::Combined => {
                let mut rng = rand::thread_rng();

                // 40% chance to use fake SNI, 60% to modify original
                if rng.gen_bool(0.4) && self.config.use_fake_sni {
                    self.get_random_fake_sni()
                } else {
                    let sni = if rng.gen_bool(0.5) && self.config.randomize_capitalization {
                        self.randomize_capitalization(original_sni)
                    } else {
                        self.apply_browser_capitalization(original_sni)
                    };
                    sni
                }
            }
        }
    }

    /// Get a diverse set of SNI values for rotation
    pub fn get_rotation_set(&self, count: usize) -> Vec<String> {
        let mut rng = rand::thread_rng();
        let mut result = Vec::new();

        for _ in 0..count {
            result.push(self.obfuscate_sni(
                FAKE_SNI_POOL.choose(&mut rng).unwrap_or(&"google.com"),
            ));
        }

        // Remove duplicates while preserving some variety
        result.sort();
        result.dedup();
        result.truncate(count);

        result
    }

    /// Create SNI extension data with obfuscation
    /// This generates the raw TLS extension bytes
    pub fn create_sni_extension(&self, original_sni: &str) -> Vec<u8> {
        let obfuscated_sni = self.obfuscate_sni(original_sni);
        self.build_sni_extension_bytes(&obfuscated_sni)
    }

    /// Build SNI extension bytes for TLS ClientHello
    fn build_sni_extension_bytes(&self, sni: &str) -> Vec<u8> {
        // TLS SNI Extension format:
        // - Extension Type: 0x00 0x00 (server_name)
        // - Extension Length: 2 bytes
        // - Server Name List Length: 2 bytes
        // - Name Type: 1 byte (0x00 for host_name)
        // - Name Length: 2 bytes
        // - Name Data: variable

        let mut extension = Vec::new();

        // Extension type (server_name = 0)
        extension.extend_from_slice(&[0x00, 0x00]);

        // Build name data
        let name_data = vec![0x00]; // Name type: host_name
        let sni_bytes = sni.as_bytes();
        extension.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
        extension.extend_from_slice(sni_bytes);

        // Server Name List
        let mut list = Vec::new();
        list.extend_from_slice(&(name_data.len() as u16).to_be_bytes());
        list.extend_from_slice(&name_data);

        // Extension length
        let extension_length = list.len();
        extension.extend_from_slice(&(extension_length as u16).to_be_bytes());
        extension.extend_from_slice(&list);

        extension
    }

    /// Check if SNI looks suspicious for DPI systems
    pub fn is_suspicious_sni(sni: &str) -> bool {
        // Empty or very short SNI
        if sni.len() < 3 {
            return true;
        }

        // SNI with unusual patterns (all uppercase, all numeric, etc)
        let upper_count = sni.chars().filter(|c| c.is_uppercase()).count();
        let lower_count = sni.chars().filter(|c| c.is_lowercase()).count();
        let digit_count = sni.chars().filter(|c| c.is_numeric()).count();

        // All uppercase is suspicious
        if upper_count > lower_count && lower_count == 0 {
            return true;
        }

        // Too many digits in SNI
        if digit_count as f32 / sni.len() as f32 > 0.4 {
            return true;
        }

        false
    }

    /// Get statistics about SNI obfuscation
    pub fn get_stats(&self, original_sni: &str, obfuscated_sni: &str) -> SNIObfuscationStats {
        SNIObfuscationStats {
            original_sni: original_sni.to_string(),
            obfuscated_sni: obfuscated_sni.to_string(),
            original_length: original_sni.len(),
            obfuscated_length: obfuscated_sni.len(),
            is_fake_domain: !obfuscated_sni.eq_ignore_ascii_case(original_sni),
            capitalization_changed: original_sni != obfuscated_sni,
            is_suspicious: Self::is_suspicious_sni(original_sni),
        }
    }
}

/// Statistics about SNI obfuscation
#[derive(Clone, Debug)]
pub struct SNIObfuscationStats {
    pub original_sni: String,
    pub obfuscated_sni: String,
    pub original_length: usize,
    pub obfuscated_length: usize,
    pub is_fake_domain: bool,
    pub capitalization_changed: bool,
    pub is_suspicious: bool,
}

impl Default for SNIObfuscator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_random_fake_sni() {
        let obfuscator = SNIObfuscator::new();
        let sni = obfuscator.get_random_fake_sni();
        assert!(!sni.is_empty());
        assert!(FAKE_SNI_POOL.contains(&sni.as_str()));
    }

    #[test]
    fn test_randomize_capitalization() {
        let obfuscator = SNIObfuscator::new();
        let original = "example.com";
        let obfuscated = obfuscator.randomize_capitalization(original);
        // Should have same length
        assert_eq!(original.len(), obfuscated.len());
        // Should contain lowercase too
        assert!(obfuscated.chars().any(|c| c.is_lowercase()));
    }

    #[test]
    fn test_obfuscate_sni_combined() {
        let config = SNIObfuscationConfig {
            strategy: ObfuscationStrategy::Combined,
            use_fake_sni: true,
            ..Default::default()
        };
        let obfuscator = SNIObfuscator::with_config(config);
        let obfuscated = obfuscator.obfuscate_sni("example.com");
        assert!(!obfuscated.is_empty());
    }

    #[test]
    fn test_rotation_set() {
        let obfuscator = SNIObfuscator::new();
        let rotation_set = obfuscator.get_rotation_set(5);
        assert!(!rotation_set.is_empty());
        assert!(rotation_set.len() <= 5);
    }

    #[test]
    fn test_sni_extension_format() {
        let obfuscator = SNIObfuscator::new();
        let extension = obfuscator.create_sni_extension("example.com");
        // Should have valid format
        assert!(extension.len() > 6); // At least header + data
    }

    #[test]
    fn test_is_suspicious_sni() {
        assert!(SNIObfuscator::is_suspicious_sni(""));
        assert!(SNIObfuscator::is_suspicious_sni("A")); // Too short
        assert!(!SNIObfuscator::is_suspicious_sni("google.com"));
        assert!(SNIObfuscator::is_suspicious_sni("ALLUPPERCASE"));
    }

    #[test]
    fn test_get_stats() {
        let obfuscator = SNIObfuscator::new();
        let stats = obfuscator.get_stats("example.com", "google.com");
        assert_eq!(stats.original_sni, "example.com");
        assert_eq!(stats.obfuscated_sni, "google.com");
        assert!(stats.is_fake_domain);
    }

    #[test]
    fn test_title_case() {
        assert_eq!(SNIObfuscator::title_case("example.com"), "Example.Com");
        assert_eq!(SNIObfuscator::title_case("google"), "Google");
    }
}
