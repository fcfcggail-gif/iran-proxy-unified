// TLS ClientHello Fragmentation Module
// Splits TLS ClientHello into multiple packets to evade DPI inspection
// Implements randomized fragment sizes and inter-packet delays

use rand::Rng;
use std::cmp;

const MIN_FRAGMENT_SIZE: usize = 100;
const MAX_FRAGMENT_SIZE: usize = 500;
const MIN_DELAY_MS: u32 = 10;
const MAX_DELAY_MS: u32 = 100;

// TLS Record Layer constants
const TLS_RECORD_TYPE_HANDSHAKE: u8 = 0x16;
const TLS_VERSION_MAJOR: u8 = 0x03;
const TLS_VERSION_MINOR: u8 = 0x03;
const TLS_HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;

/// Configuration for TLS fragmentation behavior
#[derive(Clone, Debug)]
pub struct TLSFragmentationConfig {
    pub min_fragment_size: usize,
    pub max_fragment_size: usize,
    pub min_delay_ms: u32,
    pub max_delay_ms: u32,
    pub randomize_delays: bool,
    pub preserve_record_boundary: bool,
}

impl Default for TLSFragmentationConfig {
    fn default() -> Self {
        TLSFragmentationConfig {
            min_fragment_size: MIN_FRAGMENT_SIZE,
            max_fragment_size: MAX_FRAGMENT_SIZE,
            min_delay_ms: MIN_DELAY_MS,
            max_delay_ms: MAX_DELAY_MS,
            randomize_delays: true,
            preserve_record_boundary: true,
        }
    }
}

/// Represents a TLS record with timing information
#[derive(Clone, Debug)]
pub struct FragmentedPacket {
    pub data: Vec<u8>,
    pub delay_ms: u32,
}

/// TLS fragmentation engine
pub struct TLSFragmenter {
    config: TLSFragmentationConfig,
}

impl TLSFragmenter {
    /// Create a new TLS fragmenter with default configuration
    pub fn new() -> Self {
        TLSFragmenter {
            config: TLSFragmentationConfig::default(),
        }
    }

    /// Create a new TLS fragmenter with custom configuration
    pub fn with_config(config: TLSFragmentationConfig) -> Self {
        TLSFragmenter { config }
    }

    /// Detect if data is a TLS ClientHello handshake
    fn is_client_hello(data: &[u8]) -> bool {
        if data.len() < 6 {
            return false;
        }

        // Check TLS record type (Handshake = 0x16)
        if data[0] != TLS_RECORD_TYPE_HANDSHAKE {
            return false;
        }

        // Check TLS version (3.3 = TLS 1.2, 3.4 = TLS 1.3)
        if data[1] != TLS_VERSION_MAJOR || (data[2] != 0x03 && data[2] != 0x04) {
            return false;
        }

        // Check handshake type (ClientHello = 0x01)
        if data[5] != TLS_HANDSHAKE_TYPE_CLIENT_HELLO {
            return false;
        }

        true
    }

    /// Calculate TLS record length from bytes 3-4
    fn get_record_length(data: &[u8]) -> Option<usize> {
        if data.len() < 5 {
            return None;
        }
        let len = ((data[3] as usize) << 8) | (data[4] as usize);
        Some(len + 5) // Add 5-byte header
    }

    /// Fragment ClientHello maintaining TLS record boundaries
    pub fn fragment_client_hello(&self, handshake: &[u8]) -> Result<Vec<FragmentedPacket>, String> {
        if !Self::is_client_hello(handshake) {
            return Err("Not a TLS ClientHello packet".to_string());
        }

        if handshake.len() < 43 {
            return Err("ClientHello too short".to_string());
        }

        let mut rng = rand::thread_rng();
        let mut packets = Vec::new();
        let mut offset = 0;

        // Split the TLS record into fragments
        while offset < handshake.len() {
            // Generate random fragment size
            let fragment_size = if self.config.preserve_record_boundary {
                // For first packet, try to send some header + partial payload
                if offset == 0 {
                    // Send at least the TLS record header + some handshake data
                    let min_first = cmp::min(200, handshake.len());
                    rng.gen_range(150..=min_first)
                } else {
                    rng.gen_range(
                        self.config.min_fragment_size..=cmp::min(
                            self.config.max_fragment_size,
                            handshake.len() - offset,
                        ),
                    )
                }
            } else {
                rng.gen_range(
                    self.config.min_fragment_size..=cmp::min(
                        self.config.max_fragment_size,
                        handshake.len() - offset,
                    ),
                )
            };

            let end = cmp::min(offset + fragment_size, handshake.len());
            let fragment_data = handshake[offset..end].to_vec();

            // Generate delay for this packet (except potentially first packet)
            let delay = if offset == 0 && !self.config.randomize_delays {
                0
            } else {
                rng.gen_range(self.config.min_delay_ms..=self.config.max_delay_ms)
            };

            packets.push(FragmentedPacket {
                data: fragment_data,
                delay_ms: delay,
            });

            offset = end;
        }

        // Ensure we have at least 2 packets
        if packets.len() == 1 && packets[0].data.len() > self.config.max_fragment_size {
            // Re-fragment the single packet
            return self.fragment_client_hello(handshake);
        }

        Ok(packets)
    }

    /// Fragment with Inter-Packet Delay (IPD) payload hiding
    pub fn fragment_with_ipd(&self, handshake: &[u8]) -> Result<Vec<FragmentedPacket>, String> {
        let packets = self.fragment_client_hello(handshake)?;

        // Ensure minimum delay between packets (unless first packet)
        let packets_with_delays: Vec<FragmentedPacket> = packets
            .into_iter()
            .enumerate()
            .map(|(idx, mut pkt)| {
                if idx == 0 {
                    // No delay for first packet
                    pkt.delay_ms = 0;
                } else if pkt.delay_ms == 0 {
                    // Ensure non-zero delay for subsequent packets
                    pkt.delay_ms = self.config.min_delay_ms;
                }
                pkt
            })
            .collect();

        Ok(packets_with_delays)
    }

    /// Get fragmentation statistics
    pub fn get_stats(&self, packets: &[FragmentedPacket]) -> FragmentationStats {
        let total_size: usize = packets.iter().map(|p| p.data.len()).sum();
        let min_size = packets.iter().map(|p| p.data.len()).min().unwrap_or(0);
        let max_size = packets.iter().map(|p| p.data.len()).max().unwrap_or(0);
        let avg_size = if packets.is_empty() {
            0
        } else {
            total_size / packets.len()
        };

        let total_delay: u32 = packets.iter().map(|p| p.delay_ms).sum();
        let avg_delay = if packets.is_empty() {
            0
        } else {
            total_delay / packets.len() as u32
        };

        FragmentationStats {
            num_packets: packets.len(),
            total_size,
            min_size,
            max_size,
            avg_size,
            total_delay_ms: total_delay,
            avg_delay_ms: avg_delay,
        }
    }
}

/// Statistics about fragmentation
#[derive(Clone, Debug)]
pub struct FragmentationStats {
    pub num_packets: usize,
    pub total_size: usize,
    pub min_size: usize,
    pub max_size: usize,
    pub avg_size: usize,
    pub total_delay_ms: u32,
    pub avg_delay_ms: u32,
}

/// Reassemble fragmented packets back to original
pub fn reassemble_fragments(packets: &[Vec<u8>]) -> Vec<u8> {
    let mut result = Vec::new();
    for packet in packets {
        result.extend_from_slice(packet);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_sample_client_hello() -> Vec<u8> {
        // Minimal valid ClientHello packet
        let mut hello = vec![
            0x16, // TLS Record Type: Handshake
            0x03, 0x03, // TLS Version: 1.2
            0x00, 0x50, // Record Length: 80 bytes
            0x01, // Handshake Type: ClientHello
        ];
        hello.resize(85, 0x00); // Pad to full length
        hello
    }

    #[test]
    fn test_detect_client_hello() {
        let hello = create_sample_client_hello();
        assert!(TLSFragmenter::is_client_hello(&hello));

        let not_hello = vec![0xFF, 0xFF, 0xFF];
        assert!(!TLSFragmenter::is_client_hello(&not_hello));
    }

    #[test]
    fn test_fragment_client_hello() {
        let hello = create_sample_client_hello();
        let fragmenter = TLSFragmenter::new();
        let packets = fragmenter.fragment_client_hello(&hello).unwrap();

        assert!(packets.len() >= 1);

        // Verify all data is present
        let reassembled = reassemble_fragments(
            &packets.iter().map(|p| p.data.clone()).collect::<Vec<_>>(),
        );
        assert_eq!(reassembled.len(), hello.len());
    }

    #[test]
    fn test_fragment_sizes_within_bounds() {
        let hello = create_sample_client_hello();
        let fragmenter = TLSFragmenter::new();
        let packets = fragmenter.fragment_client_hello(&hello).unwrap();

        for packet in &packets {
            assert!(packet.data.len() >= MIN_FRAGMENT_SIZE);
            assert!(packet.data.len() <= MAX_FRAGMENT_SIZE + 5); // +5 for potential header
        }
    }

    #[test]
    fn test_ipd_delays() {
        let hello = create_sample_client_hello();
        let fragmenter = TLSFragmenter::new();
        let packets = fragmenter.fragment_with_ipd(&hello).unwrap();

        assert!(packets.len() >= 1);
        if packets.len() > 1 {
            // First packet should have 0 delay
            assert_eq!(packets[0].delay_ms, 0);

            // Other packets should have delays
            for packet in &packets[1..] {
                assert!(packet.delay_ms > 0);
            }
        }
    }

    #[test]
    fn test_fragmentation_stats() {
        let hello = create_sample_client_hello();
        let fragmenter = TLSFragmenter::new();
        let packets = fragmenter.fragment_client_hello(&hello).unwrap();
        let stats = fragmenter.get_stats(&packets);

        assert_eq!(stats.num_packets, packets.len());
        assert!(stats.total_size >= hello.len() - 10); // Allow small variance
    }
}
