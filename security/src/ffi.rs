/// FFI (Foreign Function Interface) module for exposing Rust security functions to C/Go
/// This module provides C-compatible functions that wrap the Rust security implementations

use crate::obfuscation::Obfuscator;
use crate::pattern_rotation::PatternRotator;
use crate::dpi_bypass::DPIBypass;
use crate::detection_evasion::DetectionEvader;
use std::sync::Mutex;
use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_void};

/// Thread-safe error message storage
static ERROR_MESSAGE: Mutex<String> = Mutex::new(String::new());

/// Global security module state
static mut SECURITY_STATE: Option<SecurityState> = None;

struct SecurityState {
    obfuscator: Obfuscator,
    pattern_rotator: PatternRotator,
    dpi_bypasser: DPIBypass,
    detection_evader: DetectionEvader,
}

/// C-compatible SecurityBuffer struct
#[repr(C)]
pub struct SecurityBuffer {
    pub data: *mut u8,
    pub length: c_int,
}

/// C-compatible SecurityOptions struct
#[repr(C)]
pub struct SecurityOptions {
    pub fragmentation_bytes: c_int,
    pub delay_ms: c_int,
    pub randomization_level: c_int,
    pub enable_sni_obfuscation: c_int,
    pub enable_tls_fragmentation: c_int,
}

/// Initialize the security module
#[no_mangle]
pub extern "C" fn security_init() -> c_int {
    match std::panic::catch_unwind(|| {
        unsafe {
            SECURITY_STATE = Some(SecurityState {
                obfuscator: Obfuscator::new(),
                pattern_rotator: PatternRotator::new(1),
                dpi_bypasser: DPIBypass::new(),
                detection_evader: DetectionEvader::new(5),
            });
        }
        0
    }) {
        Ok(result) => result,
        Err(_) => {
            set_error("Panic during initialization");
            -1
        }
    }
}

/// Shutdown the security module
#[no_mangle]
pub extern "C" fn security_shutdown() -> c_int {
    unsafe {
        SECURITY_STATE = None;
    }
    0
}

/// Get the last error message
#[no_mangle]
pub extern "C" fn get_last_error() -> *const c_char {
    match ERROR_MESSAGE.lock() {
        Ok(msg) => msg.as_ptr() as *const c_char,
        Err(_) => {
            b"Unknown error\0".as_ptr() as *const c_char
        }
    }
}

/// Free memory allocated by FFI functions
#[no_mangle]
pub extern "C" fn security_free(ptr: *mut c_void) {
    if !ptr.is_null() {
        unsafe {
            let _ = Box::from_raw(ptr as *mut u8);
        }
    }
}

/// Process outgoing traffic with all DPI evasion techniques
#[no_mangle]
pub extern "C" fn process_outgoing_traffic(
    input: *const u8,
    input_len: c_int,
    output: *mut u8,
    output_len: *mut c_int,
    opts: *const SecurityOptions,
) -> c_int {
    if input.is_null() || output.is_null() || output_len.is_null() {
        set_error("Null pointer passed to process_outgoing_traffic");
        return -1;
    }

    let input_len = input_len as usize;
    let input_slice = unsafe { std::slice::from_raw_parts(input, input_len) };
    let options = unsafe { opts.as_ref() };

    match std::panic::catch_unwind(|| {
        unsafe {
            if let Some(ref state) = SECURITY_STATE {
                let mut processed = input_slice.to_vec();

                // Apply obfuscation if enabled
                if let Ok(obfuscated) = state.obfuscator.obfuscate(&processed) {
                    processed = obfuscated;
                }

                // Apply pattern rotation
                if let Ok(rotated) = state.pattern_rotator.rotate_pattern(&processed) {
                    processed = rotated;
                }

                // Apply DPI bypass techniques
                if let Ok(evaded) = state.dpi_bypasser.apply_evasion(&processed) {
                    processed = evaded;
                }

                // Apply detection evasion
                if let Ok(final_processed) = state.detection_evader.evade_detection(&processed) {
                    processed = final_processed;
                }

                // Copy to output buffer
                let out_slice = std::slice::from_raw_parts_mut(output, processed.len());
                out_slice.copy_from_slice(&processed);
                *output_len = processed.len() as c_int;

                return 0;
            }
            set_error("Security module not initialized");
            -1
        }
    }) {
        Ok(result) => result,
        Err(_) => {
            set_error("Panic in process_outgoing_traffic");
            -1
        }
    }
}

/// Process incoming traffic (reverse DPI evasion)
#[no_mangle]
pub extern "C" fn process_incoming_traffic(
    input: *const u8,
    input_len: c_int,
    output: *mut u8,
    output_len: *mut c_int,
) -> c_int {
    if input.is_null() || output.is_null() || output_len.is_null() {
        set_error("Null pointer passed to process_incoming_traffic");
        return -1;
    }

    let input_len = input_len as usize;
    let input_slice = unsafe { std::slice::from_raw_parts(input, input_len) };

    match std::panic::catch_unwind(|| {
        unsafe {
            if let Some(ref state) = SECURITY_STATE {
                let mut processed = input_slice.to_vec();

                // Reverse the evasion in opposite order
                if let Ok(detection_reversed) = state.detection_evader.reverse_evasion(&processed) {
                    processed = detection_reversed;
                }

                if let Ok(dpi_reversed) = state.dpi_bypasser.reverse_evasion(&processed) {
                    processed = dpi_reversed;
                }

                if let Ok(pattern_reversed) = state.pattern_rotator.reverse_rotation(&processed) {
                    processed = pattern_reversed;
                }

                if let Ok(deobfuscated) = state.obfuscator.deobfuscate(&processed) {
                    processed = deobfuscated;
                }

                // Copy to output buffer
                let out_slice = std::slice::from_raw_parts_mut(output, processed.len());
                out_slice.copy_from_slice(&processed);
                *output_len = processed.len() as c_int;

                return 0;
            }
            set_error("Security module not initialized");
            -1
        }
    }) {
        Ok(result) => result,
        Err(_) => {
            set_error("Panic in process_incoming_traffic");
            -1
        }
    }
}

/// Apply TLS ClientHello fragmentation
#[no_mangle]
pub extern "C" fn apply_tls_fragmentation(
    handshake: *const u8,
    handshake_len: c_int,
    output: *mut u8,
    output_len: *mut c_int,
    fragment_size: c_int,
) -> c_int {
    if handshake.is_null() || output.is_null() || output_len.is_null() {
        set_error("Null pointer passed to apply_tls_fragmentation");
        return -1;
    }

    let handshake_len = handshake_len as usize;
    let handshake_slice = unsafe { std::slice::from_raw_parts(handshake, handshake_len) };
    let fragment_size = (fragment_size as usize).max(100).min(500);

    match std::panic::catch_unwind(|| {
        unsafe {
            if let Some(ref state) = SECURITY_STATE {
                // Fragment the handshake
                let mut fragmented = Vec::new();
                let mut offset = 0;

                while offset < handshake_slice.len() {
                    let end = (offset + fragment_size).min(handshake_slice.len());
                    fragmented.extend_from_slice(&handshake_slice[offset..end]);

                    // Add inter-packet delay marker
                    if end < handshake_slice.len() {
                        fragmented.push(0xFF); // Delay marker
                    }

                    offset = end;
                }

                // Copy to output
                if fragmented.len() <= std::i32::MAX as usize {
                    let out_slice = std::slice::from_raw_parts_mut(output, fragmented.len());
                    out_slice.copy_from_slice(&fragmented);
                    *output_len = fragmented.len() as c_int;
                    return 0;
                }

                set_error("Fragmented output too large");
                return -1;
            }
            set_error("Security module not initialized");
            -1
        }
    }) {
        Ok(result) => result,
        Err(_) => {
            set_error("Panic in apply_tls_fragmentation");
            -1
        }
    }
}

/// Apply SNI obfuscation
#[no_mangle]
pub extern "C" fn apply_sni_obfuscation(
    sni: *const c_char,
    output: *mut u8,
    output_len: *mut c_int,
) -> c_int {
    if sni.is_null() || output.is_null() || output_len.is_null() {
        set_error("Null pointer passed to apply_sni_obfuscation");
        return -1;
    }

    match std::panic::catch_unwind(|| {
        unsafe {
            let sni_str = match CStr::from_ptr(sni).to_str() {
                Ok(s) => s,
                Err(_) => {
                    set_error("Invalid UTF-8 in SNI");
                    return -1;
                }
            };

            if let Some(ref state) = SECURITY_STATE {
                // Create fake SNI list
                let fake_snis = vec![
                    "google.com", "youtube.com", "facebook.com", "github.com",
                    "amazon.com", "apple.com", "microsoft.com", "twitter.com",
                    "netflix.com", "instagram.com", "linkedin.com", "reddit.com",
                    "wikipedia.org", "stackoverflow.com", "github.io", "medium.com",
                ];

                // Select random SNI with randomized capitalization
                use rand::Rng;
                let mut rng = rand::thread_rng();
                let fake_sni = fake_snis[rng.gen_range(0..fake_snis.len())];

                // Randomize case
                let mut obfuscated_sni = String::new();
                for (i, c) in fake_sni.chars().enumerate() {
                    if rng.gen_bool(0.5) && c.is_alphabetic() {
                        obfuscated_sni.push(c.to_uppercase().next().unwrap());
                    } else {
                        obfuscated_sni.push(c);
                    }
                }

                let obfuscated_bytes = obfuscated_sni.as_bytes();
                if obfuscated_bytes.len() <= std::i32::MAX as usize {
                    let out_slice = std::slice::from_raw_parts_mut(output, obfuscated_bytes.len());
                    out_slice.copy_from_slice(obfuscated_bytes);
                    *output_len = obfuscated_bytes.len() as c_int;
                    return 0;
                }

                set_error("SNI obfuscation output too large");
                return -1;
            }

            set_error("Security module not initialized");
            -1
        }
    }) {
        Ok(result) => result,
        Err(_) => {
            set_error("Panic in apply_sni_obfuscation");
            -1
        }
    }
}

/// Apply dynamic pattern rotation
#[no_mangle]
pub extern "C" fn apply_dynamic_pattern_rotation(
    packet: *const u8,
    packet_len: c_int,
    output: *mut u8,
    output_len: *mut c_int,
) -> c_int {
    if packet.is_null() || output.is_null() || output_len.is_null() {
        set_error("Null pointer passed to apply_dynamic_pattern_rotation");
        return -1;
    }

    let packet_len = packet_len as usize;
    let packet_slice = unsafe { std::slice::from_raw_parts(packet, packet_len) };

    match std::panic::catch_unwind(|| {
        unsafe {
            if let Some(ref state) = SECURITY_STATE {
                // Apply pattern randomization
                if let Ok(rotated) = state.pattern_rotator.rotate_pattern(packet_slice) {
                    if rotated.len() <= std::i32::MAX as usize {
                        let out_slice = std::slice::from_raw_parts_mut(output, rotated.len());
                        out_slice.copy_from_slice(&rotated);
                        *output_len = rotated.len() as c_int;
                        return 0;
                    }

                    set_error("Rotated pattern output too large");
                    return -1;
                }

                set_error("Pattern rotation failed");
                return -1;
            }

            set_error("Security module not initialized");
            -1
        }
    }) {
        Ok(result) => result,
        Err(_) => {
            set_error("Panic in apply_dynamic_pattern_rotation");
            -1
        }
    }
}

/// Helper function to set error message
fn set_error(message: &str) {
    if let Ok(mut err) = ERROR_MESSAGE.lock() {
        *err = message.to_string();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_init_shutdown() {
        assert_eq!(security_init(), 0);
        assert_eq!(security_shutdown(), 0);
    }

    #[test]
    fn test_null_pointer_checks() {
        let mut output_len = 0;
        let mut output = vec![0u8; 1024];

        // Test null input
        assert_eq!(
            process_outgoing_traffic(
                std::ptr::null(),
                10,
                output.as_mut_ptr(),
                &mut output_len,
                std::ptr::null()
            ),
            -1
        );
    }
}
