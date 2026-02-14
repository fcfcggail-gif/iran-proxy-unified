#ifndef SECURITY_H_
#define SECURITY_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

/* SecurityBuffer represents a byte buffer with length */
typedef struct {
    unsigned char* data;
    int length;
} SecurityBuffer;

/* SecurityOptions configures DPI evasion behavior */
typedef struct {
    int fragmentation_bytes;      /* Fragment size for TLS (100-500) */
    int delay_ms;                 /* Delay between fragments (10-100) */
    int randomization_level;      /* Level of randomization (1-5) */
    int enable_sni_obfuscation;   /* 1 = enabled, 0 = disabled */
    int enable_tls_fragmentation; /* 1 = enabled, 0 = disabled */
} SecurityOptions;

/* Initialization and cleanup */

/**
 * Initialize the security module
 * Must be called before using other functions
 * @return 0 on success, -1 on failure
 */
int security_init(void);

/**
 * Shutdown the security module
 * @return 0 on success, -1 on failure
 */
int security_shutdown(void);

/* Traffic processing */

/**
 * Process outgoing traffic with DPI evasion
 * @param input Input traffic data
 * @param input_len Length of input traffic
 * @param output Output buffer (must be pre-allocated, recommend 2x input size)
 * @param output_len Pointer to output length (set by function)
 * @param opts Security options configuration
 * @return 0 on success, -1 on failure
 */
int process_outgoing_traffic(
    const unsigned char* input,
    int input_len,
    unsigned char* output,
    int* output_len,
    const SecurityOptions* opts
);

/**
 * Process incoming traffic (reverse evasion)
 * @param input Input traffic data
 * @param input_len Length of input traffic
 * @param output Output buffer
 * @param output_len Pointer to output length (set by function)
 * @return 0 on success, -1 on failure
 */
int process_incoming_traffic(
    const unsigned char* input,
    int input_len,
    unsigned char* output,
    int* output_len
);

/* DPI-specific evasion functions */

/**
 * Apply TLS ClientHello fragmentation
 * Splits TLS handshake into multiple packets with delays
 * @param handshake TLS ClientHello data
 * @param handshake_len Length of handshake
 * @param output Output buffer with fragmented packets
 * @param output_len Pointer to output length
 * @param fragment_size Size of each fragment (100-500)
 * @return 0 on success, -1 on failure
 */
int apply_tls_fragmentation(
    const unsigned char* handshake,
    int handshake_len,
    unsigned char* output,
    int* output_len,
    int fragment_size
);

/**
 * Apply SNI obfuscation
 * Randomizes SNI in TLS ClientHello
 * @param sni Original SNI value
 * @param output Output buffer with obfuscated SNI
 * @param output_len Pointer to output length
 * @return 0 on success, -1 on failure
 */
int apply_sni_obfuscation(
    const char* sni,
    unsigned char* output,
    int* output_len
);

/**
 * Apply dynamic pattern rotation
 * Randomizes TCP/IP layer parameters
 * @param packet Network packet
 * @param packet_len Length of packet
 * @param output Output buffer with rotated pattern
 * @param output_len Pointer to output length
 * @return 0 on success, -1 on failure
 */
int apply_dynamic_pattern_rotation(
    const unsigned char* packet,
    int packet_len,
    unsigned char* output,
    int* output_len
);

/**
 * Get error message for last error
 * @return Error message string
 */
const char* get_last_error(void);

/**
 * Free allocated memory
 * Used for buffers allocated by library functions
 * @param ptr Pointer to memory to free
 */
void security_free(void* ptr);

#ifdef __cplusplus
}
#endif

#endif /* SECURITY_H_ */
