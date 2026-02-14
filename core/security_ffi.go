package main

/*
#cgo CFLAGS: -I/workspaces/iran-proxy-unified/security/include
#cgo LDFLAGS: -L/workspaces/iran-proxy-unified/security/target/release -liran_proxy_security
#include "security.h"
#include <stdlib.h>
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// SecurityOptions wraps the C SecurityOptions struct
type SecurityFFIOptions struct {
	FragmentationBytes      int
	DelayMS                 int
	RandomizationLevel      int
	EnableSNIObfuscation    bool
	EnableTLSFragmentation  bool
}

// SafeProcessOutgoing wraps the Rust security module for outgoing traffic
func SafeProcessOutgoing(data []byte, opts *SecurityFFIOptions) ([]byte, error) {
	if len(data) == 0 {
		return data, nil
	}

	// Prepare output buffer (2x input size should be sufficient)
	outputSize := len(data) * 2
	output := make([]byte, outputSize)

	// Convert options to C struct
	cOpts := C.SecurityOptions{
		fragmentation_bytes:      C.int(opts.FragmentationBytes),
		delay_ms:                 C.int(opts.DelayMS),
		randomization_level:      C.int(opts.RandomizationLevel),
		enable_sni_obfuscation:   boolToC(opts.EnableSNIObfuscation),
		enable_tls_fragmentation: boolToC(opts.EnableTLSFragmentation),
	}

	// Call Rust FFI function
	var outputLen C.int
	result := C.process_outgoing_traffic(
		(*C.uchar)(unsafe.Pointer(&data[0])),
		C.int(len(data)),
		(*C.uchar)(unsafe.Pointer(&output[0])),
		&outputLen,
		&cOpts,
	)

	if result != 0 {
		errMsg := C.GoString(C.get_last_error())
		return nil, fmt.Errorf("security processing failed: %s", errMsg)
	}

	if outputLen > 0 && outputLen <= C.int(len(output)) {
		return output[:outputLen], nil
	}

	return output, nil
}

// SafeProcessIncoming wraps the Rust security module for incoming traffic
func SafeProcessIncoming(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return data, nil
	}

	// Prepare output buffer
	outputSize := len(data) * 2
	output := make([]byte, outputSize)

	// Call Rust FFI function
	var outputLen C.int
	result := C.process_incoming_traffic(
		(*C.uchar)(unsafe.Pointer(&data[0])),
		C.int(len(data)),
		(*C.uchar)(unsafe.Pointer(&output[0])),
		&outputLen,
	)

	if result != 0 {
		errMsg := C.GoString(C.get_last_error())
		return nil, fmt.Errorf("security processing failed: %s", errMsg)
	}

	if outputLen > 0 && outputLen <= C.int(len(output)) {
		return output[:outputLen], nil
	}

	return output, nil
}

// ApplyTLSFragmentation applies TLS ClientHello fragmentation
func ApplyTLSFragmentation(handshake []byte, fragmentSize int) ([]byte, error) {
	if len(handshake) == 0 {
		return handshake, nil
	}

	// Clamp fragment size
	if fragmentSize < 100 {
		fragmentSize = 100
	}
	if fragmentSize > 500 {
		fragmentSize = 500
	}

	// Prepare output buffer
	outputSize := len(handshake) + 256 // For extra markers
	output := make([]byte, outputSize)

	var outputLen C.int
	result := C.apply_tls_fragmentation(
		(*C.uchar)(unsafe.Pointer(&handshake[0])),
		C.int(len(handshake)),
		(*C.uchar)(unsafe.Pointer(&output[0])),
		&outputLen,
		C.int(fragmentSize),
	)

	if result != 0 {
		errMsg := C.GoString(C.get_last_error())
		return nil, fmt.Errorf("TLS fragmentation failed: %s", errMsg)
	}

	if outputLen > 0 && outputLen <= C.int(len(output)) {
		return output[:outputLen], nil
	}

	return output, nil
}

// ApplySNIObfuscation applies SNI obfuscation
func ApplySNIObfuscation(sni string) (string, error) {
	if sni == "" {
		return sni, nil
	}

	// Prepare output buffer
	outputSize := len(sni) * 2
	output := make([]byte, outputSize)

	cSNI := C.CString(sni)
	defer C.free(unsafe.Pointer(cSNI))

	var outputLen C.int
	result := C.apply_sni_obfuscation(
		cSNI,
		(*C.uchar)(unsafe.Pointer(&output[0])),
		&outputLen,
	)

	if result != 0 {
		errMsg := C.GoString(C.get_last_error())
		return "", fmt.Errorf("SNI obfuscation failed: %s", errMsg)
	}

	if outputLen > 0 && outputLen <= C.int(len(output)) {
		return string(output[:outputLen]), nil
	}

	return "", fmt.Errorf("SNI obfuscation produced invalid output")
}

// ApplyDynamicPatternRotation applies dynamic pattern rotation
func ApplyDynamicPatternRotation(packet []byte) ([]byte, error) {
	if len(packet) == 0 {
		return packet, nil
	}

	// Prepare output buffer
	outputSize := len(packet) + 128
	output := make([]byte, outputSize)

	var outputLen C.int
	result := C.apply_dynamic_pattern_rotation(
		(*C.uchar)(unsafe.Pointer(&packet[0])),
		C.int(len(packet)),
		(*C.uchar)(unsafe.Pointer(&output[0])),
		&outputLen,
	)

	if result != 0 {
		errMsg := C.GoString(C.get_last_error())
		return nil, fmt.Errorf("pattern rotation failed: %s", errMsg)
	}

	if outputLen > 0 && outputLen <= C.int(len(output)) {
		return output[:outputLen], nil
	}

	return output, nil
}

// InitSecurityModule initializes the Rust security module
func InitSecurityModule() error {
	result := C.security_init()
	if result != 0 {
		return fmt.Errorf("security module initialization failed")
	}
	return nil
}

// ShutdownSecurityModule shuts down the Rust security module
func ShutdownSecurityModule() error {
	result := C.security_shutdown()
	if result != 0 {
		return fmt.Errorf("security module shutdown failed")
	}
	return nil
}

// Helper function to convert Go bool to C int
func boolToC(b bool) C.int {
	if b {
		return C.int(1)
	}
	return C.int(0)
}

// GetLastError gets the last error message from the security module
func GetLastError() string {
	return C.GoString(C.get_last_error())
}
