package main

import (
	"strings"
	"testing"
)

// TestEndToEndPipeline tests the complete pipeline: parse -> filter -> generate
func TestEndToEndPipeline(t *testing.T) {
	NewProtocolParser()

	// Create sample configs
	configs := []*Config{
		{
			ID:       "vless-1",
			Protocol: "vless",
			Server:   "server1.com",
			Port:     443,
			UUID:     "uuid-1",
			Name:     "VLESS Config 1",
			Source:   "test-source",
		},
		{
			ID:       "trojan-1",
			Protocol: "trojan",
			Server:   "server2.com",
			Port:     443,
			Password: "pass123",
			Name:     "Trojan Config 1",
			Source:   "test-source",
		},
		{
			ID:       "ss-1",
			Protocol: "ss",
			Server:   "server3.com",
			Port:     8388,
			Password: "sspass",
			Cipher:   "aes-256-gcm",
			Name:     "SS Config 1",
			Source:   "test-source",
		},
	}

	// Generate Clash format
	clashGen := NewSubscriptionGenerator("clash")
	clashSub, err := clashGen.Generate(configs)
	if err != nil {
		t.Fatalf("Failed to generate Clash subscription: %v", err)
	}

	if !strings.Contains(clashSub, "proxy") {
		t.Errorf("Clash subscription should contain 'proxy'")
	}

	if !strings.Contains(clashSub, "VLESS Config 1") {
		t.Errorf("Clash subscription should contain config names")
	}

	// Generate Sing-box format
	singboxGen := NewSubscriptionGenerator("singbox")
	singboxSub, err := singboxGen.Generate(configs)
	if err != nil {
		t.Fatalf("Failed to generate Sing-box subscription: %v", err)
	}

	if !strings.Contains(singboxSub, "outbound") {
		t.Errorf("Sing-box subscription should contain 'outbound'")
	}

	// Generate V2Ray format
	v2rayGen := NewSubscriptionGenerator("v2ray")
	v2raySub, err := v2rayGen.Generate(configs)
	if err != nil {
		t.Fatalf("Failed to generate V2Ray subscription: %v", err)
	}

	if v2raySub == "" {
		t.Errorf("V2Ray subscription should not be empty")
	}

	// Generate Raw format
	rawGen := NewSubscriptionGenerator("raw")
	rawSub, err := rawGen.Generate(configs)
	if err != nil {
		t.Fatalf("Failed to generate Raw subscription: %v", err)
	}

	if !strings.Contains(rawSub, "v2ray://") {
		t.Errorf("Raw subscription should contain v2ray:// links")
	}
}

// TestParseAndGenerateClash tests parsing URIs and generating Clash config
func TestParseAndGenerateClash(t *testing.T) {
	parser := NewProtocolParser()

	uris := []string{
		"vless://12345678-1234-1234-1234-123456789012@example1.com:443?remark=VLESSTest",
		"trojan://password@example2.com:443?name=TrojanTest",
		"ss://aes-256-gcm:password@example3.com:8388",
	}

	var configs []*Config
	for _, uri := range uris {
		cfg, err := parser.ParseConfig(uri, "test-source")
		if err != nil {
			t.Fatalf("Failed to parse URI %s: %v", uri, err)
		}
		configs = append(configs, cfg)
	}

	gen := NewSubscriptionGenerator("clash")
	sub, err := gen.Generate(configs)
	if err != nil {
		t.Fatalf("Failed to generate Clash: %v", err)
	}

	// Verify all protocols are present
	if !strings.Contains(sub, "vless") {
		t.Errorf("Clash output should contain vless")
	}

	if !strings.Contains(sub, "trojan") {
		t.Errorf("Clash output should contain trojan")
	}

	if !strings.Contains(sub, "ss") {
		t.Errorf("Clash output should contain ss")
	}
}

// TestREALITYProtocolGeneration tests REALITY protocol in subscriptions
func TestREALITYProtocolGeneration(t *testing.T) {
	config := &Config{
		ID:         "reality-1",
		Protocol:   "vless",
		Server:     "reality.example.com",
		Port:       443,
		UUID:       "uuid-123",
		PublicKey:  "abc123def456",
		ShortID:    "sid123",
		ServerName: "real.example.com",
		Name:       "REALITY Config",
		Source:     "test",
	}

	configs := []*Config{config}

	// Test Clash generation with REALITY
	clashGen := NewSubscriptionGenerator("clash")
	clashSub, err := clashGen.Generate(configs)
	if err != nil {
		t.Fatalf("Failed to generate Clash with REALITY: %v", err)
	}

	if !strings.Contains(clashSub, "reality-opts") {
		t.Errorf("Clash should include reality-opts for REALITY protocol")
	}

	// Test Sing-box generation with REALITY (should have reality in JSON)
	singboxGen := NewSubscriptionGenerator("singbox")
	singboxSub, err := singboxGen.Generate(configs)
	if err != nil {
		t.Fatalf("Failed to generate Sing-box with REALITY: %v", err)
	}

	if !strings.Contains(singboxSub, "reality") {
		t.Errorf("Sing-box should include reality config")
	}
}

// TestXHTTPProtocolGeneration tests XHTTP protocol in subscriptions
func TestXHTTPProtocolGeneration(t *testing.T) {
	config := &Config{
		ID:         "xhttp-1",
		Protocol:   "vless",
		Server:     "xhttp.example.com",
		Port:       443,
		UUID:       "uuid-456",
		HTTPMethod: "GET",
		HTTPHost:   "example.com",
		HTTPPath:   "/api",
		Name:       "XHTTP Config",
		Source:     "test",
	}

	configs := []*Config{config}

	// Test Clash generation with XHTTP
	clashGen := NewSubscriptionGenerator("clash")
	clashSub, err := clashGen.Generate(configs)
	if err != nil {
		t.Fatalf("Failed to generate Clash with XHTTP: %v", err)
	}

	if !strings.Contains(clashSub, "http-opts") {
		t.Errorf("Clash should include http-opts for XHTTP protocol")
	}

	// Test Sing-box generation with XHTTP
	singboxGen := NewSubscriptionGenerator("singbox")
	singboxSub, err := singboxGen.Generate(configs)
	if err != nil {
		t.Fatalf("Failed to generate Sing-box with XHTTP: %v", err)
	}

	if !strings.Contains(singboxSub, "http") {
		t.Errorf("Sing-box should include http config")
	}
}

// TestVMessGeneration tests VMess protocol generation
func TestVMessGeneration(t *testing.T) {
	config := &Config{
		ID:       "vmess-1",
		Protocol: "vmess",
		Server:   "vmess.example.com",
		Port:     443,
		UUID:     "vmess-uuid",
		AlterId:  0,
		Cipher:   "auto",
		Name:     "VMess Config",
		Source:   "test",
	}

	gen := NewSubscriptionGenerator("clash")
	sub, err := gen.Generate([]*Config{config})
	if err != nil {
		t.Fatalf("Failed to generate VMess subscription: %v", err)
	}

	if !strings.Contains(sub, "vmess") {
		t.Errorf("Subscription should contain vmess protocol")
	}

	if !strings.Contains(sub, "alterId") {
		t.Errorf("VMess config should include alterId")
	}
}

// TestMultipleFormatsGeneration tests generating all formats from same configs
func TestMultipleFormatsGeneration(t *testing.T) {
	configs := []*Config{
		{
			ID:       "test-1",
			Protocol: "vless",
			Server:   "server.com",
			Port:     443,
			UUID:     "uuid",
			Name:     "Test Config",
		},
	}

	formats := []string{"clash", "singbox", "v2ray", "raw"}

	for _, format := range formats {
		gen := NewSubscriptionGenerator(format)
		sub, err := gen.Generate(configs)

		if err != nil {
			t.Fatalf("Failed to generate %s format: %v", format, err)
		}

		if sub == "" {
			t.Errorf("Generated %s subscription is empty", format)
		}
	}
}

// TestBase64Encoding tests Base64 encoding/decoding of subscriptions
func TestBase64Encoding(t *testing.T) {
	content := "proxies:\n  - name: test\n    type: vless"

	encoded := EncodeBase64(content)
	if encoded == "" {
		t.Errorf("Base64 encoding produced empty string")
	}

	decoded, err := DecodeBase64(encoded)
	if err != nil {
		t.Fatalf("Failed to decode Base64: %v", err)
	}

	if decoded != content {
		t.Errorf("Decoded content doesn't match original")
	}
}

// TestSubscriptionMetadata tests that subscriptions include proper metadata
func TestSubscriptionMetadata(t *testing.T) {
	config := &Config{
		ID:       "meta-1",
		Protocol: "vless",
		Server:   "server.com",
		Port:     443,
		UUID:     "uuid",
		Name:     "Named Config",
		Source:   "test-source",
	}

	gen := NewSubscriptionGenerator("clash")
	sub, _ := gen.Generate([]*Config{config})

	// Should include the name
	if !strings.Contains(sub, "Named Config") {
		t.Errorf("Subscription should include config name")
	}

	// Should include protocol info
	if !strings.Contains(sub, "vless") {
		t.Errorf("Subscription should include protocol information")
	}
}

// TestLargeConfigSet tests generation with many configs (performance)
func TestLargeConfigSet(t *testing.T) {
	// Create 100 configs
	var configs []*Config
	for i := 0; i < 100; i++ {
		configs = append(configs, &Config{
			ID:       "config" + string(rune(i)),
			Protocol: "vless",
			Server:   "server.com",
			Port:     443 + i,
			UUID:     "uuid-" + string(rune(i)),
			Name:     "Config " + string(rune(i)),
		})
	}

	gen := NewSubscriptionGenerator("clash")
	sub, err := gen.Generate(configs)

	if err != nil {
		t.Fatalf("Failed to generate large subscription: %v", err)
	}

	// Should contain all configs
	if len(sub) < 1000 {
		t.Errorf("Large subscription should have significant size")
	}
}

// TestInvalidFormatHandling tests handling of invalid formats
func TestInvalidFormatHandling(t *testing.T) {
	gen := NewSubscriptionGenerator("invalid-format")
	configs := []*Config{
		{
			Protocol: "vless",
			Server:   "server.com",
			Port:     443,
		},
	}

	_, err := gen.Generate(configs)
	if err == nil {
		t.Errorf("Should return error for invalid format")
	}
}

// TestEmptyConfigSet tests generation with empty config set
func TestEmptyConfigSet(t *testing.T) {
	gen := NewSubscriptionGenerator("clash")
	sub, err := gen.Generate([]*Config{})

	if err != nil {
		t.Fatalf("Should not error on empty config set: %v", err)
	}

	// Should still be valid YAML
	if !strings.Contains(sub, "proxies") {
		t.Errorf("Empty Clash should still have proxies section")
	}
}

// TestProtocolMapping tests protocol name mapping
func TestProtocolMapping(t *testing.T) {
	gen := NewSubscriptionGenerator("clash")

	testCases := []struct {
		protocol string
		expected string
	}{
		{"vmess", "vmess"},
		{"vless", "vless"},
		{"ss", "ss"},
		{"trojan", "trojan"},
		{"reality", "vless"}, // REALITY is a VLESS variant
		{"xhttp", "vless"},   // XHTTP is a VLESS variant
	}

	for _, tc := range testCases {
		result := gen.mapProtocol(tc.protocol)
		if result != tc.expected {
			t.Errorf("Protocol %s should map to %s, got %s", tc.protocol, tc.expected, result)
		}
	}
}

// BenchmarkClashGeneration benchmarks Clash format generation
func BenchmarkClashGeneration(b *testing.B) {
	var configs []*Config
	for i := 0; i < 100; i++ {
		configs = append(configs, &Config{
			ID:       "config-" + string(rune(i)),
			Protocol: "vless",
			Server:   "server.com",
			Port:     443,
			UUID:     "uuid-" + string(rune(i)),
			Name:     "Config " + string(rune(i)),
		})
	}

	gen := NewSubscriptionGenerator("clash")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		gen.Generate(configs)
	}
}

// BenchmarkSingboxGeneration benchmarks Sing-box format generation
func BenchmarkSingboxGeneration(b *testing.B) {
	var configs []*Config
	for i := 0; i < 100; i++ {
		configs = append(configs, &Config{
			ID:       "config-" + string(rune(i)),
			Protocol: "vless",
			Server:   "server.com",
			Port:     443,
			UUID:     "uuid-" + string(rune(i)),
			Name:     "Config " + string(rune(i)),
		})
	}

	gen := NewSubscriptionGenerator("singbox")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		gen.Generate(configs)
	}
}

// BenchmarkEndToEnd benchmarks the complete pipeline
func BenchmarkEndToEnd(b *testing.B) {
	parser := NewProtocolParser()
	uris := []string{
		"vless://uuid1@server1.com:443",
		"trojan://pass@server2.com:443",
		"ss://cipher:pass@server3.com:8388",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var configs []*Config
		for _, uri := range uris {
			cfg, _ := parser.ParseConfig(uri, "source")
			configs = append(configs, cfg)
		}

		gen := NewSubscriptionGenerator("clash")
		gen.Generate(configs)
	}
}
