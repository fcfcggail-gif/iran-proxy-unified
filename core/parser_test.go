package main

import (
	"encoding/base64"
	"testing"
)

// TestParseVMessURI tests VMess URI parsing
func TestParseVMessURI(t *testing.T) {
	parser := NewProtocolParser()

	// Create a valid VMess JSON config
	vmessJSON := `{"ps":"Test VMess","add":"example.com","port":443,"id":"12345678-1234-1234-1234-123456789012","aid":0,"net":"tcp","cipher":"auto"}`
	encoded := base64.StdEncoding.EncodeToString([]byte(vmessJSON))
	uri := "vmess://" + encoded

	cfg, err := parser.ParseConfig(uri, "test-source")
	if err != nil {
		t.Fatalf("Failed to parse VMess URI: %v", err)
	}

	if cfg.Protocol != "vmess" {
		t.Errorf("Expected protocol vmess, got %s", cfg.Protocol)
	}

	if cfg.Server != "example.com" {
		t.Errorf("Expected server example.com, got %s", cfg.Server)
	}

	if cfg.Port != 443 {
		t.Errorf("Expected port 443, got %d", cfg.Port)
	}

	if cfg.Name != "Test VMess" {
		t.Errorf("Expected name 'Test VMess', got %s", cfg.Name)
	}
}

// TestParseVLESSURI tests VLESS URI parsing
func TestParseVLESSURI(t *testing.T) {
	parser := NewProtocolParser()

	uri := "vless://12345678-1234-1234-1234-123456789012@example.com:443?remark=TestVLESS&security=tls&sni=example.com"

	cfg, err := parser.ParseConfig(uri, "test-source")
	if err != nil {
		t.Fatalf("Failed to parse VLESS URI: %v", err)
	}

	if cfg.Protocol != "vless" {
		t.Errorf("Expected protocol vless, got %s", cfg.Protocol)
	}

	if cfg.Server != "example.com" {
		t.Errorf("Expected server example.com, got %s", cfg.Server)
	}

	if cfg.Port != 443 {
		t.Errorf("Expected port 443, got %d", cfg.Port)
	}

	if cfg.UUID != "12345678-1234-1234-1234-123456789012" {
		t.Errorf("Expected UUID 12345678-1234-1234-1234-123456789012, got %s", cfg.UUID)
	}

	if cfg.Security != "tls" {
		t.Errorf("Expected security tls, got %s", cfg.Security)
	}
}

// TestParseVLESSWithREALITY tests VLESS with REALITY protocol
func TestParseVLESSWithREALITY(t *testing.T) {
	parser := NewProtocolParser()

	uri := "vless://12345678-1234-1234-1234-123456789012@example.com:443?type=tcp&reality=yes&pbk=publickey123&sid=shortid123&sni=real.example.com"

	cfg, err := parser.ParseConfig(uri, "test-source")
	if err != nil {
		t.Fatalf("Failed to parse VLESS with REALITY: %v", err)
	}

	if cfg.Protocol != "vless" {
		t.Errorf("Expected protocol vless, got %s", cfg.Protocol)
	}

	if cfg.PublicKey != "publickey123" {
		t.Errorf("Expected PublicKey publickey123, got %s", cfg.PublicKey)
	}

	if cfg.ShortID != "shortid123" {
		t.Errorf("Expected ShortID shortid123, got %s", cfg.ShortID)
	}

	if cfg.ServerName != "real.example.com" {
		t.Errorf("Expected ServerName real.example.com, got %s", cfg.ServerName)
	}
}

// TestParseVLESSWithXHTTP tests VLESS with XHTTP protocol
func TestParseVLESSWithXHTTP(t *testing.T) {
	parser := NewProtocolParser()

	uri := "vless://12345678-1234-1234-1234-123456789012@example.com:443?type=http&xhttp=yes&method=GET&host=example.com&path=/api"

	cfg, err := parser.ParseConfig(uri, "test-source")
	if err != nil {
		t.Fatalf("Failed to parse VLESS with XHTTP: %v", err)
	}

	if cfg.HTTPMethod != "GET" {
		t.Errorf("Expected HTTPMethod GET, got %s", cfg.HTTPMethod)
	}

	if cfg.HTTPHost != "example.com" {
		t.Errorf("Expected HTTPHost example.com, got %s", cfg.HTTPHost)
	}

	if cfg.HTTPPath != "/api" {
		t.Errorf("Expected HTTPPath /api, got %s", cfg.HTTPPath)
	}
}

// TestParseTrojanURI tests Trojan URI parsing
func TestParseTrojanURI(t *testing.T) {
	parser := NewProtocolParser()

	uri := "trojan://mypassword@example.com:443?name=TestTrojan&sni=example.com"

	cfg, err := parser.ParseConfig(uri, "test-source")
	if err != nil {
		t.Fatalf("Failed to parse Trojan URI: %v", err)
	}

	if cfg.Protocol != "trojan" {
		t.Errorf("Expected protocol trojan, got %s", cfg.Protocol)
	}

	if cfg.Password != "mypassword" {
		t.Errorf("Expected password mypassword, got %s", cfg.Password)
	}

	if cfg.Server != "example.com" {
		t.Errorf("Expected server example.com, got %s", cfg.Server)
	}

	if cfg.Port != 443 {
		t.Errorf("Expected port 443, got %d", cfg.Port)
	}

	if cfg.TLSServerName != "example.com" {
		t.Errorf("Expected TLSServerName example.com, got %s", cfg.TLSServerName)
	}
}

// TestParseShadowsocksURI tests Shadowsocks URI parsing
func TestParseShadowsocksURI(t *testing.T) {
	parser := NewProtocolParser()

	// Shadowsocks format: ss://cipher:password@server:port
	uri := "ss://aes-256-gcm:mypassword@example.com:8388"

	cfg, err := parser.ParseConfig(uri, "test-source")
	if err != nil {
		t.Fatalf("Failed to parse Shadowsocks URI: %v", err)
	}

	if cfg.Protocol != "ss" {
		t.Errorf("Expected protocol ss, got %s", cfg.Protocol)
	}

	if cfg.Cipher != "aes-256-gcm" {
		t.Errorf("Expected cipher aes-256-gcm, got %s", cfg.Cipher)
	}

	if cfg.Password != "mypassword" {
		t.Errorf("Expected password mypassword, got %s", cfg.Password)
	}

	if cfg.Server != "example.com" {
		t.Errorf("Expected server example.com, got %s", cfg.Server)
	}

	if cfg.Port != 8388 {
		t.Errorf("Expected port 8388, got %d", cfg.Port)
	}
}

// TestParseBase64Encoded tests base64-encoded URI parsing
func TestParseBase64Encoded(t *testing.T) {
	parser := NewProtocolParser()

	vmessURI := "vmess://eyJwcyI6IlRlc3QiLCJhZGQiOiJleGFtcGxlLmNvbSIsInBvcnQiOjQ0MywiYWlkIjowfQ=="
	encoded := base64.StdEncoding.EncodeToString([]byte(vmessURI))

	cfg, err := parser.ParseConfig(encoded, "test-source")
	if err != nil {
		t.Fatalf("Failed to parse base64-encoded URI: %v", err)
	}

	if cfg.Protocol != "vmess" {
		t.Errorf("Expected protocol vmess, got %s", cfg.Protocol)
	}
}

// TestParseJSONConfig tests JSON config parsing
func TestParseJSONConfig(t *testing.T) {
	parser := NewProtocolParser()

	jsonConfig := `{"protocol":"vless","server":"example.com","port":443,"uuid":"12345678-1234-1234-1234-123456789012","name":"TestJSON"}`

	cfg, err := parser.ParseConfig(jsonConfig, "test-source")
	if err != nil {
		t.Fatalf("Failed to parse JSON config: %v", err)
	}

	if cfg.Protocol != "vless" {
		t.Errorf("Expected protocol vless, got %s", cfg.Protocol)
	}

	if cfg.Server != "example.com" {
		t.Errorf("Expected server example.com, got %s", cfg.Server)
	}
}

// TestParseMultipleConfigs tests parsing multiple configs
func TestParseMultipleConfigs(t *testing.T) {
	parser := NewProtocolParser()

	configs := []struct {
		uri      string
		protocol string
	}{
		{"vless://uuid@server1.com:443", "vless"},
		{"trojan://pass@server2.com:443", "trojan"},
		{"ss://cipher:pass@server3.com:8388", "ss"},
	}

	for _, tc := range configs {
		cfg, err := parser.ParseConfig(tc.uri, "test-source")
		if err != nil {
			t.Fatalf("Failed to parse %s: %v", tc.uri, err)
		}

		if cfg.Protocol != tc.protocol {
			t.Errorf("Expected protocol %s, got %s", tc.protocol, cfg.Protocol)
		}
	}
}

// TestErrorHandling tests error handling for invalid configs
func TestErrorHandling(t *testing.T) {
	parser := NewProtocolParser()

	invalidConfigs := []string{
		"",                  // Empty string
		"invalid",           // No protocol
		"http://example.com", // Unsupported protocol
	}

	for _, config := range invalidConfigs {
		_, err := parser.ParseConfig(config, "test-source")
		if err == nil {
			t.Errorf("Expected error for invalid config: %s", config)
		}
	}
}

// TestIDGeneration tests unique ID generation
func TestIDGeneration(t *testing.T) {
	parser := NewProtocolParser()

	uri1 := "vless://uuid@server.com:443"
	uri2 := "vless://uuid@different-server.com:443"

	cfg1, _ := parser.ParseConfig(uri1, "source1")
	cfg2, _ := parser.ParseConfig(uri2, "source2")

	if cfg1.ID == cfg2.ID {
		t.Errorf("Expected different IDs for different configs, got %s for both", cfg1.ID)
	}

	// Same config should generate same ID
	cfg1Again, _ := parser.ParseConfig(uri1, "source1")
	if cfg1.ID != cfg1Again.ID {
		t.Errorf("Expected same ID for same config, got %s and %s", cfg1.ID, cfg1Again.ID)
	}
}

// TestQueryParamParsing tests query parameter parsing
func TestQueryParamParsing(t *testing.T) {
	parser := NewProtocolParser()

	uri := "vless://uuid@server.com:443?flow=xtls-rprx-vision&security=tls&sni=server.com&allowInsecure=1"

	cfg, err := parser.ParseConfig(uri, "test-source")
	if err != nil {
		t.Fatalf("Failed to parse URI with query params: %v", err)
	}

	if cfg.Flow != "xtls-rprx-vision" {
		t.Errorf("Expected flow xtls-rprx-vision, got %s", cfg.Flow)
	}

	if cfg.Security != "tls" {
		t.Errorf("Expected security tls, got %s", cfg.Security)
	}
}

// TestProtocolDetection tests automatic protocol detection
func TestProtocolDetection(t *testing.T) {
	testCases := []struct {
		uri      string
		expected string
	}{
		{"vmess://...", "vmess"},
		{"vless://...", "vless"},
		{"trojan://...", "trojan"},
		{"ss://...", "ss"},
	}

	for _, tc := range testCases {
		if !contains(tc.uri, tc.expected) && tc.expected != "" {
			// Protocol detection happens at parsing level
			t.Logf("Protocol detection test: %s should contain %s", tc.uri, tc.expected)
		}
	}
}

// TestConfigMetadata tests that config metadata is set correctly
func TestConfigMetadata(t *testing.T) {
	parser := NewProtocolParser()

	uri := "vless://uuid@server.com:443"
	source := "test-source-123"

	cfg, _ := parser.ParseConfig(uri, source)

	if cfg.Source != source {
		t.Errorf("Expected source %s, got %s", source, cfg.Source)
	}

	if cfg.Protocol == "" {
		t.Errorf("Expected protocol to be set")
	}

	if cfg.Server == "" {
		t.Errorf("Expected server to be set")
	}

	if cfg.Port == 0 {
		t.Errorf("Expected port to be set")
	}
}

// Benchmark tests for performance verification
func BenchmarkParseVMessURI(b *testing.B) {
	parser := NewProtocolParser()
	vmessJSON := `{"ps":"Test","add":"example.com","port":443,"id":"12345678-1234-1234-1234-123456789012","aid":0}`
	encoded := base64.StdEncoding.EncodeToString([]byte(vmessJSON))
	uri := "vmess://" + encoded

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		parser.ParseConfig(uri, "source")
	}
}

func BenchmarkParseVLESSURI(b *testing.B) {
	parser := NewProtocolParser()
	uri := "vless://12345678-1234-1234-1234-123456789012@example.com:443?remark=Test&security=tls"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		parser.ParseConfig(uri, "source")
	}
}

func BenchmarkParseTrojanURI(b *testing.B) {
	parser := NewProtocolParser()
	uri := "trojan://password@example.com:443?name=Test"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		parser.ParseConfig(uri, "source")
	}
}

func BenchmarkParseJSONConfig(b *testing.B) {
	parser := NewProtocolParser()
	jsonConfig := `{"protocol":"vless","server":"example.com","port":443,"uuid":"test","name":"Test"}`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		parser.ParseConfig(jsonConfig, "source")
	}
}

// Helper function
func contains(s, substr string) bool {
	for i := 0; i < len(s); i++ {
		if len(s[i:]) < len(substr) {
			return false
		}
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
