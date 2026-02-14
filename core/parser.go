package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// ProtocolParser handles parsing of different proxy protocol formats
type ProtocolParser struct{}

// NewProtocolParser creates a new protocol parser
func NewProtocolParser() *ProtocolParser {
	return &ProtocolParser{}
}

// ParseConfig detects and parses a configuration from URI or JSON
func (pp *ProtocolParser) ParseConfig(input string, sourceURL string) (*Config, error) {
	input = strings.TrimSpace(input)

	// Try to detect protocol from URI scheme
	if strings.Contains(input, "://") {
		return pp.parseURIConfig(input, sourceURL)
	}

	// Try to parse as base64-encoded URI
	if decoded, err := base64.StdEncoding.DecodeString(input); err == nil {
		if strings.Contains(string(decoded), "://") {
			return pp.parseURIConfig(string(decoded), sourceURL)
		}
	}

	// Try to parse as JSON
	if strings.HasPrefix(input, "{") || strings.HasPrefix(input, "[") {
		return pp.parseJSONConfig(input, sourceURL)
	}

	return nil, fmt.Errorf("unsupported config format")
}

// parseURIConfig parses URI-based configurations
func (pp *ProtocolParser) parseURIConfig(uri string, source string) (*Config, error) {
	// Identify scheme and route to appropriate parser
	parts := strings.Split(uri, "://")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid URI format")
	}

	scheme := parts[0]

	switch scheme {
	case "vmess":
		return pp.parseVMessURI(uri, source)
	case "vless":
		return pp.parseVLESSURI(uri, source)
	case "trojan":
		return pp.parseTrojanURI(uri, source)
	case "ss", "ssr":
		return pp.parseShadowsocksURI(uri, source)
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", scheme)
	}
}

// parseVMessURI parses VMess URI: vmess://[base64(json)]
func (pp *ProtocolParser) parseVMessURI(uri string, source string) (*Config, error) {
	const scheme = "vmess://"
	if !strings.HasPrefix(uri, scheme) {
		return nil, fmt.Errorf("invalid VMess URI")
	}

	encoded := strings.TrimPrefix(uri, scheme)
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		// Try URL decoding - returns string, needs to be converted to []byte
		decodedStr, err := url.QueryUnescape(encoded)
		if err != nil {
			return nil, fmt.Errorf("failed to decode VMess URI: %w", err)
		}
		decoded = []byte(decodedStr)
	}

	var cfg map[string]interface{}
	if err := json.Unmarshal([]byte(decoded), &cfg); err != nil {
		return nil, fmt.Errorf("invalid VMess JSON: %w", err)
	}

	return pp.parseVMessJSON(cfg, source)
}

// parseVMessJSON parses VMess configuration from JSON object
func (pp *ProtocolParser) parseVMessJSON(cfg map[string]interface{}, source string) (*Config, error) {
	name, ok := cfg["ps"].(string)
	if !ok {
		name = "VMess Config"
	}

	server, ok := cfg["add"].(string)
	if !ok || server == "" {
		return nil, fmt.Errorf("VMess missing server address")
	}

	port := 443
	if p, ok := cfg["port"].(float64); ok {
		port = int(p)
	} else if p, ok := cfg["port"].(string); ok {
		fmt.Sscanf(p, "%d", &port)
	}

	id, ok := cfg["id"].(string)
	if !ok || id == "" {
		return nil, fmt.Errorf("VMess missing UUID")
	}

	alterId := 0
	if aid, ok := cfg["aid"].(float64); ok {
		alterId = int(aid)
	}

	cipher := "auto"
	if c, ok := cfg["cipher"].(string); ok {
		cipher = c
	}

	config := &Config{
		Protocol:     "vmess",
		Server:       server,
		Port:         port,
		UUID:         id,
		AlterId:      alterId,
		Cipher:       cipher,
		Name:         name,
		Source:       source,
		AddedAt:      time.Now(),
		Obfuscation:  false,
		RawConfig:    fmt.Sprintf("%s:%d", server, port),
	}

	// Generate unique ID
	config.ID = pp.generateConfigID(config)

	return config, nil
}

// parseVLESSURI parses VLESS URI: vless://uuid@server:port?params
func (pp *ProtocolParser) parseVLESSURI(uri string, source string) (*Config, error) {
	const scheme = "vless://"
	if !strings.HasPrefix(uri, scheme) {
		return nil, fmt.Errorf("invalid VLESS URI")
	}

	uri = strings.TrimPrefix(uri, scheme)

	// Parse query parameters
	var params map[string]string
	if idx := strings.Index(uri, "?"); idx != -1 {
		queryStr := uri[idx+1:]
		uri = uri[:idx]
		params = pp.parseQueryParams(queryStr)
	} else {
		params = make(map[string]string)
	}

	// Parse uuid@server:port
	parts := strings.Split(uri, "@")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid VLESS URI structure")
	}

	uuid := parts[0]
	serverPort := parts[1]

	// Parse server:port
	addr := strings.Split(serverPort, ":")
	if len(addr) < 1 {
		return nil, fmt.Errorf("invalid server address")
	}

	server := addr[0]
	port := 443
	if len(addr) > 1 {
		fmt.Sscanf(addr[1], "%d", &port)
	}

	// Extract name from params or remark
	name := params["remark"]
	if name == "" {
		name = fmt.Sprintf("VLESS-%s", server)
	}

	// Check for REALITY support
	isReality := params["type"] == "tcp" && params["reality"] == "yes"
	isXHTTP := params["type"] == "http" && params["xhttp"] == "yes"

	config := &Config{
		Protocol:    "vless",
		Server:      server,
		Port:        port,
		UUID:        uuid,
		Name:        name,
		Source:      source,
		AddedAt:     time.Now(),
		Flow:        params["flow"],
		Security:    params["security"],
		ServerName:  params["sni"],
		RawConfig:   fmt.Sprintf("%s:%d", server, port),
	}

	// Handle REALITY protocol
	if isReality {
		config.PublicKey = params["pbk"]
		config.ShortID = params["sid"]
		config.ServerName = params["sni"]
	}

	// Handle XHTTP protocol
	if isXHTTP {
		config.HTTPMethod = params["method"]
		config.HTTPHost = params["host"]
		config.HTTPPath = params["path"]
	}

	// Generate unique ID
	config.ID = pp.generateConfigID(config)

	return config, nil
}

// parseTrojanURI parses Trojan URI: trojan://password@server:port
func (pp *ProtocolParser) parseTrojanURI(uri string, source string) (*Config, error) {
	const scheme = "trojan://"
	if !strings.HasPrefix(uri, scheme) {
		return nil, fmt.Errorf("invalid Trojan URI")
	}

	uri = strings.TrimPrefix(uri, scheme)

	// Parse query parameters if present
	var params map[string]string
	if idx := strings.Index(uri, "?"); idx != -1 {
		queryStr := uri[idx+1:]
		uri = uri[:idx]
		params = pp.parseQueryParams(queryStr)
	} else {
		params = make(map[string]string)
	}

	// Parse password@server:port
	parts := strings.Split(uri, "@")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid Trojan URI structure")
	}

	password := parts[0]
	serverPort := parts[1]

	// Parse server:port
	addr := strings.Split(serverPort, ":")
	if len(addr) < 1 {
		return nil, fmt.Errorf("invalid server address")
	}

	server := addr[0]
	port := 443
	if len(addr) > 1 {
		fmt.Sscanf(addr[1], "%d", &port)
	}

	name := params["name"]
	if name == "" {
		name = fmt.Sprintf("Trojan-%s", server)
	}

	config := &Config{
		Protocol:      "trojan",
		Server:        server,
		Port:          port,
		Password:      password,
		Name:          name,
		Source:        source,
		AddedAt:       time.Now(),
		TLSServerName: params["sni"],
		ServerName:    params["sni"],
		AllowInsecure: params["allowinsecure"] == "1",
		RawConfig:     fmt.Sprintf("%s:%d", server, port),
	}

	// Generate unique ID
	config.ID = pp.generateConfigID(config)

	return config, nil
}

// parseShadowsocksURI parses Shadowsocks URI: ss://[cipher:password]@server:port
func (pp *ProtocolParser) parseShadowsocksURI(uri string, source string) (*Config, error) {
	const scheme = "ss://"
	if !strings.HasPrefix(uri, scheme) {
		return nil, fmt.Errorf("invalid Shadowsocks URI")
	}

	uri = strings.TrimPrefix(uri, scheme)

	// Parse query parameters if present
	var params map[string]string
	if idx := strings.Index(uri, "?"); idx != -1 {
		queryStr := uri[idx+1:]
		uri = uri[:idx]
		params = pp.parseQueryParams(queryStr)
	} else {
		params = make(map[string]string)
	}

	// Decode if base64
	decoded, _ := base64.RawURLEncoding.DecodeString(uri)
	if len(decoded) > 0 {
		uri = string(decoded)
	}

	// Parse cipher:password@server:port
	parts := strings.Split(uri, "@")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid Shadowsocks URI structure")
	}

	cipherPass := parts[0]
	serverPort := parts[1]

	// Parse cipher:password
	cipherParts := strings.Split(cipherPass, ":")
	if len(cipherParts) != 2 {
		return nil, fmt.Errorf("invalid cipher:password format")
	}

	cipher := cipherParts[0]
	password := cipherParts[1]

	// Parse server:port
	addr := strings.Split(serverPort, ":")
	if len(addr) < 1 {
		return nil, fmt.Errorf("invalid server address")
	}

	server := addr[0]
	port := 443
	if len(addr) > 1 {
		fmt.Sscanf(addr[1], "%d", &port)
	}

	name := params["remark"]
	if name == "" {
		name = fmt.Sprintf("SS-%s", server)
	}

	config := &Config{
		Protocol:    "ss",
		Server:      server,
		Port:        port,
		Password:    password,
		Cipher:      cipher,
		Name:        name,
		Source:      source,
		AddedAt:     time.Now(),
		Method:      cipher,
		RawConfig:   fmt.Sprintf("%s:%d", server, port),
	}

	// Generate unique ID
	config.ID = pp.generateConfigID(config)

	return config, nil
}

// parseJSONConfig parses a JSON object configuration
func (pp *ProtocolParser) parseJSONConfig(jsonStr string, source string) (*Config, error) {
	var cfg map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &cfg); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	// Detect protocol type
	if protocol, ok := cfg["protocol"].(string); ok {
		switch protocol {
		case "vmess":
			return pp.parseVMessJSON(cfg, source)
		case "vless":
			return pp.parseVLESSJSON(cfg, source)
		case "trojan":
			return pp.parseTrojanJSON(cfg, source)
		case "shadowsocks":
			return pp.parseShadowsocksJSON(cfg, source)
		}
	}

	return nil, fmt.Errorf("unknown protocol in JSON")
}

// parseVLESSJSON parses VLESS from JSON
func (pp *ProtocolParser) parseVLESSJSON(cfg map[string]interface{}, source string) (*Config, error) {
	server, ok := cfg["server"].(string)
	if !ok || server == "" {
		return nil, fmt.Errorf("VLESS missing server")
	}

	port := 443
	if p, ok := cfg["port"].(float64); ok {
		port = int(p)
	}

	uuid, ok := cfg["uuid"].(string)
	if !ok || uuid == "" {
		return nil, fmt.Errorf("VLESS missing UUID")
	}

	name, ok := cfg["name"].(string)
	if !ok {
		name = fmt.Sprintf("VLESS-%s", server)
	}

	config := &Config{
		Protocol:   "vless",
		Server:     server,
		Port:       port,
		UUID:       uuid,
		Name:       name,
		Source:     source,
		AddedAt:    time.Now(),
		RawConfig:  fmt.Sprintf("%s:%d", server, port),
	}

	// Optional fields
	if sni, ok := cfg["sni"].(string); ok {
		config.ServerName = sni
	}
	if security, ok := cfg["security"].(string); ok {
		config.Security = security
	}
	if flow, ok := cfg["flow"].(string); ok {
		config.Flow = flow
	}

	config.ID = pp.generateConfigID(config)
	return config, nil
}

// parseTrojanJSON parses Trojan from JSON
func (pp *ProtocolParser) parseTrojanJSON(cfg map[string]interface{}, source string) (*Config, error) {
	server, ok := cfg["server"].(string)
	if !ok || server == "" {
		return nil, fmt.Errorf("Trojan missing server")
	}

	port := 443
	if p, ok := cfg["port"].(float64); ok {
		port = int(p)
	}

	password, ok := cfg["password"].(string)
	if !ok || password == "" {
		return nil, fmt.Errorf("Trojan missing password")
	}

	name, ok := cfg["name"].(string)
	if !ok {
		name = fmt.Sprintf("Trojan-%s", server)
	}

	config := &Config{
		Protocol:   "trojan",
		Server:     server,
		Port:       port,
		Password:   password,
		Name:       name,
		Source:     source,
		AddedAt:    time.Now(),
		RawConfig:  fmt.Sprintf("%s:%d", server, port),
	}

	if sni, ok := cfg["sni"].(string); ok {
		config.TLSServerName = sni
	}

	config.ID = pp.generateConfigID(config)
	return config, nil
}

// parseShadowsocksJSON parses Shadowsocks from JSON
func (pp *ProtocolParser) parseShadowsocksJSON(cfg map[string]interface{}, source string) (*Config, error) {
	server, ok := cfg["server"].(string)
	if !ok || server == "" {
		return nil, fmt.Errorf("Shadowsocks missing server")
	}

	port := 8388
	if p, ok := cfg["port"].(float64); ok {
		port = int(p)
	}

	password, ok := cfg["password"].(string)
	if !ok || password == "" {
		return nil, fmt.Errorf("Shadowsocks missing password")
	}

	method, ok := cfg["method"].(string)
	if !ok {
		method = "chacha20-ietf-poly1305"
	}

	name, ok := cfg["remarks"].(string)
	if !ok {
		name = fmt.Sprintf("SS-%s", server)
	}

	config := &Config{
		Protocol:   "ss",
		Server:     server,
		Port:       port,
		Password:   password,
		Method:     method,
		Cipher:     method,
		Name:       name,
		Source:     source,
		AddedAt:    time.Now(),
		RawConfig:  fmt.Sprintf("%s:%d", server, port),
	}

	config.ID = pp.generateConfigID(config)
	return config, nil
}

// parseQueryParams extracts query parameters from a string
func (pp *ProtocolParser) parseQueryParams(queryStr string) map[string]string {
	params := make(map[string]string)
	pairs := strings.Split(queryStr, "&")
	for _, pair := range pairs {
		if idx := strings.Index(pair, "="); idx != -1 {
			key := pair[:idx]
			value := pair[idx+1:]
			if decoded, err := url.QueryUnescape(value); err == nil {
				params[key] = decoded
			} else {
				params[key] = value
			}
		}
	}
	return params
}

// generateConfigID creates a unique ID for a config
func (pp *ProtocolParser) generateConfigID(cfg *Config) string {
	// Create hash from protocol, server, and port
	key := fmt.Sprintf("%s:%s:%d", cfg.Protocol, cfg.Server, cfg.Port)
	// Use simple hash function (in production, could use crypto hash)
	hash := 0
	for _, char := range key {
		hash = ((hash << 5) - hash) + int(char)
	}
	return fmt.Sprintf("%s-%x", cfg.Protocol, hash%1000000)
}
