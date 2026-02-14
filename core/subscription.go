package main

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// SubscriptionGenerator handles converting configs to various subscription formats
type SubscriptionGenerator struct {
	format string
}

// NewSubscriptionGenerator creates a new subscription generator
func NewSubscriptionGenerator(format string) *SubscriptionGenerator {
	return &SubscriptionGenerator{
		format: format,
	}
}

// Generate creates a subscription from configs
func (sg *SubscriptionGenerator) Generate(configs []*Config) (string, error) {
	switch sg.format {
	case "clash":
		return sg.generateClash(configs)
	case "singbox":
		return sg.generateSingbox(configs)
	case "v2ray":
		return sg.generateV2Ray(configs)
	case "raw":
		return sg.generateRaw(configs)
	default:
		return "", fmt.Errorf("unsupported format: %s", sg.format)
	}
}

// generateClash creates a Clash subscription format
func (sg *SubscriptionGenerator) generateClash(configs []*Config) (string, error) {
	var sb strings.Builder

	sb.WriteString("proxies:\n")

	for i, cfg := range configs {
		if i > 0 {
			sb.WriteString("\n")
		}

		sb.WriteString("  - name: " + cfg.Name + "\n")
		sb.WriteString("    type: " + sg.mapProtocol(cfg.Protocol) + "\n")
		sb.WriteString("    server: " + cfg.Server + "\n")
		sb.WriteString(fmt.Sprintf("    port: %d\n", cfg.Port))

		if cfg.Password != "" {
			sb.WriteString("    password: " + cfg.Password + "\n")
		}

		if cfg.UUID != "" {
			sb.WriteString("    uuid: " + cfg.UUID + "\n")
		}

		if cfg.Cipher != "" {
			sb.WriteString("    cipher: " + cfg.Cipher + "\n")
		}

		if cfg.Method != "" {
			sb.WriteString("    method: " + cfg.Method + "\n")
		}

		if cfg.Obfuscation {
			sb.WriteString("    obfs: http\n")
		}

		sb.WriteString(fmt.Sprintf("    skip-cert-verify: true\n"))
	}

	// Add proxy groups
	sb.WriteString("\nproxy-groups:\n")
	sb.WriteString("  - name: \"All\"\n")
	sb.WriteString("    type: select\n")
	sb.WriteString("    proxies:\n")

	for _, cfg := range configs {
		sb.WriteString("      - " + cfg.Name + "\n")
	}

	// Add rules
	sb.WriteString("\nrules:\n")
	sb.WriteString("  - GEOIP,CN,All\n")
	sb.WriteString("  - MATCH,All\n")

	return sb.String(), nil
}

// generateSingbox creates a Sing-box subscription format
func (sg *SubscriptionGenerator) generateSingbox(configs []*Config) (string, error) {
	var sb strings.Builder

	sb.WriteString("{\"outbounds\":[")

	for i, cfg := range configs {
		if i > 0 {
			sb.WriteString(",")
		}

		outbound := sg.configToSingboxOutbound(cfg)
		sb.WriteString(outbound)
	}

	sb.WriteString("]}")

	return sb.String(), nil
}

func (sg *SubscriptionGenerator) configToSingboxOutbound(cfg *Config) string {
	var sb strings.Builder

	sb.WriteString("{")
	sb.WriteString(fmt.Sprintf(`"type":"%s",`, sg.mapProtocol(cfg.Protocol)))
	sb.WriteString(fmt.Sprintf(`"tag":"%s",`, cfg.Name))
	sb.WriteString(fmt.Sprintf(`"server":"%s",`, cfg.Server))
	sb.WriteString(fmt.Sprintf(`"server_port":%d`, cfg.Port))

	if cfg.Password != "" {
		sb.WriteString(fmt.Sprintf(`,password:"%s`, cfg.Password))
	}

	if cfg.UUID != "" {
		sb.WriteString(fmt.Sprintf(`,uuid:"%s`, cfg.UUID))
	}

	sb.WriteString("}")

	return sb.String()
}

// generateV2Ray creates a V2Ray config format
func (sg *SubscriptionGenerator) generateV2Ray(configs []*Config) (string, error) {
	var sb strings.Builder

	sb.WriteString("{\"v\":\"2\",\"ps\":\"\",\"add\":\"\",\"port\":\"443\",\"id\":\"\",\"aid\":\"0\",\"net\":\"\",\"type\":\"\",\"host\":\"\",\"path\":\"\",\"tls\":\"\",\"sni\":\"\",\"alpn\":\"\",\"fp\":\"\"}")

	// Simple implementation - returns base structure
	// Real implementation would convert full config details

	return sb.String(), nil
}

// generateRaw creates a raw proxy list (one per line in v2ray:// format)
func (sg *SubscriptionGenerator) generateRaw(configs []*Config) (string, error) {
	var lines []string

	for _, cfg := range configs {
		line := sg.configToV2RayLink(cfg)
		lines = append(lines, line)
	}

	return strings.Join(lines, "\n"), nil
}

func (sg *SubscriptionGenerator) configToV2RayLink(cfg *Config) string {
	// Format: v2ray://{base64encoded}
	// This is a simplified version
	content := fmt.Sprintf("%s:%d@%s", cfg.Protocol, cfg.Port, cfg.Server)
	encoded := base64.StdEncoding.EncodeToString([]byte(content))
	return "v2ray://" + encoded
}

// mapProtocol maps standard protocol names to format-specific names
func (sg *SubscriptionGenerator) mapProtocol(proto string) string {
	switch proto {
	case "vmess":
		return "vmess"
	case "vless":
		return "vless"
	case "ss", "shadowsocks":
		return "ss"
	case "ssr", "shadowsocksr":
		return "ssr"
	case "trojan":
		return "trojan"
	default:
		return proto
	}
}

// EncodeBase64 encodes a subscription to base64
func EncodeBase64(data string) string {
	return base64.StdEncoding.EncodeToString([]byte(data))
}

// DecodeBase64 decodes a base64 subscription
func DecodeBase64(data string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}
