package main

import (
	"log"
	"strings"
)

// FilterEngine applies filtering rules to configs
type FilterEngine struct {
	rules            []FilterRule
	countryWhitelist map[string]bool
	protocolFilter   map[string]bool
	domainBlacklist  map[string]bool
}

// NewFilterEngine creates a new filter engine
func NewFilterEngine(rules []FilterRule) *FilterEngine {
	fe := &FilterEngine{
		rules:            rules,
		countryWhitelist: make(map[string]bool),
		protocolFilter:   make(map[string]bool),
		domainBlacklist:  make(map[string]bool),
	}

	// Initialize filter maps from rules
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}

		switch rule.Type {
		case "country":
			if rule.Action == "include" {
				fe.countryWhitelist[rule.Pattern] = true
			}
		case "protocol":
			if rule.Action == "include" {
				fe.protocolFilter[rule.Pattern] = true
			}
		case "domain":
			if rule.Action == "exclude" {
				fe.domainBlacklist[rule.Pattern] = true
			}
		}
	}

	return fe
}

// Filter checks if a config should be included based on rules
func (fe *FilterEngine) Filter(config *Config) bool {
	// Check country whitelist
	if len(fe.countryWhitelist) > 0 {
		if !fe.countryWhitelist[config.Country] {
			return false
		}
	}

	// Check protocol filter
	if len(fe.protocolFilter) > 0 {
		if !fe.protocolFilter[config.Protocol] {
			return false
		}
	}

	// Check domain blacklist
	if fe.isInDomainBlacklist(config.Server) {
		return false
	}

	// Check for Iran-specific requirements
	if !fe.meetsIranRequirements(config) {
		return false
	}

	return true
}

// isInDomainBlacklist checks if a domain is blacklisted
func (fe *FilterEngine) isInDomainBlacklist(domain string) bool {
	if fe.domainBlacklist[domain] {
		return true
	}

	// Check partial matches
	for blacklisted := range fe.domainBlacklist {
		if strings.Contains(domain, blacklisted) {
			return true
		}
	}

	return false
}

// meetsIranRequirements verifies Iran-specific network requirements
func (fe *FilterEngine) meetsIranRequirements(config *Config) bool {
	// Ensure protocol is supported in Iran's network
	supportedInIran := map[string]bool{
		"vmess":  true,
		"vless":  true,
		"ss":     true,
		"ssr":    true,
		"trojan": true,
	}

	if !supportedInIran[config.Protocol] {
		return false
	}

	// Reject configs with known unreliable ports in Iran
	unreliablePorts := map[int]bool{
		22:    true, // SSH
		3389:  true, // RDP
		27017: true, // MongoDB
	}

	if unreliablePorts[config.Port] {
		return false
	}

	// Ensure server is not empty
	if config.Server == "" {
		return false
	}

	// Ensure port is in valid range
	if config.Port < 1 || config.Port > 65535 {
		return false
	}

	return true
}

// FilterConfigs applies filters to a list of configs
func (fe *FilterEngine) FilterConfigs(configs []*Config) []*Config {
	var filtered []*Config

	for _, config := range configs {
		if fe.Filter(config) {
			filtered = append(filtered, config)
		}
	}

	log.Printf("Filtered configs: %d -> %d (removed %d)\n", len(configs), len(filtered), len(configs)-len(filtered))

	return filtered
}

// IranSpecificFilter implements additional Iran-specific filtering
type IranSpecificFilter struct {
	blockUnstableServers bool
	enforceObfuscation   bool
	preferLocalServers   bool
}

// NewIranSpecificFilter creates an Iran-specific filter
func NewIranSpecificFilter() *IranSpecificFilter {
	return &IranSpecificFilter{
		blockUnstableServers: true,
		enforceObfuscation:   true,
		preferLocalServers:   true,
	}
}

// ApplyIranRules applies Iran-specific filtering rules
func (isf *IranSpecificFilter) ApplyIranRules(config *Config) bool {
	// Block known unstable servers
	if isf.blockUnstableServers {
		if isf.isUnstableServer(config.Server) {
			return false
		}
	}

	// Prefer configs with obfuscation in Iran's restricted network
	if isf.enforceObfuscation {
		if config.Protocol == "vmess" && !config.Obfuscation {
			return false
		}
	}

	return true
}

// isUnstableServer checks if a server is known to be unstable in Iran
func (isf *IranSpecificFilter) isUnstableServer(server string) bool {
	unstablePatterns := []string{
		// Add patterns of known unstable servers
		"example.com", // placeholder
	}

	for _, pattern := range unstablePatterns {
		if strings.Contains(server, pattern) {
			return true
		}
	}

	return false
}
