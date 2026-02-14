package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/go-resty/resty/v2"
	"gopkg.in/yaml.v3"
)

// Config represents a single proxy configuration
type Config struct {
	ID          string            `json:"id"`
	Protocol    string            `json:"protocol"` // vmess, vless, ss, ssr, trojan
	Server      string            `json:"server"`
	Port        int               `json:"port"`
	Password    string            `json:"password,omitempty"`
	Method      string            `json:"method,omitempty"`
	Cipher      string            `json:"cipher,omitempty"`
	UUID        string            `json:"uuid,omitempty"`
	Name        string            `json:"name"`
	Country     string            `json:"country,omitempty"`
	Ping        int               `json:"ping,omitempty"` // milliseconds
	Obfuscation bool              `json:"obfuscation"`
	Source      string            `json:"source"`
	RawConfig   string            `json:"raw_config"`
	AddedAt     time.Time         `json:"added_at"`
	Metadata    map[string]string `json:"metadata,omitempty"`

	// REALITY protocol fields
	PublicKey     string `json:"public_key,omitempty"`
	ShortID       string `json:"short_id,omitempty"`
	ServerName    string `json:"server_name,omitempty"`
	StaleBehavior string `json:"stale_behavior,omitempty"`

	// XHTTP protocol fields
	HTTPMethod       string `json:"http_method,omitempty"`
	HTTPHost         string `json:"http_host,omitempty"`
	HTTPPath         string `json:"http_path,omitempty"`
	HTTPPathOverride string `json:"http_path_override,omitempty"`

	// Trojan-specific fields
	TLSServerName string `json:"tls_server_name,omitempty"`
	AllowInsecure bool   `json:"allow_insecure,omitempty"`

	// Advanced protocol options
	AlterId        int    `json:"alter_id,omitempty"` // VMess alter ID
	Flow           string `json:"flow,omitempty"`     // VLESS flow (xtls-rprx-vision)
	Security       string `json:"security,omitempty"` // TLS, reality, etc
	Edition        string `json:"edition,omitempty"`  // Protocol version
	SkipCertVerify bool   `json:"skip_cert_verify,omitempty"`
	TransportType  string `json:"transport_type,omitempty"` // tcp, mux, grpc, ws, http

	// Performance and metadata
	ParseTime        int64  `json:"parse_time_ns,omitempty"`
	ValidationStatus string `json:"validation_status,omitempty"`
}

// ConfigSource represents a source to fetch configs from
type ConfigSource struct {
	Name     string `yaml:"name"`
	URL      string `yaml:"url"`
	Type     string `yaml:"type"` // base64, json, plain
	Enabled  bool   `yaml:"enabled"`
	Auth     string `yaml:"auth,omitempty"`
	Timeout  int    `yaml:"timeout,omitempty"`  // seconds
	Interval int    `yaml:"interval,omitempty"` // seconds between updates
}

// FilterRule represents a filtering rule
type FilterRule struct {
	Name    string `json:"name"`
	Type    string `json:"type"` // country, protocol, domain
	Pattern string `json:"pattern"`
	Action  string `json:"action"` // include, exclude
	Enabled bool   `json:"enabled"`
}

// Aggregator manages config fetching and processing
type Aggregator struct {
	sources      []ConfigSource
	rules        []FilterRule
	cache        *Cache
	maxConfigs   int
	httpClient   *resty.Client
	configs      map[string]*Config
	configsMutex sync.RWMutex
}

// NewAggregator creates a new aggregator instance
func NewAggregator(sourcesFile, rulesFile string, maxConfigs int) (*Aggregator, error) {
	sources, err := loadSources(sourcesFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load sources: %w", err)
	}

	rules, err := loadRules(rulesFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load rules: %w", err)
	}

	cache := NewCache(1 * time.Hour)

	httpClient := resty.New().
		SetTimeout(30 * time.Second).
		SetRetryCount(3).
		SetRetryWaitTime(1 * time.Second)

	return &Aggregator{
		sources:    sources,
		rules:      rules,
		cache:      cache,
		maxConfigs: maxConfigs,
		httpClient: httpClient,
		configs:    make(map[string]*Config),
	}, nil
}

// FetchAndProcessConfigs fetches configs from all sources and applies filtering
func (a *Aggregator) FetchAndProcessConfigs() ([]*Config, error) {
	var wg sync.WaitGroup
	configsChan := make(chan *Config, 1000)
	errorsChan := make(chan error, len(a.sources))

	// Fetch from all sources concurrently
	for _, source := range a.sources {
		if !source.Enabled {
			continue
		}

		wg.Add(1)
		go func(src ConfigSource) {
			defer wg.Done()
			if err := a.fetchFromSource(src, configsChan); err != nil {
				log.Printf("Error fetching from %s: %v\n", src.Name, err)
				errorsChan <- err
			}
		}(source)
	}

	// Close channels when all fetches complete
	go func() {
		wg.Wait()
		close(configsChan)
		close(errorsChan)
	}()

	// Collect configs and apply deduplication
	seen := make(map[string]bool)
	var config *Config

	for config = range configsChan {
		// Skip duplicates
		configKey := fmt.Sprintf("%s:%d:%s", config.Server, config.Port, config.Protocol)
		if seen[configKey] {
			continue
		}
		seen[configKey] = true

		// Apply filtering rules
		if a.shouldIncludeConfig(config) {
			a.configsMutex.Lock()
			a.configs[config.ID] = config
			a.configsMutex.Unlock()

			// Stop if we've reached max configs
			if len(a.configs) >= a.maxConfigs {
				break
			}
		}
	}

	a.configsMutex.RLock()
	defer a.configsMutex.RUnlock()

	result := make([]*Config, 0, len(a.configs))
	for _, cfg := range a.configs {
		result = append(result, cfg)
	}

	return result, nil
}

func (a *Aggregator) fetchFromSource(source ConfigSource, configsChan chan<- *Config) error {
	// Check cache first
	if cached := a.cache.Get(source.Name); cached != nil {
		log.Printf("Using cached configs from %s\n", source.Name)
		if configs, ok := cached.([]*Config); ok {
			for _, cfg := range configs {
				configsChan <- cfg
			}
		}
		return nil
	}

	resp, err := a.httpClient.R().Get(source.URL)
	if err != nil {
		return fmt.Errorf("failed to fetch from %s: %w", source.Name, err)
	}

	if resp.StatusCode() != http.StatusOK {
		return fmt.Errorf("unexpected status code from %s: %d", source.Name, resp.StatusCode())
	}

	var configs []*Config
	switch source.Type {
	case "base64":
		configs, err = a.parseBase64Configs(resp.Body())
	case "json":
		configs, err = a.parseJSONConfigs()
	case "plain":
		configs, err = a.parsePlainConfigs()
	default:
		return fmt.Errorf("unknown source type: %s", source.Type)
	}

	if err != nil {
		return err
	}

	// Cache the configs
	a.cache.Set(source.Name, configs)

	// Send to channel
	for _, cfg := range configs {
		configsChan <- cfg
	}

	return nil
}

func (a *Aggregator) parseBase64Configs(data []byte) ([]*Config, error) {
	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %w", err)
	}

	var _ []byte = decoded
	return a.parsePlainConfigs()
}

func (a *Aggregator) parseJSONConfigs() ([]*Config, error) {
	// This would parse JSON format configs
	// Implementation depends on the JSON structure
	var configs []*Config
	// TODO: Implement JSON parsing
	return configs, nil
}

func (a *Aggregator) parsePlainConfigs() ([]*Config, error) {
	// Parse line-by-line config strings (v2ray://, ss://, etc.)
	var configs []*Config
	// TODO: Implement plain config parsing
	return configs, nil
}

func (a *Aggregator) shouldIncludeConfig(config *Config) bool {
	for _, rule := range a.rules {
		if !rule.Enabled {
			continue
		}

		include := rule.Action == "include"

		switch rule.Type {
		case "protocol":
			if config.Protocol == rule.Pattern {
				return include
			}
		case "country":
			if config.Country == rule.Pattern {
				return include
			}
		case "domain":
			if config.Server == rule.Pattern {
				return include
			}
		}
	}

	// Default: include if no rules matched
	return true
}

func loadSources(sourcesFile string) ([]ConfigSource, error) {
	data, err := os.ReadFile(sourcesFile)
	if err != nil {
		return nil, err
	}

	var sources []ConfigSource
	if err := yaml.Unmarshal(data, &sources); err != nil {
		return nil, err
	}

	return sources, nil
}

func loadRules(rulesFile string) ([]FilterRule, error) {
	data, err := os.ReadFile(rulesFile)
	if err != nil {
		return nil, err
	}

	var rules []FilterRule
	if err := json.Unmarshal(data, &rules); err != nil {
		return nil, err
	}

	return rules, nil
}
