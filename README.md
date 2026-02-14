# Iran-Proxy-Unified

A comprehensive, intelligent proxy configuration aggregator and manager designed specifically for Iran's restrictive network environment. Combines the power of multiple existing projects (v2go, V2ray-Config, Iran-v2ray-rules, REALITY, XHTTP) into one unified, professional solution.

## Features

### Core Capabilities
- **Fast Config Aggregation**: Process 20,000+ proxy configurations in ~11 seconds
- **Automatic Updates**: Refresh subscriptions every 6 hours via GitHub Actions
- **Multiple Formats**: Generate subscriptions in Clash, Sing-box, V2Ray, and raw formats
- **Intelligent Deduplication**: Remove duplicate configs while preserving quality
- **Caching System**: Smart caching mechanism with automatic expiration

### Advanced Anti-DPI Features
- **Pattern Rotation**: Regularly rotate proxy patterns to avoid fingerprinting
- **Traffic Obfuscation**: Mimic legitimate HTTPS traffic
- **AI/ML Detection Evasion**: Evade machine learning-based detection systems
- **Packet Fragmentation**: Fragment packets to bypass pattern detection
- **Protocol Support**: REALITY, XHTTP, VMess, VLESS, Shadowsocks, Trojan
- **Behavior Randomization**: Variable connection patterns to prevent classification

### Iran-Specific Optimization
- **Filtering Rules**: Custom rules optimized for Iran's network
- **Protocol Compatibility**: Ensure configs work in Iran's restricted environment
- **ISP Optimization**: Performance improvement for Iranian ISPs
- **Firewall Bypass**: Techniques to bypass Iran-specific firewalls
- **24/7 Monitoring**: Track DPI updates and adapt automatically

## Project Structure

```
iran-proxy-unified/
├── core/                    # Go aggregator (main processing engine)
├── security/                # Rust anti-DPI module (advanced evasion)
├── utils/                   # Python utilities (orchestration & tools)
├── config/                  # Configuration files
├── .github/workflows/       # GitHub Actions automation
├── tests/                   # Testing suite
├── docs/                    # Documentation
└── subscriptions/           # Generated subscription files
```

## Tech Stack

- **Go**: Fast config aggregation, subscription generation, and orchestration
- **Rust**: Advanced DPI bypass techniques, pattern rotation, traffic obfuscation
- **Python**: GitHub Actions integration, rule management, testing utilities

## Quick Start

### Prerequisites
- Go 1.21+
- Rust 1.70+ (for security module)
- Python 3.8+ (for utilities)
- GitHub repository (for CI/CD automation)

### Installation

```bash
# Clone the repository
git clone https://github.com/fcfcggail-gif/iran-proxy-unified.git
cd iran-proxy-unified

# Build Go module
cd core
go mod download
go build -o aggregator main.go aggregator.go subscription.go cache.go filter.go

# Build Rust module
cd ../security
cargo build --release

# Install Python dependencies
cd ../utils
pip install -r requirements.txt
```

### Usage

#### Generate Subscriptions
```bash
cd core
./aggregator -mode=generate -format=clash -output=subscriptions/main.txt
```

#### Available Modes
- `generate`: Fetch configs and generate subscriptions
- `fetch`: Only fetch configs from sources
- `validate`: Validate configuration files

#### Output Formats
- `clash`: Clash subscription format
- `singbox`: Sing-box configuration
- `v2ray`: V2Ray configuration format
- `raw`: Raw proxy list

#### Examples
```bash
# Generate Clash subscription
./aggregator -mode=generate -format=clash -output=subscriptions/clash.txt

# Generate Sing-box subscription
./aggregator -mode=generate -format=singbox -output=subscriptions/singbox.json

# Validate configurations
./aggregator -mode=validate

# Verbose output
./aggregator -mode=generate -format=clash -v
```

## Configuration Files

### sources.yaml
Define external sources for proxy configurations:
```yaml
sources:
  - name: source-name
    url: https://example.com/configs
    type: base64|json|plain
    enabled: true
    timeout: 30
    interval: 360
```

### iran_rules.json
Define filtering and optimization rules:
```json
[
  {
    "name": "Include VMess protocol",
    "type": "protocol",
    "pattern": "vmess",
    "action": "include",
    "enabled": true
  }
]
```

### obfuscation_rules.yaml
Define DPI evasion strategies:
```yaml
obfuscation_strategies:
  - name: "HTTP Obfuscation"
    type: "http"
    enabled: true
    rules:
      - technique: "fake-http-headers"
        enabled: true
```

## Automation with GitHub Actions

The project includes automated workflows that:
1. Run every 6 hours
2. Fetch latest configs from configured sources
3. Apply Iran-specific filtering rules
4. Generate subscriptions in multiple formats
5. Commit changes to the repository
6. Update deployment systems

Configure `ACTIONS_TOKEN` secret in GitHub to enable automated commits.

## Advanced Features

### Anti-AI DPI Protection
Implements multi-layered evasion:
- Feature scrambling to randomize classifiable characteristics
- Adaptive response to new detection methods
- Decoy traffic injection (20% random traffic)
- Variable timing to prevent timing attacks
- Ensemble based approach combining multiple techniques

### Pattern Rotation Engine (Rust)
- Rotate protocol signatures every hour
- Randomize connection parameters
- Vary TLS handshake characteristics
- Implement behavior unpredictability

### Application Support
- **Clash**: Native support
- **Sing-box**: Full JSON configuration
- **V2Ray**: Configuration file format
- **Shadowsocks**: Direct protocol support
- **Trojan**: Full implementation

## Performance Benchmarks

- Config aggregation: 20,000+ configs in ~11 seconds
- Deduplication: Removes 30-40% redundant entries
- Memory usage: < 500MB for 20,000 configs
- Update interval: Every 6 hours

## Security

- No configs stored locally permanently (cached only)
- HTTPS-only communication with sources
- Validation of all input configurations
- Safe error handling with no credential exposure

## Documentation

- [ARCHITECTURE.md](docs/ARCHITECTURE.md) - Detailed system architecture
- [SETUP.md](docs/SETUP.md) - Complete setup guide
- [API.md](docs/API.md) - API documentation
- [DPI_EVASION.md](docs/DPI_EVASION.md) - Advanced DPI evasion techniques

## Contributing

Contributions are welcome! Areas for improvement:
- New proxy protocols
- Enhanced DPI evasion techniques
- Performance optimization
- Testing and quality assurance
- Documentation

## License

This project is provided as-is for educational and authorized security testing purposes.

## Disclaimer

This project is designed for lawful use in jurisdictions where circumvention of internet filters is legal. Users are responsible for understanding and complying with applicable laws in their region.

## Support

- Report issues: [GitHub Issues](https://github.com/fcfcggail-gif/iran-proxy-unified/issues)
- Request features: [GitHub Discussions](https://github.com/fcfcggail-gif/iran-proxy-unified/discussions)

---

**Built with**: Go, Rust, Python | **For**: Iran's Network Environment | **By**: Community Contributors