# Iran-Proxy-Unified Architecture

## System Overview

Iran-Proxy-Unified is a three-tier proxy configuration management system designed for Iran's restrictive network environment. It combines high-performance config aggregation with advanced DPI evasion techniques.

```
┌─────────────────────────────────────────────────────────────┐
│                    External Config Sources                   │
│  (barry-far, v2go, ssrshare, trojan repositories, etc.)     │
└────────────────┬────────────────────────────────────────────┘
                 │
        ┌────────▼────────┐
        │   Fetching      │
        │  (HTTP/HTTPS)   │
        └────────┬────────┘
                 │
    ┌────────────▼──────────────┐
    │   GO CORE MODULE           │
    │  (Config Aggregation)      │◄─── Config Sources (YAML)
    │                            │     Iran Rules (JSON)
    │ • Deduplication           │     Obfuscation Rules
    │ • Filtering               │
    │ • Format Conversion       │
    │ • Caching                 │
    └────────────┬──────────────┘
                 │
    ┌────────────▼──────────────┐
    │  RUST SECURITY MODULE     │
    │  (Anti-DPI Features)      │
    │                            │
    │ • Pattern Rotation        │
    │ • Traffic Obfuscation     │
    │ • DPI Bypass              │
    │ • Detection Evasion       │
    └────────────┬──────────────┘
                 │
    ┌────────────▼──────────────┐
    │ SUBSCRIPTION GENERATION   │
    │                            │
    │ • Clash Format            │
    │ • Sing-box Format         │
    │ • V2Ray Format            │
    │ • Raw Format              │
    └────────────┬──────────────┘
                 │
        ┌────────▼────────┐
        │   GitHub Pages  │
        │  (Distribution) │
        └─────────────────┘
```

## Component Architecture

### 1. Go Core Module (`/core`)

**Responsibilities:**
- Fetch proxy configs from multiple sources
- Parse and validate configurations
- Apply filtering rules
- Deduplicate configs
- Generate subscriptions in multiple formats
- Manage caching

**Key Files:**
- `main.go` - Entry point and CLI interface
- `aggregator.go` - Core aggregation logic
- `subscription.go` - Subscription format generation
- `cache.go` - In-memory caching with TTL
- `filter.go` - Filtering and Iran-specific rules

**Data Flow:**
```
Fetch Sources → Parse Configs → Apply Filters → Deduplicate →
             ↓
        Cache Results
             ↓
    Generate Subscriptions
```

**Performance Targets:**
- Process 20,000+ configs in ~11 seconds
- Memory usage: < 500MB for 20,000 configs
- Cache hit rate: 70-80% for repeat sources

### 2. Rust Security Module (`/security`)

**Responsibilities:**
- Implement advanced DPI evasion techniques
- Pattern rotation engine
- Traffic obfuscation
- Timing randomization
- AI/ML detection evasion
- Integration with Go core

**Key Files:**
- `lib.rs` - Main security processor
- `obfuscation.rs` - HTTP/HTTPS traffic disguise
- `pattern_rotation.rs` - Protocol signature rotation
- `dpi_bypass.rs` - DPI evasion techniques
- `detection_evasion.rs` - ML-based detection evasion
- `config.rs` - Configuration management
- `error.rs` - Error types

**Security Layers:**
```
Level 1: Obfuscation
  └─ HTTP header injection
  └─ Random padding
  └─ Noise injection

Level 2: Pattern Rotation
  └─ Signature randomization
  └─ TLS variation
  └─ Connection parameter randomization

Level 3: DPI Bypass
  └─ Packet fragmentation
  └─ TLS handshake manipulation
  └─ DNS tunneling simulation

Level 4: Detection Evasion
  └─ Feature scrambling
  └─ Behavior randomization
  └─ Decoy traffic injection
  └─ Adaptive strategies
```

### 3. Python Utilities (`/utils`)

**Responsibilities:**
- Configuration validation
- Source management and updates
- GitHub Actions integration
- Testing and reporting

**Key Files:**
- `validator.py` - Configuration file validation
- `source_manager.py` - Source management and fetching
- `github_actions_helper.py` - Workflow orchestration
- `requirements.txt` - Python dependencies

### 4. Configuration Files (`/config`)

**sources.yaml:**
- Defines proxy config sources
- Source type (base64, json, plain)
- Fetch timeout and interval settings
- Per-source enable/disable

**iran_rules.json:**
- Filtering rules for protocols, countries, domains
- Iran-specific optimizations
- Protocol compatibility checks
- ISP optimization settings

**obfuscation_rules.yaml:**
- DPI evasion strategy definitions
- Technique parameters and settings
- Thresholds for Iran's environment
- Adaptive evasion settings

### 5. GitHub Actions Workflows (`/.github/workflows`)

**update_configs.yml:**
- Runs every 6 hours
- Fetches latest configs
- Generates subscriptions
- Commits and pushes updates
- Auto-deploy to GitHub Pages

**test_and_validate.yml:**
- Validates configurations
- Runs unit tests
- Builds binaries
- Checks code quality

## Data Flow

### Config Update Pipeline
```
1. Schedule Trigger (6 hours)
   │
   ├─ Checkout repository
   ├─ Setup Go, Rust, Python
   │
2. Config Fetching
   ├─ Read source definitions
   ├─ Fetch from all enabled sources
   ├─ Parse based on source type
   │
3. Filtering & Processing
   ├─ Apply Iran-specific rules
   ├─ Validate each config
   ├─ Deduplicate
   │
4. DPI Enhancement
   ├─ Apply obfuscation
   ├─ Add pattern variation
   ├─ Inject evasion headers
   │
5. Subscription Generation
   ├─ Convert to Clash format
   ├─ Convert to Sing-box format
   ├─ Convert to V2Ray format
   ├─ Generate raw list
   │
6. Storage & Distribution
   ├─ Store subscription files
   ├─ Commit to repository
   ├─ Push to GitHub
   └─ Available via GitHub Pages
```

## Anti-DPI Strategies

### 1. Traffic Obfuscation
- HTTP header spoofing
- User-agent randomization
- Fake HTTPS headers
- HTTP Keep-Alive simulation
- Random padding injection

### 2. Pattern Rotation
- Hourly protocol signature rotation
- Random cipher suite reordering
- Connection parameter randomization
- TLS fingerprint variation
- Timing-based transformation

### 3. DPI Bypass
- Packet fragmentation (random size chunks)
- TLS record level fragmentation
- DNS tunneling simulation
- Mirrored traffic injection
- Time-based transformation

### 4. AI/ML Detection Evasion
- Feature scrambling
- Behavior randomization (slow/burst/mixed)
- Decoy traffic injection (20% random)
- Adaptive response levels (1-5)
- Ensemble approach combining multiple techniques

## Performance Characteristics

| Metric | Target | Achieved |
|--------|--------|----------|
| Config Processing | 20,000+/11sec | Optimized |
| Memory Usage | < 500MB | Efficient |
| Deduplication | 30-40% reduction | Effective |
| Update Interval | 6 hours | Automated |
| Cache Hit Rate | 70-80% | Good |
| DPI Evasion Success | 95%+ | High |

## Security Considerations

1. **No Local Storage**: Configs cached only in memory with TTL
2. **HTTPS Communication**: All source fetching uses HTTPS
3. **Configuration Validation**: All inputs validated before use
4. **Error Handling**: Safe error handling with no credential exposure
5. **Update Frequency**: Regular updates prevent stale config usage
6. **Multi-Layer Defense**: Combines 4 independent evasion strategies

## Deployment

### Local Deployment
```bash
cd core
./aggregator -mode=generate -format=clash -output=subscriptions/main.txt
```

### Automated Deployment
- GitHub Actions on schedule (every 6 hours)
- Automatic config updates
- Auto-commit and push
- Distribution via GitHub Pages

### Docker Deployment (Future)
- Containerized Go and Rust modules
- Easy deployment on any server
- Docker Compose support

## Integration Points

### External Sources
- GitHub repositories (raw content)
- Public subscription APIs
- Custom sources (via configuration)

### Proxy Clients
- Clash (via subscription URL)
- Sing-box (via JSON)
- V2Ray (via config format)
- Shadowsocks clients (direct support)
- Custom applications (raw format)

## Monitoring & Telemetry

- Config fetch success rate (per source)
- Config count per source
- Deduplication statistics
- Subscription generation metrics
- GitHub Actions workflow status

## Future Enhancements

1. **Extended Protocol Support**: Add Hysteria, Tuic protocols
2. **Real-time Analysis**: Monitor DPI blocks in real-time
3. **Machine Learning**: Train models on detected patterns
4. **API Server**: REST API for programmatic access
5. **Web Dashboard**: Visual management interface
6. **Geographic Distribution**: CDN-like distribution
7. **User Feedback Loop**: Community-driven improvements

## References

- [V2Ray Project](https://v2fly.org/)
- [REALITY Protocol](https://github.com/XTLS/REALITY)
- [XHTTP Protocol](https://github.com/tobyxdd/hysteria2)
- [DPI Evasion Techniques](https://github.com/zhouyongtao/trojan)
- [Clash Subscription Format](https://github.com/MetaCubeX/Clash.Meta)
