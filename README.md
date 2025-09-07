
# BugScanX-Go

**Advanced SNI Bug Host Scanner** - Enhanced fork of BugScanner-Go with improved features, speed, and reliability.

[![Telegram](https://img.shields.io/badge/Telegram-Join%20Group-0088cc?style=flat-square&logo=telegram)](https://t.me/BugscanX)
[![Go Version](https://img.shields.io/github/go-mod/go-version/Ayanrajpoot10/bugscanx-go?style=flat-square)](https://github.com/Ayanrajpoot10/bugscanx-go)
[![License](https://img.shields.io/github/license/Ayanrajpoot10/bugscanx-go?style=flat-square)](LICENSE)
[![Release](https://img.shields.io/github/v/release/Ayanrajpoot10/bugscanx-go?style=flat-square)](https://github.com/Ayanrajpoot10/bugscanx-go/releases)

## Installation

### Prebuilt Binaries
Download the latest prebuilt binary directly from the [Releases](https://github.com/Ayanrajpoot10/bugscanx-go/releases) section. Available for Windows, Linux, and macOS.

### Build from Source

```bash
go install github.com/ayanrajpoot10/bugscanx-go@latest
```

## Usage

### Quick Start
```bash
# Show all available commands
bugscanx-go --help

# Direct scan
bugscanx-go direct -f domains.txt -o output.txt

# CDN SSL scan
bugscanx-go cdn-ssl --proxy-filename proxies.txt --target example.com

# SNI scan with custom parameters
bugscanx-go sni -f subdomains.txt --threads 16 --timeout 8 --deep 3
```

### Available Commands
- `direct` - Direct domain scanning
- `cdn-ssl` - CDN SSL scanning
- `proxy` - Proxy-based scanning
- `sni` - SNI (Server Name Indication) scanning
- `ping` - TCP ping scanning

## Features
- High-performance concurrent scanning
- Multiple scan modes for different use cases
- Customizable thread count and timeout settings
- Output results to files for further processing
- Cross-platform support (Windows, Linux, macOS)

## Contributing
Contributions are welcome! Please feel free to submit issues, feature requests, or pull requests.

## Support
Join our [Telegram group](https://t.me/BugscanX) for support, updates, and discussions.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.