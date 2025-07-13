
<h1 align="center">BugScanX-Go</h1>

<p align="center"><b>Advanced SNI Bug Host Scanner</b></p>
<p align="center">Enhanced fork of BugScanner-Go with improved features, speed, and reliability.</p>

<div align="center">
  <a href="https://t.me/BugscanX">
    <img src="https://img.shields.io/badge/Telegram-Join%20Group-0088cc?style=for-the-badge&logo=telegram" alt="Telegram">
  </a>
  <img src="https://img.shields.io/github/go-mod/go-version/Ayanrajpoot10/bugscanx-go?style=for-the-badge" alt="Go Version">
  <img src="https://img.shields.io/github/license/Ayanrajpoot10/bugscanx-go?style=for-the-badge" alt="License">
</div>


## Installation

```bash
go install -v github.com/Ayanrajpoot10/bugscanx-go@latest
# Add Go bin to your PATH if needed:
echo 'export PATH="$PATH:$HOME/go/bin"' >> $HOME/.bashrc && source $HOME/.bashrc
```

---

## Usage

Show help:
```bash
bugscanx-go --help
```

### Example Commands

**Direct scan:**
```bash
bugscanx-go direct -f example.txt -o cf.txt
```

**CDN SSL scan:**
```bash
bugscanx-go cdn-ssl --proxy-filename cf.txt --target ws.example.com
```

**Proxy scan:**
```bash
bugscanx-go proxy -f example.txt --target ws.example.com
```

**SNI scan:**
```bash
bugscanx-go sni -f example.com.txt --threads 16 --timeout 8 --deep 3
```

**Ping scan:**
```bash
bugscanx-go ping -f example.txt --threads 15 -o save.txt
```

---

## Integrations & Tips

- For subdomain enumeration, use [Subfinder](https://github.com/projectdiscovery/subfinder#installation).
- Output files can be used as input for other tools in your workflow.
- Join our [Telegram](https://t.me/BugscanX) for support and updates.

---

## Contributing

Contributions, bug reports, and feature requests are welcome! Please open an issue or pull request.

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.