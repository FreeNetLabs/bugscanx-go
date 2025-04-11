<h1 align="center"> BugScanX-Go: Advanced SNI Bug Host Scanner</h1>

<p align="center">
   <i>Enhanced fork of BugScanner-Go with improved features and performance</i>
</p>

<div align="center">
   <a href="https://github.com/Ayanrajpoot10/BugScanX-Go/stargazers">
      <img src="https://img.shields.io/github/stars/Ayanrajpoot10/BugScanX-Go?style=for-the-badge&color=green" alt="Stars">
   </a>
   <a href="https://t.me/BugscanX">
      <img src="https://img.shields.io/badge/Telegram-Join%20Group-0088cc?style=for-the-badge&logo=telegram" alt="Telegram">
   </a>
</div>

## Features
- Skips 302 redirects to recharge portals
- Saves all server results under "Others"
- Supports GET, PATCH, and PUT methods
- Dual scheme scanning (HTTP/HTTPS)
- Fast PING scan option
- Enhanced UI with improved color scheme

## Installation
```bash
go install -v github.com/Ayanrajpoot10/bugscanx-go@latest
echo 'export PATH="$PATH:$HOME/go/bin"' >> $HOME/.bashrc && source $HOME/.bashrc
```
## Usage

### Basic Commands
```bash
# Show help
bugscanx-go --help

# Direct scan
bugscanx-go scan direct -f example.txt -o cf.txt

# CDN SSL scan
bugscanx-go scan cdn-ssl --proxy-filename cf.txt --target ws.example.com

# SNI scan
bugscanx-go scan sni -f example.com.txt --threads 16 --timeout 8 --deep 3

# Ping scan
bugscanx-go scan ping -f example.txt --threads 15 -o save.txt

# DNS scan
bugscanx-go scan dns -f example.txt -o save.txt
```

Note: For subdomain gathering, install [Subfinder](https://github.com/projectdiscovery/subfinder#installation)