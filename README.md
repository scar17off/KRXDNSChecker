# KRX DNS Checker

A Windows utility to test Cracked API DNS servers for status.

## Features
- Tests DNS servers from a list
- Automatically sets and verifies DNS settings
- Checks connectivity to Cracked API
- Provides detailed test results with working/failed DNS servers
- Automatically resets DNS to DHCP on exit

## Requirements for using
- Windows 10/11
- Administrator privileges

## Requirements for building
- Visual Studio 2022 with C++ development tools
- vcpkg package manager

## Building
1. Clone the repository
```bash
git clone https://github.com/scar17off/KRXDNSChecker
cd KRXDNSChecker
```

2. Build using CMake
```bash
mkdir build
cd build
cmake ..
```

## Usage
1. Create a `dns_servers.txt` file with DNS servers (one per line)
2. Run the program as Administrator
3. Wait for the test results
4. DNS will automatically reset to DHCP on exit

## License
MIT License - see [LICENSE.md](LICENSE.md)
