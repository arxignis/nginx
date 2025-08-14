# nginx

## 🎉 Join Our Discord Community! 🎉

Come hang out with us and be part of our awesome community on Discord! Whether you're here to chat, get support, or just have fun, everyone is welcome.

[![Join us on Discord](https://img.shields.io/badge/Join%20Us%20on-Discord-5865F2?logo=discord&logoColor=white)](https://discord.gg/jzsW5Q6s9q)

See you there! 💬✨

This directory contains a custom nginx Docker image built with OpenResty and various security and performance modules.

## Base Image
- **Base**: Alpine Linux 3.22
- **OpenResty**: 1.27.1.2
- **Nginx**: 1.27.1

## Core Components

### OpenSSL
- **Version**: 3.4.1
- **Features**: TLS 1.3, KTLS, FIPS support, weak SSL ciphers enabled

### PCRE2
- **Version**: 10.44
- **Features**: JIT compilation, Unicode support

## Security Modules

### ModSecurity
- **Version**: 3.0.14
- **Nginx Module**: 1.0.4
- **Features**: Web Application Firewall (WAF), LMDB storage

### JA4 Fingerprinting
- **Version**: 1.3.1-beta
- **Features**: TLS client fingerprinting, JA4 support

### HTTP Auth Digest
- **Version**: 1.0.0
- **Features**: Digest authentication support

## Performance & Compression

### Brotli
- **Commit**: 6e975bcb015f62e1f303054897783355e2a877dc
- **Features**: Brotli compression algorithm

### Dynamic ETag
- **Version**: 0.2.1
- **Features**: Dynamic ETag generation

## Geo-location & IP

### GeoIP2
- **Version**: 3.4
- **Features**: MaxMind GeoIP2 database support

## Monitoring & Observability

### OpenTelemetry
- **Version**: 0.1.1
- **Features**: Distributed tracing and metrics

## Lua & Extensions

### LuaRocks
- **Version**: 3.12.2
- **Features**: Lua package manager

### Lua Resty Balancer
- **Version**: 0.05
- **Features**: Load balancing utilities

### Arxignis Integration
- **Version**: 1.0-0
- **Features**: Custom Arxignis functionality

## Build Features

### Nginx Modules
- HTTP/2 and HTTP/3 support
- Stream module with SSL
- Real IP module
- Auth request module
- Image filter module
- XSLT module
- Gzip and gunzip modules
- Slice module
- Secure link module

### Compilation
- Multi-threaded compilation
- JIT compilation enabled
- Optimized CFLAGS (-g -O3)
- Shared library support

## Runtime Configuration

### User
- **User**: www-data (UID: 101)
- **Group**: www-data

### Directories
- Logs: `/var/log/nginx/`
- Configuration: `/etc/nginx/`
- Temporary files: `/var/lib/nginx/`
- ModSecurity: `/opt/modsecurity/`

### Signals
- **Stop Signal**: SIGQUIT (graceful shutdown)

## Usage

```bash
# Build the image
docker build -t arxignis/nginx .

# Run the container
docker run -d -p 80:80 -p 443:443 arxignis/nginx
```

## Dependencies

The image includes comprehensive build dependencies and runtime packages for Alpine Linux, including:
- Build tools (gcc, make, cmake)
- Development libraries (pcre-dev, geoip-dev, brotli-dev)
- Runtime libraries (gd, geoip, brotli, lmdb)
- Additional tools (git, curl, wget, dumb-init)
