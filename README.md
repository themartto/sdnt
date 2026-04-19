# sdnt


sdnt (Simple Doman Name Tools) web API for for looking up DNS records, WHOIS data, SSL certificate info of any domain.


Check the live version at [api.sdnt.info](https://api.sdnt.info) or the web interface [sdnt.info](https://sdnt.info)


Built with Rust + Actix-web.

## Features

- **DNS lookup** — query DNS records from multiple geographic locations worldwide
- **WHOIS lookup** — retrieve domain registration info
- **SSL inspection** — fetch and parse TLS certificate details

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/dns` | DNS record lookup |
| GET | `/whois` | WHOIS lookup |
| GET | `/ssl` | SSL certificate info |
| GET | `/ip` | Request Origin address info |

## Running locally

**Prerequisites:** Rust (edition 2024)

```bash
cargo run
```

The server starts on `0.0.0.0:8080` by default (configurable in `config.toml`).

## Configuration

Edit `config.toml` to set the server host/port and configure the DNS server locations used for multi-region lookups:

```toml
[server]
host = "0.0.0.0"
port = 8080

[[dns_servers]]
location = "New York, US"
ip = "1.1.1.1"
```

## Docker

```bash
docker build -t sdnt-api .
docker run -p 8080:8080 sdnt-api
```

## Rate limiting

Requests are rate-limited to 5 bursts, then 1 request/second per IP.