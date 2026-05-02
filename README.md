# dns-mcp

[![Listed in Awesome MCP Servers](https://srv-cdn.himpfen.io/badges/awesome-mcp-servers/awesome-flat.svg)](https://github.com/punkpeye/awesome-mcp-servers)
[![r0bin2u/dns-mcp MCP server](https://glama.ai/mcp/servers/r0bin2u/dns-mcp/badges/score.svg)](https://glama.ai/mcp/servers/r0bin2u/dns-mcp)

A [Model Context Protocol](https://modelcontextprotocol.io/) server that lets any MCP client (Claude Desktop, Claude Code, Cursor, etc.) do DNS, WHOIS, and IP geolocation lookups mid-conversation.

Ask Claude *"why is foo.com unreachable from Tokyo?"* and it can actually dig the records, check the WHOIS, and geo-locate the IP without leaving the chat.

## Features

- [x] `resolve_dns` — forward lookup via DNS-over-HTTPS (A, AAAA, CNAME, MX, TXT, NS, SOA, PTR, SRV, CAA)
- [x] `reverse_dns` — PTR lookup for IPv4 or IPv6
- [x] `whois_domain` — structured registration info via RDAP (modern WHOIS)
- [x] `geo_ip` — country / city / ASN / ISP for a public IP
- [ ] Bulk / zone transfer queries
- [ ] DNSSEC validation output
- [ ] Local cache (reduce repeated upstream calls)

No API keys required. All four tools hit public free endpoints:

| Tool | Upstream |
|------|----------|
| `resolve_dns`, `reverse_dns` | `dns.google` (DNS-over-HTTPS, JSON) |
| `whois_domain` | `rdap.org` (RDAP bootstrap, redirects to TLD registry) |
| `geo_ip` | `ip-api.com` (HTTP, 45 req/min free tier) |

## Quick Start

### Install

```bash
pipx install dns-mcp
# or
uv tool install dns-mcp
```

### Claude Desktop

Add to `claude_desktop_config.json` (macOS: `~/Library/Application Support/Claude/`, Windows: `%APPDATA%\Claude\`):

```json
{
  "mcpServers": {
    "dns": {
      "command": "dns-mcp"
    }
  }
}
```

Restart Claude Desktop; the four tools should show up in the tool menu.

### Claude Code

```bash
claude mcp add dns dns-mcp
```

### Codex CLI

Add to `~/.codex/config.toml`:

```toml
[mcp_servers.dns]
command = "dns-mcp"
```

Restart Codex. The four tools are then available in any Codex session.

### Run from source

```bash
git clone https://github.com/r0bin2u/dns-mcp && cd dns-mcp
uv sync
uv run dns-mcp
```

## Example Prompts

- *"What are github.com's A and MX records?"*
- *"Who registered cloudflare.com and when does it expire?"*
- *"Geolocate 140.82.121.4 — which country and ISP?"*
- *"My users in Tokyo say foo.com is slow. Resolve it, then geo-locate the IP."*
- *"I got an email from support@paypa1-security.com. Is that domain suspicious?"*

## Development

```bash
uv sync
uv run pytest
uv run ruff check .
```

Interactive debugging with the MCP Inspector:

```bash
npx @modelcontextprotocol/inspector uv run dns-mcp
```

## A note on `ip-api.com`

The free tier of `ip-api.com` requires **HTTP** (not HTTPS). This is fine for geolocating arbitrary public IPs — no credentials are sent — but it means the request is visible on the wire. If that's a concern in your environment, swap in a HTTPS alternative (e.g. `ipwho.is`, `ipinfo.io` with a token) by editing `IPGEO_URL` in `src/dns_mcp/__init__.py`.

## License

MIT — see [LICENSE](LICENSE).
