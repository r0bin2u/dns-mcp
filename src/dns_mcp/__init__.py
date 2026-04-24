"""MCP server for DNS resolution, RDAP (WHOIS), and IP geolocation."""
from __future__ import annotations

import ipaddress

import httpx
from mcp.server.fastmcp import FastMCP

DOH_URL = "https://dns.google/resolve"
RDAP_URL = "https://rdap.org/domain"
IPGEO_URL = "http://ip-api.com/json"

VALID_RECORD_TYPES = {"A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "PTR", "SRV", "CAA"}

mcp = FastMCP("dns-mcp")


def _normalize_domain(name: str) -> str:
    n = name.strip().rstrip(".").lower()
    if not n or " " in n or "/" in n:
        raise ValueError(f"Invalid domain {name!r}")
    return n


def _parse_ip(ip: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        return ipaddress.ip_address(ip.strip())
    except ValueError as e:
        raise ValueError(f"Invalid IP address {ip!r}") from e


@mcp.tool()
async def resolve_dns(name: str, record_type: str = "A") -> dict:
    """Resolve a domain name via DNS-over-HTTPS. Returns answer records and TTL.

    Args:
        name: Domain to look up, e.g. "github.com".
        record_type: DNS record type. One of A, AAAA, CNAME, MX, TXT, NS, SOA, PTR, SRV, CAA.
    """
    domain = _normalize_domain(name)
    rtype = record_type.strip().upper()
    if rtype not in VALID_RECORD_TYPES:
        raise ValueError(
            f"Unsupported record_type {record_type!r}. "
            f"Valid types: {', '.join(sorted(VALID_RECORD_TYPES))}"
        )
    async with httpx.AsyncClient(timeout=10.0) as client:
        r = await client.get(DOH_URL, params={"name": domain, "type": rtype})
        r.raise_for_status()
        data = r.json()
    return {
        "name": domain,
        "type": rtype,
        "status": data.get("Status"),
        "answers": [
            {
                "name": a.get("name"),
                "type": a.get("type"),
                "ttl": a.get("TTL"),
                "data": a.get("data"),
            }
            for a in data.get("Answer", [])
        ],
        "authority": [
            {
                "name": a.get("name"),
                "type": a.get("type"),
                "ttl": a.get("TTL"),
                "data": a.get("data"),
            }
            for a in data.get("Authority", [])
        ],
    }


@mcp.tool()
async def reverse_dns(ip: str) -> dict:
    """Reverse-resolve an IP address to its PTR record (the hostname it points to).

    Args:
        ip: IPv4 or IPv6 address, e.g. "140.82.121.4".
    """
    parsed = _parse_ip(ip)
    arpa = parsed.reverse_pointer
    async with httpx.AsyncClient(timeout=10.0) as client:
        r = await client.get(DOH_URL, params={"name": arpa, "type": "PTR"})
        r.raise_for_status()
        data = r.json()
    return {
        "ip": str(parsed),
        "arpa": arpa,
        "status": data.get("Status"),
        "hostnames": [a.get("data", "").rstrip(".") for a in data.get("Answer", [])],
    }


@mcp.tool()
async def whois_domain(domain: str) -> dict:
    """Look up domain registration info via RDAP (the modern structured WHOIS).

    Args:
        domain: Domain name, e.g. "github.com".
    """
    name = _normalize_domain(domain)
    headers = {"Accept": "application/rdap+json"}
    async with httpx.AsyncClient(timeout=15.0, follow_redirects=True, headers=headers) as client:
        r = await client.get(f"{RDAP_URL}/{name}")
        r.raise_for_status()
        data = r.json()
    events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])}
    registrar = None
    for ent in data.get("entities", []):
        if "registrar" in (ent.get("roles") or []):
            vcard = ent.get("vcardArray") or []
            if len(vcard) >= 2:
                for field in vcard[1]:
                    if isinstance(field, list) and len(field) >= 4 and field[0] == "fn":
                        registrar = field[3]
                        break
            break
    return {
        "domain": data.get("ldhName", name).lower(),
        "handle": data.get("handle"),
        "status": data.get("status", []),
        "registered": events.get("registration"),
        "expires": events.get("expiration"),
        "last_changed": events.get("last changed"),
        "registrar": registrar,
        "nameservers": [ns.get("ldhName", "").lower() for ns in data.get("nameservers", [])],
    }


@mcp.tool()
async def geo_ip(ip: str) -> dict:
    """Locate an IP address geographically. Returns country, city, ASN, and ISP.

    Args:
        ip: Public IPv4 or IPv6 address. Private/reserved ranges are rejected.
    """
    parsed = _parse_ip(ip)
    if parsed.is_private or parsed.is_loopback or parsed.is_reserved:
        raise ValueError(
            f"{parsed} is a private/reserved address; geolocation is only for public IPs."
        )
    async with httpx.AsyncClient(timeout=10.0) as client:
        r = await client.get(f"{IPGEO_URL}/{parsed}")
        r.raise_for_status()
        data = r.json()
    if data.get("status") != "success":
        raise RuntimeError(f"ip-api.com error for {parsed}: {data.get('message', 'unknown')}")
    return {
        "ip": str(parsed),
        "country": data.get("country"),
        "country_code": data.get("countryCode"),
        "region": data.get("regionName"),
        "city": data.get("city"),
        "lat": data.get("lat"),
        "lon": data.get("lon"),
        "timezone": data.get("timezone"),
        "isp": data.get("isp"),
        "org": data.get("org"),
        "asn": data.get("as"),
    }


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
