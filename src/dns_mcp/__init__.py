"""MCP server for DNS resolution, RDAP (WHOIS), and IP geolocation."""
from __future__ import annotations

import ipaddress

import httpx
from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

DOH_URL = "https://dns.google/resolve"
RDAP_URL = "https://rdap.org/domain"
IPGEO_URL = "http://ip-api.com/json"

VALID_RECORD_TYPES = {"A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "PTR", "SRV", "CAA"}

READ_ONLY_NETWORK = ToolAnnotations(
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=True,
)

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


@mcp.tool(annotations=READ_ONLY_NETWORK)
async def resolve_dns(name: str, record_type: str = "A") -> dict:
    """Resolve DNS records for a domain via DNS-over-HTTPS.

    Use when the user asks for a domain's IP address, mail servers, nameservers,
    or any DNS record type. Examples: "what's the A record of github.com",
    "show me the MX records of example.com", "is gmail.com's SPF set up",
    "which nameservers does cloudflare.com use".

    Returns: matching DNS records with TTL in `answers`, plus authoritative
    referrals in `authority`. Empty `answers` means the record type doesn't
    exist for that domain — that is a valid answer, not an error.

    For IP-to-hostname (PTR) lookups, use `reverse_dns` instead. For richer
    info about the IP behind a domain (country, ISP, ASN), follow up with
    `geo_ip` on the resolved address.

    Args:
        name: Domain to resolve, e.g. "github.com" or "mail.example.org".
            Trailing dots are stripped, case is normalized.
        record_type: One of A (IPv4), AAAA (IPv6), CNAME (alias), MX (mail
            exchanger), TXT (text records like SPF/DKIM/verification), NS
            (nameservers), SOA (zone authority), PTR (reverse pointer), SRV
            (service), CAA (certificate authority authorization). Defaults
            to "A".
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


@mcp.tool(annotations=READ_ONLY_NETWORK)
async def reverse_dns(ip: str) -> dict:
    """Reverse-lookup an IP address to find its PTR hostname.

    Use when the user wants to know what hostname is behind an IP, or to
    identify infrastructure from an IP seen in logs. Examples: "what is
    8.8.8.8's hostname", "reverse 140.82.121.4", "I see this IP hitting
    my server, who is it", "is this Google or AWS".

    Returns: the hostname(s) the IP's owner has set in their reverse DNS
    zone, with the in-addr.arpa / ip6.arpa name used. Empty `hostnames`
    means the IP has no PTR record — common for residential, mobile, and
    some cloud IPs whose owners haven't bothered to set one. Multiple
    hostnames are possible but rare.

    For domain-to-IP forward resolution, use `resolve_dns`. For country,
    city, ASN, and ISP info about the IP, use `geo_ip`.

    Args:
        ip: A public IPv4 or IPv6 address, e.g. "140.82.121.4" or
            "2606:4700::1111". The reverse-pointer name is computed
            automatically; you do not need to construct in-addr.arpa
            yourself.
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


@mcp.tool(annotations=READ_ONLY_NETWORK)
async def whois_domain(domain: str) -> dict:
    """Look up domain registration info via RDAP (the modern structured WHOIS).

    Use when the user wants to know who registered a domain, when, when it
    expires, or which registrar manages it. Especially useful for spotting
    suspicious or freshly-registered domains in phishing investigations.
    Examples: "who registered cloudflare.com", "when does github.com
    expire", "is paypa1-security.com a real domain or a phishing one",
    "is example.com about to expire".

    Returns: registration date, expiration date, last-changed date,
    registrar name, status flags (e.g. "client transfer prohibited"), and
    the domain's authoritative nameservers. RDAP is the IETF replacement
    for legacy text WHOIS; output is structured JSON, not a free-text blob.

    Works for most TLDs that operate a public RDAP server (.com, .net,
    .org, .io, most ccTLDs). A few TLDs (.cn and some EU ccTLDs) restrict
    access; calls to those domains may return partial data or fail with
    an HTTP error.

    For DNS records on the domain, use `resolve_dns`. For info about the
    IP a domain resolves to, use `geo_ip` after resolving.

    Args:
        domain: Domain name, e.g. "github.com" or "example.org". Pass the
            registrable parent — subdomains like "api.github.com" are not
            supported by RDAP.
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


@mcp.tool(annotations=READ_ONLY_NETWORK)
async def geo_ip(ip: str) -> dict:
    """Locate an IP geographically and identify the network operator.

    Use when the user wants to know where an IP is hosted, which network
    runs it, or what its ASN is. Useful for log analysis, debugging
    "why is X slow from Tokyo", or identifying CDN / cloud provider IPs.
    Examples: "where is 140.82.121.4", "which cloud provider runs
    35.190.60.75", "what country is this IP in", "is this an AWS or GCP IP".

    Returns: country, country code, region, city, lat/lon, timezone, ISP
    name, organization name, and ASN (e.g. "AS36459 GitHub, Inc."). Backed
    by ip-api.com (free 45 requests/minute, no API key).

    Rejects private (10.x, 172.16-31.x, 192.168.x), loopback (127.x), and
    reserved IPs — geolocation is meaningless for those. For just the
    hostname behind an IP, use `reverse_dns`.

    Args:
        ip: A public IPv4 or IPv6 address, e.g. "140.82.121.4" or
            "2606:4700::1111".
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
