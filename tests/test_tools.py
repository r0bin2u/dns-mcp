import httpx
import pytest
import respx

from dns_mcp import (
    _normalize_domain,
    _parse_ip,
    geo_ip,
    resolve_dns,
    reverse_dns,
    whois_domain,
)

DOH = "https://dns.google/resolve"
RDAP_GITHUB = "https://rdap.org/domain/github.com"
RDAP_VERISIGN = "https://rdap.verisign.com/com/v1/domain/github.com"
IPGEO = "http://ip-api.com/json/140.82.121.4"


@respx.mock
async def test_resolve_dns_a_record():
    respx.get(DOH, params={"name": "github.com", "type": "A"}).mock(
        return_value=httpx.Response(200, json={
            "Status": 0,
            "Answer": [{"name": "github.com.", "type": 1, "TTL": 60, "data": "140.82.121.4"}],
        })
    )
    result = await resolve_dns("GitHub.com", "a")
    assert result["name"] == "github.com"
    assert result["type"] == "A"
    assert result["answers"][0]["data"] == "140.82.121.4"
    assert result["answers"][0]["ttl"] == 60


@respx.mock
async def test_resolve_dns_mx_record():
    respx.get(DOH, params={"name": "example.com", "type": "MX"}).mock(
        return_value=httpx.Response(200, json={
            "Status": 0,
            "Answer": [
                {"name": "example.com.", "type": 15, "TTL": 300, "data": "10 mail.example.com."},
            ],
        })
    )
    result = await resolve_dns("example.com", "MX")
    assert result["answers"][0]["data"] == "10 mail.example.com."


async def test_resolve_dns_rejects_bad_type():
    with pytest.raises(ValueError, match="record_type"):
        await resolve_dns("example.com", "ZZZ")


@respx.mock
async def test_reverse_dns_ipv4():
    respx.get(DOH, params={"name": "4.121.82.140.in-addr.arpa", "type": "PTR"}).mock(
        return_value=httpx.Response(200, json={
            "Status": 0,
            "Answer": [{
                "name": "4.121.82.140.in-addr.arpa.",
                "type": 12, "TTL": 3600,
                "data": "lb-140-82-121-4-fra.github.com.",
            }],
        })
    )
    result = await reverse_dns("140.82.121.4")
    assert result["arpa"] == "4.121.82.140.in-addr.arpa"
    assert result["hostnames"] == ["lb-140-82-121-4-fra.github.com"]


async def test_reverse_dns_rejects_bad_ip():
    with pytest.raises(ValueError, match="Invalid IP"):
        await reverse_dns("not-an-ip")


@respx.mock
async def test_whois_domain_follows_redirect_and_extracts_registrar():
    respx.get(RDAP_GITHUB).mock(
        return_value=httpx.Response(302, headers={"Location": RDAP_VERISIGN})
    )
    respx.get(RDAP_VERISIGN).mock(
        return_value=httpx.Response(200, json={
            "ldhName": "GITHUB.COM",
            "handle": "1264983250_DOMAIN_COM-VRSN",
            "status": ["client delete prohibited"],
            "events": [
                {"eventAction": "registration", "eventDate": "2007-10-09T18:20:50Z"},
                {"eventAction": "expiration", "eventDate": "2026-10-09T18:20:50Z"},
            ],
            "entities": [{
                "roles": ["registrar"],
                "vcardArray": ["vcard", [
                    ["version", {}, "text", "4.0"],
                    ["fn", {}, "text", "MarkMonitor Inc."],
                ]],
            }],
            "nameservers": [{"ldhName": "DNS1.P08.NSONE.NET"}],
        })
    )
    result = await whois_domain("GitHub.com")
    assert result["domain"] == "github.com"
    assert result["registrar"] == "MarkMonitor Inc."
    assert result["registered"] == "2007-10-09T18:20:50Z"
    assert result["expires"] == "2026-10-09T18:20:50Z"
    assert result["nameservers"] == ["dns1.p08.nsone.net"]


@respx.mock
async def test_geo_ip_public():
    respx.get(IPGEO).mock(
        return_value=httpx.Response(200, json={
            "status": "success",
            "country": "Germany",
            "countryCode": "DE",
            "regionName": "Hesse",
            "city": "Frankfurt am Main",
            "lat": 50.1, "lon": 8.7,
            "timezone": "Europe/Berlin",
            "isp": "GitHub, Inc.", "org": "GitHub, Inc.",
            "as": "AS36459 GitHub, Inc.",
        })
    )
    result = await geo_ip("140.82.121.4")
    assert result["country"] == "Germany"
    assert result["asn"] == "AS36459 GitHub, Inc."


async def test_geo_ip_rejects_private():
    with pytest.raises(ValueError, match="private/reserved"):
        await geo_ip("192.168.1.1")


async def test_geo_ip_rejects_loopback():
    with pytest.raises(ValueError, match="private/reserved"):
        await geo_ip("127.0.0.1")


@respx.mock
async def test_geo_ip_surfaces_upstream_error():
    respx.get("http://ip-api.com/json/8.8.8.8").mock(
        return_value=httpx.Response(200, json={"status": "fail", "message": "reserved range"})
    )
    with pytest.raises(RuntimeError, match="ip-api.com error"):
        await geo_ip("8.8.8.8")


@pytest.mark.parametrize("bad", ["", " ", "foo bar.com", "foo/bar.com"])
def test_normalize_domain_rejects_bad(bad):
    with pytest.raises(ValueError):
        _normalize_domain(bad)


def test_normalize_domain_strips_and_lowers():
    assert _normalize_domain("  GitHub.COM.  ") == "github.com"


def test_parse_ip_ipv4_and_ipv6():
    assert str(_parse_ip("140.82.121.4")) == "140.82.121.4"
    assert str(_parse_ip("2606:4700::1111")) == "2606:4700::1111"


def test_parse_ip_rejects_garbage():
    with pytest.raises(ValueError):
        _parse_ip("not-an-ip")
