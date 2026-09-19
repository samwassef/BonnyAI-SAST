"""Bounded GET collection with DNS validation and direct-IP socket connections."""

# Imports used by the request models, services, and helpers below.
import http.client
import ipaddress
import re
import socket
import ssl
import time

from app.operation import checkpoint
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit, urlunsplit

import dns.exception
import dns.resolver


# Represent collection failures using messages safe for the browser.
class FetchError(Exception):
    """Safe collection failure; never include raw remote data in error messages."""


# Normalize a web URL and reject unsupported hosts, credentials, ports, and characters.
def parse_url(url: str) -> tuple[str, str, int]:
    if (not url or len(url) > 8192 or not url.isascii()
            or any(ord(c) <= 32 or ord(c) == 127 for c in url) or "\\" in url
            or re.search(r"%(?![0-9a-fA-F]{2})|%(?:0[0-9a-f]|1[0-9a-f]|7f)", url, re.I)):
        raise FetchError("Invalid URL characters or length.")
    try:
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.netloc:
            raise ValueError()
        if any(c in parts.netloc for c in "@%[]") or parts.netloc.endswith(":"):
            raise ValueError()
        host = (parts.hostname or "").lower().removesuffix(".")
        # Validate DNS labels and exclude special local hostname forms.
        labels = host.split(".")
        if (len(host) > 253 or len(labels) < 2
                or not re.fullmatch(r"[a-z][a-z0-9-]*", labels[-1])
                or labels[-1].startswith("0x")
                or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", x)
                       for x in labels)
                or host.endswith((".localhost", ".local", ".internal"))):
            raise ValueError()
        port = parts.port if parts.port is not None else (443 if parts.scheme == "https" else 80)
        if port != (443 if parts.scheme == "https" else 80):
            raise ValueError()
        return urlunsplit((parts.scheme, host, parts.path or "/", parts.query, "")), host, port
    except ValueError:
        raise FetchError("Use an HTTP(S) DNS hostname, standard port, and no URL credentials.") from None


# Reject local/private destinations and IPv6 forms that could bypass address checks.
def validate_ip(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise FetchError("DNS returned an invalid address.") from None
    # Block address-translation forms that could obscure the true destination.
    transition = ("::/96", "::ffff:0:0/96", "64:ff9b::/96", "64:ff9b:1::/48",
                  "2001::/32", "2002::/16")
    if ("%" in value or not address.is_global or address.is_multicast or address.is_reserved
            or address.is_loopback or address.is_link_local
            or (address.version == 6 and any(address in ipaddress.ip_network(n) for n in transition))):
        raise FetchError("Private, metadata, local, reserved, or transition IP destinations are blocked.")
    return str(address)


# Check every IPv4 and IPv6 DNS answer before choosing a destination.
def resolve(host: str) -> list[str]:
    """Query both families; a failure in either family fails closed."""
    resolver = dns.resolver.Resolver()
    addresses = []
    try:
        # A private answer in either address family rejects the whole destination.
        for family in ("A", "AAAA"):
            try:
                answers = resolver.resolve(host + ".", family, lifetime=3, search=False)
                addresses.extend(str(answer) for answer in answers)
            except dns.resolver.NoAnswer:
                continue
    except dns.exception.DNSException:
        raise FetchError("DNS lookup failed or timed out.") from None
    if not addresses or len(addresses) > 64:
        raise FetchError("DNS returned no usable addresses or too many addresses.")
    return list(dict.fromkeys(validate_ip(address) for address in addresses))


# Connect to an approved IP while retaining the original hostname for HTTPS.
class PinnedConnection(http.client.HTTPConnection):
    # Store the approved destination and TLS settings for the connection.
    def __init__(self, host: str, port: int, ip: str, tls: bool):
        super().__init__(host, port, timeout=10)
        self.ip = ip
        self.tls = tls

    # Open the socket directly, verify its peer, and apply TLS with hostname validation.
    def connect(self) -> None:
        # No hostname resolution or environment proxy use at the transport boundary.
        sock = socket.socket(socket.AF_INET6 if ":" in self.ip else socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(10)
            sock.connect((self.ip, self.port))
            if ipaddress.ip_address(sock.getpeername()[0]) != ipaddress.ip_address(self.ip):
                raise FetchError("Connected peer differs from approved destination.")
            if self.tls:
                sock = ssl.create_default_context().wrap_socket(sock, server_hostname=self.host)
            self.sock = sock
        except BaseException:
            sock.close()
            raise


# Carry the original URL, final URL, and preserved responses to the analysis layer.
@dataclass
class PageEvidence:
    original_url: str
    final_url: str
    responses: list[dict]


# Collect bounded HTTP responses without running scripts or fetching linked assets.
class HTTPFetcher:
    MAX_BYTES = 100000

    # Follow bounded same-host redirects and preserve each response as text evidence.
    def fetch(self, url: str) -> PageEvidence:
        original, allowed_host, _ = parse_url(url)
        current = original
        responses = []
        total = 0
        deadline = time.monotonic() + 45
        try:
            # Revalidate the hostname and DNS before every redirect hop.
            for hop in range(6):
                current, host, port = parse_url(current)
                if host != allowed_host:
                    raise FetchError("Redirect changes hostname. Submit the destination URL separately.")
                checkpoint()
                if time.monotonic() > deadline:
                    raise FetchError("Collection time limit exceeded.")
                ips = resolve(host)  # Validate ALL answers before selecting one.
                connection = PinnedConnection(host, port, ips[0], current.startswith("https:"))
                try:
                    parts = urlsplit(current)
                    path = urlunsplit(("", "", parts.path, parts.query, ""))
                    connection.request("GET", path, headers={
                        "User-Agent": "GLM-Web-Analysis/0.1", "Accept-Encoding": "identity",
                        "Accept": "text/html,application/xhtml+xml,text/plain", "Connection": "close",
                    })
                    response = connection.getresponse()
                    # Keep repeated headers in order and count them toward the evidence budget.
                    headers = list(response.headers.raw_items())
                    total += sum(len(k) + len(v) for k, v in headers)
                    if total > self.MAX_BYTES:
                        raise FetchError("Response exceeds the 100000-byte evidence limit; nothing sent to GLM.")
                    if response.getheader("Content-Encoding", "identity").lower() != "identity":
                        raise FetchError("Server returned compressed content despite identity encoding request.")
                    # Read incrementally to enforce byte and elapsed-time limits.
                    body = bytearray()
                    while True:
                        checkpoint()
                        if time.monotonic() > deadline:
                            raise FetchError("Collection time limit exceeded.")
                        chunk = response.read1(min(8192, self.MAX_BYTES - total + 1))
                        if not chunk:
                            if response.length is not None and response.length > 0:
                                raise FetchError("Incomplete HTTP body; nothing sent to GLM.")
                            break
                        body.extend(chunk)
                        total += len(chunk)
                        if total > self.MAX_BYTES:
                            raise FetchError("Response exceeds the 100000-byte evidence limit; nothing sent to GLM.")
                    # Decode losslessly; unsupported or invalid encodings fail the collection.
                    charset = response.headers.get_content_charset() or "utf-8"
                    try:
                        html = bytes(body).decode(charset, errors="strict")
                    except (UnicodeError, LookupError):
                        raise FetchError("Response cannot be decoded losslessly with its declared charset (default UTF-8).") from None
                    # Save this response before deciding whether to follow its redirect.
                    locations = response.headers.get_all("Location", [])
                    responses.append({"url": current, "status": response.status,
                                      "reason": response.reason, "headers": headers, "html": html,
                                      "body_bytes": len(body), "charset": charset, "resolved_ip": ips[0]})
                    if response.status not in (301, 302, 303, 307, 308):
                        return PageEvidence(original, current, responses)
                    if len(locations) != 1 or hop == 5:
                        raise FetchError("Invalid redirect Location or redirect limit exceeded.")
                    # Validate the Location syntax before resolving relative redirects.
                    location = locations[0]
                    if (not location or any(ord(c) <= 32 for c in location) or "\\" in location
                            or location.startswith("///")
                            or (urlsplit(location).scheme and not urlsplit(location).netloc)):
                        raise FetchError("Invalid redirect Location.")
                    current = urljoin(current, location)
                finally:
                    connection.close()
        except FetchError:
            raise
        except (OSError, http.client.HTTPException, ValueError):
            raise FetchError("HTTP collection failed: check TLS, connectivity, or response format.") from None
        raise FetchError("Collection failed.")
