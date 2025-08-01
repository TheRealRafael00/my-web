# File: app.py
# Requirements: flask, requests, pytz
# Install via: pip install flask requests pytz

from flask import Flask, request, jsonify, abort
import socket
import requests
from urllib.parse import urlparse
from datetime import datetime
import pytz
import re

app = Flask(__name__)

# Simple domain/IP validation (only allow IPs or domains, no arbitrary URLs with paths)
DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[A-Za-z]{2,}$"
)
IPV4_REGEX = re.compile(
    r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
)


def normalize_target(raw: str) -> str | None:
    """
    Extract hostname or IP from input.
    Reject if it contains path/query fragments beyond hostname.
    """
    raw = raw.strip()
    if not raw:
        return None
    # If user passed full URL, parse
    if raw.startswith("http://") or raw.startswith("https://"):
        parsed = urlparse(raw)
        host = parsed.hostname
    else:
        host = raw
    if not host:
        return None
    # strip possible port
    host = host.split(":")[0]
    # Validate
    if IPV4_REGEX.fullmatch(host):
        parts = host.split(".")
        if all(0 <= int(p) <= 255 for p in parts):
            return host
        else:
            return None
    if DOMAIN_REGEX.fullmatch(host):
        return host.lower()
    return None


def resolve_hostname(target: str) -> str:
    try:
        return socket.gethostbyname(target)
    except Exception:
        return ""


def lookup_geo(ip: str) -> dict:
    """
    Uses ip-api.com (free, no key) for geolocation.
    For production consider swapping to a paid/resilient service.
    """
    url = f"http://ip-api.com/json/{ip}?fields=status,message,query,continent,country,regionName,city,zip,timezone,isp,org,as,lat,lon"
    resp = requests.get(url, timeout=5)
    data = resp.json()
    if data.get("status") != "success":
        return {"error": data.get("message", "lookup failed")}
    return data


def compute_local_time(timezone_str: str) -> str:
    try:
        tz = pytz.timezone(timezone_str)
        now = datetime.now(tz)
        return now.strftime("%Y-%m-%d %H:%M:%S %Z")
    except Exception:
        return ""


@app.route("/lookup", methods=["POST"])
def lookup():
    payload = request.get_json(silent=True)
    if not payload or "target" not in payload:
        return jsonify({"error": "Missing 'target' field"}), 400

    raw = payload["target"]
    target = normalize_target(raw)
    if not target:
        return jsonify({"error": "Invalid target format"}), 400

    # Resolve to IP
    ip_addr = ""
    hostname = ""
    if IPV4_REGEX.fullmatch(target):
        ip_addr = target
        try:
            hostname = socket.gethostbyaddr(ip_addr)[0]
        except Exception:
            hostname = ""
    else:
        # domain: resolve
        ip_addr = resolve_hostname(target)
        hostname = target  # original domain as hostname

    if not ip_addr:
        return jsonify({"error": "Unable to resolve IP for target"}), 400

    geo = lookup_geo(ip_addr)
    if "error" in geo:
        return jsonify({"error": f"Geolocation failed: {geo.get('error')}"},), 500

    # Build response fields
    response = {
        "ip": geo.get("query", ip_addr),
        "hostname": hostname or "",
        "ip_range": "",  # ip-api.com doesn't give range; could integrate another service
        "isp": geo.get("isp", ""),
        "organization": geo.get("org", ""),
        "country": geo.get("country", ""),
        "region": geo.get("regionName", ""),
        "city": geo.get("city", ""),
        "timezone": geo.get("timezone", ""),
        "carrier": "",  # Not available from ip-api.com (usually mobile lookup)
        "local_time": compute_local_time(geo.get("timezone", "")),
        "postal": geo.get("zip", ""),
        "latitude": geo.get("lat", ""),
        "longitude": geo.get("lon", ""),
    }

    return jsonify(response)


if __name__ == "__main__":
    # For production use a proper WSGI server; this is for local/testing only.
    app.run(host="0.0.0.0", port=5000, debug=True)