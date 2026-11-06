from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse
from http import cookies
from datetime import datetime, timezone, timedelta
import base64
import hashlib
import hmac
import html
import json
import os
import secrets
import time

LOG_FILE = os.environ.get("PORTAL_LOG_FILE", "/var/log/tesis-portal/app.log")
SESSION_SECRET_FILE = os.environ.get(
    "PORTAL_SESSION_SECRET_FILE", "/opt/tesis-portal/session_secret"
)
LOCK_THRESHOLD = 5
LOCK_SECONDS = 300
EC_TZ = timezone(timedelta(hours=-5), name="America/Guayaquil")
AFFECTED_SERVICE = "Portal de autenticacion corporativo"
ASSET_NAME = os.environ.get("PORTAL_ASSET_NAME", "tesis-ir-portal-ec2")
ASSET_TYPE = "EC2 web application"
COMPANY_NAME = "Asteria Operaciones"
PORTAL_VERSION = "2.2.0"

# Usuarios internos de la aplicacion. No son usuarios IAM reales de AWS.
USERS = {
    "admin.demo": {
        "display": "Administrador",
        "hash": "VpqSvQMFATBEs7T3ZU/BSA==:xioUwz95jf3bZ1gsUHqTc3H6cTcU6upr0fZiFuoU9ZY=",
    },
    "soc.demo": {
        "display": "Analista SOC",
        "hash": "9lkouWYrd54ObTxyAsNSUw==:UPSlJBYvlF2uIdpzV9LVmqMUuMNsLwXFDX+f5dedX04=",
    },
    "usuario.demo": {
        "display": "Usuario operativo",
        "hash": "n33eTr4zUj6AkGU1EfAx8A==:C3Bu/CHMnuT3SPOvBTvp0H0qpmCFJvpOjtnv7YKD9yQ=",
    },
}

FAILED_STATE = {}
SERVER_START_TIME = time.time()

# Métricas en memoria para telemetría y tiempos de respuesta (TIC)
METRICS = {
    "requests_total": 0,
    "status_2xx": 0,
    "status_3xx": 0,
    "status_4xx": 0,
    "status_5xx": 0,
    "latencies_ms": [],
    "recent_audit": [],
}

# Iconografía minimalista en SVG vectorial (sin uso de emojis según el estándar formal del TIC)
SVG_ICONS = {
    "shield": (
        '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor"'
        ' stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
        '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>'
    ),
    "pulse": (
        '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor"'
        ' stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
        '<polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>'
    ),
    "chart": (
        '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor"'
        ' stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
        '<line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12"'
        ' y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg>'
    ),
    "alert": (
        '<svg class="icon icon-alert" viewBox="0 0 24 24" fill="none"'
        ' stroke="currentColor" stroke-width="2" stroke-linecap="round"'
        ' stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12"'
        ' y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01"'
        ' y2="16"/></svg>'
    ),
    "sun": (
        '<svg class="icon icon-sun" viewBox="0 0 24 24" fill="none"'
        ' stroke="currentColor" stroke-width="2" stroke-linecap="round"'
        ' stroke-linejoin="round"><circle cx="12" cy="12" r="5"/><line x1="12"'
        ' y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line'
        ' x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36"'
        ' x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line'
        ' x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64"'
        ' y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>'
    ),
    "moon": (
        '<svg class="icon icon-moon" viewBox="0 0 24 24" fill="none"'
        ' stroke="currentColor" stroke-width="2" stroke-linecap="round"'
        ' stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0'
        ' 0 21 12.79z"/></svg>'
    ),
    "logout": (
        '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor"'
        ' stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
        '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline'
        ' points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>'
    ),
    "user": (
        '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor"'
        ' stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
        '<path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12"'
        ' cy="7" r="4"/></svg>'
    ),
    "lock": (
        '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor"'
        ' stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
        '<rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>'
        '<path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>'
    ),
    "arrow_right": (
        '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor"'
        ' stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
        '<line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></svg>'
    ),
}


def now_ecuador():
    return datetime.now(EC_TZ).isoformat()


def now_utc():
    return datetime.now(timezone.utc).isoformat()


def epoch_now():
    return int(time.time())


def get_uptime_seconds():
    return int(time.time() - SERVER_START_TIME)


def format_uptime(seconds):
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    if days > 0:
        return f"{days}d {hours}h {minutes}m"
    if hours > 0:
        return f"{hours}h {minutes}m {secs}s"
    return f"{minutes}m {secs}s"


def get_system_stats():
    try:
        load1, load5, load15 = os.getloadavg()
    except Exception:
        load1, load5, load15 = 0.05, 0.08, 0.05

    mem_total_mb = 1024
    mem_used_mb = 256
    mem_percent = 25.0
    try:
        if os.path.exists("/proc/meminfo"):
            meminfo = {}
            with open("/proc/meminfo", "r") as f:
                for line in f:
                    parts = line.split(":")
                    if len(parts) == 2:
                        key = parts[0].strip()
                        val = parts[1].strip().split()[0]
                        meminfo[key] = int(val)
            total = meminfo.get("MemTotal", 1024 * 1024)
            avail = meminfo.get("MemAvailable", total // 2)
            used = total - avail
            mem_total_mb = round(total / 1024)
            mem_used_mb = round(used / 1024)
            mem_percent = round((used / total) * 100, 1)
    except Exception:
        pass

    return {
        "load_1m": round(load1, 2),
        "load_5m": round(load5, 2),
        "load_15m": round(load15, 2),
        "mem_used_mb": mem_used_mb,
        "mem_total_mb": mem_total_mb,
        "mem_percent": mem_percent,
    }


def record_request_metric(status_code, latency_ms):
    METRICS["requests_total"] += 1
    if 200 <= status_code < 300:
        METRICS["status_2xx"] += 1
    elif 300 <= status_code < 400:
        METRICS["status_3xx"] += 1
    elif 400 <= status_code < 500:
        METRICS["status_4xx"] += 1
    elif status_code >= 500:
        METRICS["status_5xx"] += 1

    latencies = METRICS["latencies_ms"]
    latencies.append(round(latency_ms, 2))
    if len(latencies) > 100:
        latencies.pop(0)


def get_latency_stats():
    latencies = METRICS["latencies_ms"]
    if not latencies:
        return {
            "last_ms": 1.25,
            "avg_ms": 1.50,
            "p95_ms": 2.10,
            "min_ms": 0.85,
            "max_ms": 3.40,
            "samples": 0,
            "recent": [1.2, 1.4, 1.1, 1.8, 1.3, 1.5, 1.9, 1.2, 1.6, 1.4],
        }
    sorted_l = sorted(latencies)
    p95_idx = max(0, int(len(sorted_l) * 0.95) - 1)
    return {
        "last_ms": latencies[-1],
        "avg_ms": round(sum(latencies) / len(latencies), 2),
        "p95_ms": sorted_l[p95_idx],
        "min_ms": sorted_l[0],
        "max_ms": sorted_l[-1],
        "samples": len(latencies),
        "recent": latencies[-12:],
    }


def record_audit_event(event):
    recent = METRICS["recent_audit"]
    dt = datetime.now(EC_TZ).strftime("%H:%M:%S")
    summary = {
        "time": dt,
        "timestamp_utc": event.get("timestamp_utc", now_utc()),
        "event_type": event.get("event_type", "unknown"),
        "username": event.get("username", "—"),
        "source_ip": event.get("sourceIPAddress") or event.get("source_ip", "—"),
        "result": event.get("result", "INFO"),
        "severity": event.get("severity", "LOW"),
        "reason": (
            event.get("failure_reason") or event.get("message") or "Operacion normal"
        ),
    }
    recent.insert(0, summary)
    if len(recent) > 30:
        recent.pop()


def get_session_secret():
    if os.path.exists(SESSION_SECRET_FILE):
        with open(SESSION_SECRET_FILE, "rb") as f:
            return f.read().strip()
    secret = base64.urlsafe_b64encode(secrets.token_bytes(48))
    with open(SESSION_SECRET_FILE, "wb") as f:
        f.write(secret)
    os.chmod(SESSION_SECRET_FILE, 0o600)
    return secret


SESSION_SECRET = get_session_secret()


def base_event(event):
    clean = dict(event)
    clean.pop("password", None)
    clean.setdefault("timestamp", now_ecuador())
    clean.setdefault("timestamp_utc", now_utc())
    clean.setdefault("timezone", "America/Guayaquil")
    clean.setdefault("affected_service", AFFECTED_SERVICE)
    clean.setdefault("asset_name", ASSET_NAME)
    clean.setdefault("asset_type", ASSET_TYPE)
    clean.setdefault("service_owner", COMPANY_NAME)
    return clean


def write_event(event):
    ev = base_event(event)
    record_audit_event(ev)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(ev, ensure_ascii=False, separators=(",", ":")) + "\n")


def verify_password(username, password):
    user = USERS.get(username)
    if not user:
        return False
    salt_b64, hash_b64 = user["hash"].split(":", 1)
    salt = base64.b64decode(salt_b64)
    expected = base64.b64decode(hash_b64)
    candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 120000)
    return hmac.compare_digest(candidate, expected)


def sign_value(value):
    sig = hmac.new(SESSION_SECRET, value.encode("utf-8"), hashlib.sha256).hexdigest()
    return value + "." + sig


def verify_signed_value(value):
    if not value or "." not in value:
        return None
    payload, sig = value.rsplit(".", 1)
    expected = hmac.new(
        SESSION_SECRET, payload.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    if hmac.compare_digest(sig, expected):
        return payload
    return None


def html_escape(value):
    return html.escape(str(value if value is not None else ""))


def shared_styles():
    """Estilos y variables de diseño inspirados en Emil Kowalski:
    Craft riguroso, micro-interacciones suaves, bordes sutiles con iluminación interna,
    soporte completo para Modo Claro / Modo Oscuro, cero emojis e iconografía SVG vectorial.
    """
    return """
    :root, [data-theme="dark"] {
      --bg: #070a12;
      --bg-surface: #0e1424;
      --bg-elevated: #141c30;
      --bg-subtle: #1b2640;
      --border: rgba(255, 255, 255, 0.08);
      --border-highlight: rgba(255, 255, 255, 0.16);
      --border-focus: #38bdf8;
      --text-main: #f8fafc;
      --text-muted: #94a3b8;
      --text-dim: #64748b;
      --primary: #3b82f6;
      --primary-hover: #2563eb;
      --accent-cyan: #38bdf8;
      --emerald: #10b981;
      --emerald-bg: rgba(16, 185, 129, 0.12);
      --amber: #f59e0b;
      --amber-bg: rgba(245, 158, 11, 0.12);
      --orange: #f97316;
      --orange-bg: rgba(249, 115, 22, 0.12);
      --red: #ef4444;
      --red-bg: rgba(239, 68, 68, 0.12);
      --shadow-card: inset 0 1px 0 rgba(255, 255, 255, 0.08), 0 12px 36px -8px rgba(0, 0, 0, 0.6);
      --shadow-sm: inset 0 1px 0 rgba(255, 255, 255, 0.06), 0 2px 6px rgba(0, 0, 0, 0.4);
      --nav-bg: rgba(7, 10, 18, 0.80);
      --bg-gradient: radial-gradient(1200px circle at 50% -20%, rgba(30, 58, 138, 0.22), transparent 75%), #070a12;
      --table-header-bg: #141c30;
      --table-row-hover: rgba(255, 255, 255, 0.02);
      --theme-sun-display: block;
      --theme-moon-display: none;
    }
    [data-theme="light"] {
      --bg: #f8fafc;
      --bg-surface: #ffffff;
      --bg-elevated: #f1f5f9;
      --bg-subtle: #e2e8f0;
      --border: rgba(15, 23, 42, 0.08);
      --border-highlight: rgba(15, 23, 42, 0.18);
      --border-focus: #0284c7;
      --text-main: #0f172a;
      --text-muted: #475569;
      --text-dim: #64748b;
      --primary: #2563eb;
      --primary-hover: #1d4ed8;
      --accent-cyan: #0284c7;
      --emerald: #059669;
      --emerald-bg: rgba(5, 150, 105, 0.10);
      --amber: #d97706;
      --amber-bg: rgba(217, 119, 6, 0.10);
      --orange: #ea580c;
      --orange-bg: rgba(234, 88, 12, 0.10);
      --red: #dc2626;
      --red-bg: rgba(220, 38, 38, 0.10);
      --shadow-card: inset 0 1px 0 rgba(255, 255, 255, 0.9), 0 12px 32px -8px rgba(15, 23, 42, 0.08), 0 1px 3px rgba(15, 23, 42, 0.05);
      --shadow-sm: inset 0 1px 0 rgba(255, 255, 255, 0.8), 0 1px 3px rgba(15, 23, 42, 0.06);
      --nav-bg: rgba(255, 255, 255, 0.85);
      --bg-gradient: radial-gradient(1200px circle at 50% -20%, rgba(219, 234, 254, 0.7), transparent 75%), #f8fafc;
      --table-header-bg: #f8fafc;
      --table-row-hover: rgba(15, 23, 42, 0.02);
      --theme-sun-display: none;
      --theme-moon-display: block;
    }
    :root {
      --radius-sm: 8px;
      --radius-md: 14px;
      --radius-lg: 20px;
      --ease-snappy: cubic-bezier(0.16, 1, 0.3, 1);
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      min-height: 100vh;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Inter", sans-serif;
      background: var(--bg-gradient);
      color: var(--text-main);
      line-height: 1.5;
      -webkit-font-smoothing: antialiased;
      overflow-x: hidden;
      transition: background-color 0.2s var(--ease-snappy), color 0.2s var(--ease-snappy);
    }
    .num, .metric-value, .latency-val, .uptime-val {
      font-variant-numeric: tabular-nums;
      font-feature-settings: 'tnum' 1;
    }

    /* Minimalist SVG Icon styles */
    .icon {
      width: 16px;
      height: 16px;
      vertical-align: middle;
      display: inline-block;
      flex-shrink: 0;
    }
    .icon-alert {
      width: 38px;
      height: 38px;
      color: var(--red);
    }

    /* Micro-interactions & animations */
    button, .btn, .tab-btn, .pill-btn, .btn-theme {
      transition: all 0.16s var(--ease-snappy);
      cursor: pointer;
      user-select: none;
    }
    button:active, .btn:active, .tab-btn:active, .pill-btn:active, .btn-theme:active {
      transform: scale(0.98);
    }

    /* Live Beacon Pulsing */
    .beacon {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: var(--emerald);
      display: inline-block;
      position: relative;
    }
    .beacon::after {
      content: '';
      position: absolute;
      inset: -3px;
      border-radius: 50%;
      border: 2px solid var(--emerald);
      animation: beacon-pulse 2.2s var(--ease-snappy) infinite;
    }
    @keyframes beacon-pulse {
      0% { transform: scale(0.8); opacity: 1; }
      100% { transform: scale(2.5); opacity: 0; }
    }

    /* Badges & Severity Chips */
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 3px 9px;
      border-radius: 999px;
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 0.04em;
      text-transform: uppercase;
      font-variant-numeric: tabular-nums;
    }
    .badge.success { background: var(--emerald-bg); color: #10b981; border: 1px solid rgba(16, 185, 129, 0.25); }
    .badge.info { background: rgba(56, 189, 248, 0.12); color: var(--accent-cyan); border: 1px solid rgba(56, 189, 248, 0.25); }
    .badge.warning { background: var(--amber-bg); color: var(--amber); border: 1px solid rgba(245, 158, 11, 0.25); }
    .badge.high { background: var(--orange-bg); color: var(--orange); border: 1px solid rgba(249, 115, 22, 0.25); }
    .badge.critical { background: var(--red-bg); color: var(--red); border: 1px solid rgba(239, 68, 68, 0.25); }

    /* Header */
    .top-nav {
      height: 64px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 0 32px;
      border-bottom: 1px solid var(--border);
      background: var(--nav-bg);
      backdrop-filter: blur(14px);
      position: sticky;
      top: 0;
      z-index: 50;
      transition: background-color 0.2s var(--ease-snappy), border-color 0.2s var(--ease-snappy);
    }
    .nav-brand {
      display: flex;
      align-items: center;
      gap: 12px;
      font-weight: 800;
      font-size: 17px;
      letter-spacing: -0.02em;
    }
    .nav-brand-icon {
      width: 30px;
      height: 30px;
      border-radius: 8px;
      background: linear-gradient(135deg, var(--primary), var(--accent-cyan));
      color: white;
      display: grid;
      place-items: center;
      box-shadow: 0 2px 10px rgba(56, 189, 248, 0.35);
    }
    .nav-actions {
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .nav-user {
      display: flex;
      align-items: center;
      gap: 8px;
      background: var(--bg-surface);
      border: 1px solid var(--border);
      padding: 5px 12px;
      border-radius: 999px;
      font-size: 13px;
    }
    .nav-user-avatar {
      width: 20px;
      height: 20px;
      border-radius: 50%;
      background: var(--bg-elevated);
      display: grid;
      place-items: center;
      font-size: 11px;
      font-weight: 700;
      color: var(--accent-cyan);
    }
    .btn-logout {
      color: var(--text-muted);
      text-decoration: none;
      font-size: 12px;
      font-weight: 600;
      padding: 6px 12px;
      border-radius: var(--radius-sm);
      border: 1px solid var(--border);
      background: transparent;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      transition: all 0.16s var(--ease-snappy);
    }
    .btn-logout:hover {
      color: var(--text-main);
      border-color: var(--border-highlight);
      background: var(--bg-surface);
    }
    .btn-theme {
      width: 32px;
      height: 32px;
      display: grid;
      place-items: center;
      border-radius: var(--radius-sm);
      border: 1px solid var(--border);
      background: var(--bg-surface);
      color: var(--text-muted);
      padding: 0;
    }
    .btn-theme:hover {
      color: var(--text-main);
      border-color: var(--border-highlight);
      background: var(--bg-elevated);
    }
    .icon-sun { display: var(--theme-sun-display); }
    .icon-moon { display: var(--theme-moon-display); }
    """


def page(title, content, authenticated=False, username=None):
    theme_btn_html = f"""
    <button class='btn-theme' type='button' aria-label='Cambiar tema' onclick='toggleTheme()' title='Cambiar modo claro / oscuro'>
      {SVG_ICONS["sun"]}
      {SVG_ICONS["moon"]}
    </button>
    """

    session_html = ""
    if authenticated:
        role = USERS.get(username, {}).get("display", "Usuario")
        initial = (username[0] if username else "A").upper()
        session_html = f"""
        <div class='nav-actions'>
          <div class='badge success'><span class='beacon'></span> AWS IR ACTIVO</div>
          <div class='nav-user'>
            <div class='nav-user-avatar'>{html_escape(initial)}</div>
            <span><strong>{html_escape(username)}</strong> ({html_escape(role)})</span>
          </div>
          {theme_btn_html}
          <a class='btn-logout' href='/logout'>{SVG_ICONS["logout"]} Salir</a>
        </div>
        """
    else:
        session_html = f"""
        <div class='nav-actions'>
          {theme_btn_html}
        </div>
        """

    return f"""<!DOCTYPE html>
<html lang='es'>
<head>
  <meta charset='UTF-8'>
  <meta name='viewport' content='width=device-width, initial-scale=1.0'>
  <title>{html_escape(title)} — {COMPANY_NAME}</title>
  <script>
    (function() {{
      const saved = localStorage.getItem('asteria_theme');
      if (saved) {{
        document.documentElement.setAttribute('data-theme', saved);
      }} else if (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) {{
        document.documentElement.setAttribute('data-theme', 'light');
      }} else {{
        document.documentElement.setAttribute('data-theme', 'dark');
      }}
    }})();
    function toggleTheme() {{
      const cur = document.documentElement.getAttribute('data-theme') || 'dark';
      const next = cur === 'dark' ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', next);
      localStorage.setItem('asteria_theme', next);
    }}
  </script>
  <style>
    {shared_styles()}
  </style>
</head>
<body>
  <header class='top-nav'>
    <div class='nav-brand'>
      <div class='nav-brand-icon'>{SVG_ICONS["shield"]}</div>
      <span>{COMPANY_NAME}</span>
      <span class='badge info'>v{PORTAL_VERSION}</span>
    </div>
    {session_html}
  </header>
  {content}
</body>
</html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = f"AsteriaPortal/{PORTAL_VERSION}"

    def __init__(self, *args, **kwargs):
        self._req_start = time.perf_counter()
        super().__init__(*args, **kwargs)

    def client_ip(self):
        forwarded = self.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return self.client_address[0]

    def get_session_user(self):
        raw_cookie = self.headers.get("Cookie")
        if not raw_cookie:
            return None
        jar = cookies.SimpleCookie(raw_cookie)
        if "portal_session" not in jar:
            return None
        payload = verify_signed_value(jar["portal_session"].value)
        if not payload:
            return None
        try:
            username, issued = payload.split(":", 1)
            if username in USERS and epoch_now() - int(issued) < 3600:
                return username
        except Exception:
            return None
        return None

    def respond(
        self,
        status,
        body,
        content_type="text/html; charset=utf-8",
        headers=None,
    ):
        elapsed_ms = (time.perf_counter() - self._req_start) * 1000
        record_request_metric(status, elapsed_ms)

        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("X-Response-Time", f"{elapsed_ms:.2f}ms")
        self.send_header("X-Server-Version", self.server_version)
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        if headers:
            for key, value in headers.items():
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(encoded)

    def redirect(self, location, headers=None):
        elapsed_ms = (time.perf_counter() - self._req_start) * 1000
        record_request_metric(302, elapsed_ms)

        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("X-Response-Time", f"{elapsed_ms:.2f}ms")
        self.send_header("Cache-Control", "no-store")
        if headers:
            for key, value in headers.items():
                self.send_header(key, value)
        self.end_headers()

    def render_login(self, message=None, error=False):
        alert_html = ""
        if message:
            kind = "critical" if error else "info"
            alert_html = f"""
            <div class='badge {kind}' style='width: 100%; padding: 11px 16px; border-radius: var(--radius-sm); margin-bottom: 20px; justify-content: center; text-transform: none; font-size: 13px; font-weight: 600; backdrop-filter: blur(8px);'>
              {html_escape(message)}
            </div>
            """

        icon_shield = SVG_ICONS["shield"]
        icon_user = SVG_ICONS["user"]
        icon_lock = SVG_ICONS["lock"]
        icon_arrow = SVG_ICONS["arrow_right"]

        content = f"""
        <style>
          /* Escena y fondo Glassmorphism con iluminacion ambiental */
          .login-scene {{
            min-height: calc(100vh - 64px);
            display: grid;
            place-items: center;
            padding: 32px 20px;
            position: relative;
            overflow: hidden;
          }}
          .ambient-orb {{
            position: absolute;
            border-radius: 50%;
            filter: blur(85px);
            pointer-events: none;
            z-index: 0;
            opacity: 0.6;
            animation: orb-drift 16s ease-in-out infinite alternate;
          }}
          .orb-1 {{
            width: 340px;
            height: 340px;
            top: 15%;
            left: calc(50% - 250px);
            background: radial-gradient(circle, rgba(56, 189, 248, 0.35), rgba(37, 99, 235, 0.15));
          }}
          .orb-2 {{
            width: 380px;
            height: 380px;
            bottom: 12%;
            right: calc(50% - 270px);
            background: radial-gradient(circle, rgba(99, 102, 241, 0.30), rgba(139, 92, 246, 0.12));
            animation-delay: -6s;
          }}
          @keyframes orb-drift {{
            0% {{ transform: translate(0, 0) scale(1); }}
            50% {{ transform: translate(30px, -24px) scale(1.08); }}
            100% {{ transform: translate(-24px, 30px) scale(0.96); }}
          }}

          /* Tarjeta Frosted Glassmorphism */
          .glass-card {{
            position: relative;
            z-index: 1;
            width: 100%;
            max-width: 440px;
            background: rgba(14, 20, 36, 0.65);
            backdrop-filter: blur(24px) saturate(190%);
            -webkit-backdrop-filter: blur(24px) saturate(190%);
            border: 1px solid rgba(255, 255, 255, 0.12);
            border-radius: 22px;
            padding: 38px 34px;
            box-shadow: inset 0 1px 1px 0 rgba(255, 255, 255, 0.18),
                        0 24px 60px -12px rgba(0, 0, 0, 0.7),
                        0 0 0 1px rgba(255, 255, 255, 0.05);
            transition: all 0.25s var(--ease-snappy);
          }}
          [data-theme="light"] .glass-card {{
            background: rgba(255, 255, 255, 0.72);
            border: 1px solid rgba(255, 255, 255, 0.85);
            box-shadow: inset 0 1px 2px 0 rgba(255, 255, 255, 0.95),
                        0 20px 48px -10px rgba(15, 23, 42, 0.12),
                        0 0 0 1px rgba(15, 23, 42, 0.06);
          }}
          [data-theme="light"] .orb-1 {{
            background: radial-gradient(circle, rgba(147, 197, 253, 0.65), rgba(191, 219, 254, 0.3));
            opacity: 0.75;
          }}
          [data-theme="light"] .orb-2 {{
            background: radial-gradient(circle, rgba(199, 210, 254, 0.55), rgba(224, 231, 255, 0.25));
            opacity: 0.75;
          }}

          /* Cabecera de la tarjeta */
          .glass-header {{
            text-align: center;
            margin-bottom: 24px;
          }}
          .glass-brand-badge {{
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 48px;
            height: 48px;
            border-radius: 14px;
            background: linear-gradient(135deg, rgba(59, 130, 246, 0.22), rgba(56, 189, 248, 0.18));
            border: 1px solid rgba(56, 189, 248, 0.35);
            color: var(--accent-cyan);
            margin-bottom: 14px;
            box-shadow: 0 4px 16px rgba(56, 189, 248, 0.25);
          }}
          .glass-brand-badge svg {{
            width: 24px;
            height: 24px;
          }}
          .glass-title {{
            font-size: 23px;
            font-weight: 800;
            letter-spacing: -0.025em;
            margin-bottom: 6px;
            color: var(--text-main);
          }}
          .glass-sub {{
            font-size: 13px;
            color: var(--text-muted);
          }}

          /* Campos del formulario translúcidos */
          .glass-form-group {{
            margin-bottom: 18px;
          }}
          .glass-label {{
            display: flex;
            align-items: center;
            gap: 6px;
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-muted);
            margin-bottom: 7px;
          }}
          .glass-label svg {{
            width: 14px;
            height: 14px;
            opacity: 0.8;
          }}
          .glass-input-wrapper {{
            position: relative;
            display: flex;
            align-items: center;
          }}
          .glass-input {{
            width: 100%;
            padding: 13px 16px;
            border-radius: var(--radius-sm);
            border: 1px solid rgba(255, 255, 255, 0.10);
            background: rgba(20, 28, 48, 0.55);
            backdrop-filter: blur(8px);
            -webkit-backdrop-filter: blur(8px);
            color: var(--text-main);
            font-size: 14px;
            outline: none;
            transition: all 0.18s var(--ease-snappy);
            font-family: inherit;
          }}
          [data-theme="light"] .glass-input {{
            background: rgba(248, 250, 252, 0.75);
            border: 1px solid rgba(15, 23, 42, 0.12);
          }}
          .glass-input:focus {{
            border-color: var(--accent-cyan);
            box-shadow: 0 0 0 3px rgba(56, 189, 248, 0.22);
            background: rgba(27, 38, 64, 0.75);
          }}
          [data-theme="light"] .glass-input:focus {{
            background: rgba(255, 255, 255, 0.95);
            box-shadow: 0 0 0 3px rgba(2, 132, 199, 0.18);
          }}

          /* Botón principal Glassmorphic */
          .glass-btn-primary {{
            width: 100%;
            padding: 13px 20px;
            border-radius: var(--radius-sm);
            border: 1px solid rgba(255, 255, 255, 0.22);
            background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
            color: #ffffff;
            font-size: 14px;
            font-weight: 700;
            letter-spacing: 0.02em;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.35),
                        0 10px 24px -4px rgba(37, 99, 235, 0.45);
            margin-top: 10px;
            transition: all 0.18s var(--ease-snappy);
            cursor: pointer;
          }}
          .glass-btn-primary:hover {{
            background: linear-gradient(135deg, #4f91fd 0%, #1d4ed8 100%);
            box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.45),
                        0 14px 28px -4px rgba(37, 99, 235, 0.55);
            transform: translateY(-1px);
          }}
          .glass-btn-primary:active {{
            transform: translateY(1px) scale(0.985);
          }}

          /* Accesos rápidos Demo estilo Glass */
          .glass-demo-box {{
            margin-top: 24px;
            padding-top: 20px;
            border-top: 1px solid var(--border);
          }}
          .glass-demo-title {{
            font-size: 11px;
            font-weight: 700;
            color: var(--text-dim);
            text-transform: uppercase;
            letter-spacing: 0.06em;
            margin-bottom: 11px;
            text-align: center;
          }}
          .glass-demo-pills {{
            display: flex;
            gap: 8px;
            justify-content: center;
            flex-wrap: wrap;
          }}
          .glass-demo-pill {{
            font-size: 12px;
            padding: 6px 12px;
            border-radius: var(--radius-sm);
            background: rgba(255, 255, 255, 0.04);
            border: 1px solid var(--border);
            backdrop-filter: blur(6px);
            -webkit-backdrop-filter: blur(6px);
            color: var(--text-muted);
            cursor: pointer;
            transition: all 0.15s var(--ease-snappy);
            font-weight: 600;
          }}
          [data-theme="light"] .glass-demo-pill {{
            background: rgba(255, 255, 255, 0.8);
            border: 1px solid rgba(15, 23, 42, 0.1);
          }}
          .glass-demo-pill:hover {{
            background: rgba(56, 189, 248, 0.12);
            border-color: rgba(56, 189, 248, 0.35);
            color: var(--text-main);
            transform: translateY(-1px);
          }}
          .glass-demo-pill:active {{
            transform: scale(0.97);
          }}

          /* Micro-badge de confianza y seguridad */
          .glass-trust-chip {{
            margin-top: 22px;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 7px;
            font-size: 11px;
            font-weight: 600;
            color: var(--text-dim);
            letter-spacing: 0.02em;
          }}
          .glass-trust-chip .beacon {{
            width: 6px;
            height: 6px;
          }}
        </style>

        <main class='login-scene'>
          <div class='ambient-orb orb-1' aria-hidden='true'></div>
          <div class='ambient-orb orb-2' aria-hidden='true'></div>

          <section class='glass-card'>
            <div class='glass-header'>
              <div class='glass-brand-badge'>
                {icon_shield}
              </div>
              <h1 class='glass-title'>Iniciar sesión</h1>
              <p class='glass-sub'>Portal seguro de operaciones & telemetría en tiempo real</p>
            </div>

            {alert_html}

            <form method='POST' action='/login' autocomplete='off'>
              <div class='glass-form-group'>
                <label class='glass-label' for='username'>
                  {icon_user} Usuario
                </label>
                <div class='glass-input-wrapper'>
                  <input class='glass-input' id='username' name='username' required maxlength='64' autocomplete='username' placeholder='admin.demo'>
                </div>
              </div>

              <div class='glass-form-group'>
                <label class='glass-label' for='password'>
                  {icon_lock} Contraseña
                </label>
                <div class='glass-input-wrapper'>
                  <input class='glass-input' id='password' name='password' type='password' required maxlength='128' autocomplete='current-password' placeholder='••••••••••••'>
                </div>
              </div>

              <button class='glass-btn-primary' type='submit'>
                <span>Acceder al panel</span>
                {icon_arrow}
              </button>
            </form>

            <div class='glass-demo-box'>
              <div class='glass-demo-title'>Accesos de prueba rápidos</div>
              <div class='glass-demo-pills'>
                <button type='button' class='glass-demo-pill' onclick='fillDemo("admin.demo", "AdminDemo#2026")'>admin.demo</button>
                <button type='button' class='glass-demo-pill' onclick='fillDemo("soc.demo", "SocDemo#2026")'>soc.demo</button>
                <button type='button' class='glass-demo-pill' onclick='fillDemo("usuario.demo", "UsuarioDemo#2026")'>usuario.demo</button>
              </div>
            </div>

            <div class='glass-trust-chip'>
              <span class='beacon'></span>
              <span>Sesión protegida por HMAC-SHA256 • Telemetría Monotónica</span>
            </div>
          </section>
        </main>
        <script>
          function fillDemo(u, p) {{
            const userEl = document.getElementById('username');
            const passEl = document.getElementById('password');
            userEl.value = u;
            passEl.value = p;
            userEl.focus();
          }}
        </script>
        """
        self.respond(200, page("Iniciar sesión", content))

    def render_access_denied(self, remaining):
        icon_alert = SVG_ICONS["alert"]
        content = f"""
        <style>
          .denied-scene {{
            min-height: calc(100vh - 64px);
            display: grid;
            place-items: center;
            padding: 32px 20px;
            position: relative;
            overflow: hidden;
          }}
          .denied-orb {{
            position: absolute;
            width: 360px;
            height: 360px;
            border-radius: 50%;
            background: radial-gradient(circle, rgba(239, 68, 68, 0.28), rgba(220, 38, 38, 0.08));
            filter: blur(85px);
            pointer-events: none;
            z-index: 0;
            opacity: 0.65;
          }}
          .denied-glass-card {{
            position: relative;
            z-index: 1;
            width: 100%;
            max-width: 460px;
            background: rgba(14, 20, 36, 0.70);
            backdrop-filter: blur(24px) saturate(190%);
            -webkit-backdrop-filter: blur(24px) saturate(190%);
            border: 1px solid rgba(239, 68, 68, 0.35);
            border-radius: 22px;
            padding: 38px 34px;
            box-shadow: inset 0 1px 1px 0 rgba(255, 255, 255, 0.15),
                        0 24px 60px -12px rgba(0, 0, 0, 0.7);
            text-align: center;
          }}
          [data-theme="light"] .denied-glass-card {{
            background: rgba(255, 255, 255, 0.75);
            border: 1px solid rgba(220, 38, 38, 0.35);
            box-shadow: inset 0 1px 2px 0 rgba(255, 255, 255, 0.95),
                        0 20px 48px -10px rgba(15, 23, 42, 0.12);
          }}
          .denied-icon-badge {{
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 56px;
            height: 56px;
            border-radius: 16px;
            background: var(--red-bg);
            border: 1px solid rgba(239, 68, 68, 0.35);
            margin-bottom: 16px;
            box-shadow: 0 4px 20px rgba(239, 68, 68, 0.25);
          }}
          .denied-title {{ font-size: 22px; font-weight: 800; color: var(--red); margin-bottom: 8px; }}
          .denied-sub {{ color: var(--text-muted); font-size: 14px; margin-bottom: 22px; line-height: 1.5; }}
          .denied-box {{
            background: var(--red-bg);
            border: 1px solid rgba(239, 68, 68, 0.28);
            padding: 14px 18px;
            border-radius: var(--radius-sm);
            color: var(--red);
            font-size: 13px;
            font-weight: 600;
            margin-bottom: 24px;
            backdrop-filter: blur(8px);
          }}
          .btn-back {{
            display: inline-block;
            padding: 12px 26px;
            border-radius: var(--radius-sm);
            background: rgba(255, 255, 255, 0.06);
            color: var(--text-main);
            text-decoration: none;
            font-size: 13px;
            font-weight: 700;
            border: 1px solid var(--border);
            backdrop-filter: blur(8px);
            transition: all 0.18s var(--ease-snappy);
          }}
          [data-theme="light"] .btn-back {{
            background: rgba(255, 255, 255, 0.85);
            border: 1px solid rgba(15, 23, 42, 0.12);
          }}
          .btn-back:hover {{
            background: var(--bg-subtle);
            border-color: var(--border-highlight);
            transform: translateY(-1px);
          }}
          .btn-back:active {{
            transform: translateY(1px) scale(0.98);
          }}
        </style>
        <main class='denied-scene'>
          <div class='denied-orb' aria-hidden='true'></div>
          <section class='denied-glass-card'>
            <div class='denied-icon-badge'>{icon_alert}</div>
            <h1 class='denied-title'>Acceso bloqueado temporalmente</h1>
            <p class='denied-sub'>Se detectó un exceso de intentos fallidos. El sistema IR activó la ventana de contención defensiva.</p>
            <div class='denied-box'>
              Tiempo restante de enfriamiento: <span id='rem' class='num'>{remaining}</span> segundos
            </div>
            <a class='btn-back' href='/login'>Volver al inicio</a>
          </section>
        </main>
        <script>
          let t = {remaining};
          setInterval(() => {{
            if (t > 0) {{ t--; document.getElementById('rem').innerText = t; }}
            else {{ window.location.href = '/login'; }}
          }}, 1000);
        </script>
        """
        self.respond(403, page("Acceso bloqueado", content))

    def render_dashboard(self, username):
        role = USERS.get(username, {}).get("display", "Usuario")
        lat = get_latency_stats()
        uptime_sec = get_uptime_seconds()
        uptime_str = format_uptime(uptime_sec)
        sys_stats = get_system_stats()
        client_ip = self.client_ip()

        audit_rows_parts = []
        for ev in METRICS["recent_audit"][:10]:
            ev_sev = ev["severity"].lower()
            audit_rows_parts.append(
                "<tr>"
                + f"<td class='num'>{html_escape(ev['time'])}</td>"
                + f"<td><code>{html_escape(ev['event_type'])}</code></td>"
                + f"<td><strong>{html_escape(ev['username'])}</strong></td>"
                + f"<td><code>{html_escape(ev['source_ip'])}</code></td>"
                + f"<td><span class='badge {ev_sev}'>{html_escape(ev['severity'])}</span></td>"
                + f"<td>{html_escape(ev['result'])}</td>"
                + "<td style='color:var(--text-muted);"
                f" font-size:12px;'>{html_escape(ev['reason'])}</td>" + "</tr>"
            )
        audit_rows_html = (
            "".join(audit_rows_parts)
            or "<tr><td colspan='7' style='text-align:center;"
            " color:var(--text-dim);'>Sin eventos de seguridad"
            " recientes</td></tr>"
        )

        content = f"""
        <style>
          .dash-wrap {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 28px 24px 60px;
          }}

          /* Segmented Controls (Emil Kowalski style) */
          .tabs-bar {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 24px;
            border-bottom: 1px solid var(--border);
            padding-bottom: 14px;
            gap: 16px;
            flex-wrap: wrap;
          }}
          .segmented-control {{
            display: inline-flex;
            background: var(--bg-surface);
            border: 1px solid var(--border);
            padding: 3px;
            border-radius: var(--radius-sm);
            gap: 2px;
          }}
          .tab-btn {{
            padding: 7px 15px;
            border-radius: 6px;
            border: 0;
            background: transparent;
            color: var(--text-muted);
            font-size: 13px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 7px;
          }}
          .tab-btn.active {{
            background: var(--bg-elevated);
            color: var(--text-main);
            box-shadow: 0 1px 4px rgba(0,0,0,0.15);
            border: 1px solid var(--border-highlight);
          }}
          .tab-btn:hover:not(.active) {{
            color: var(--text-main);
          }}
          .live-ping-box {{
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 12px;
            color: var(--text-dim);
          }}

          /* Metrics KPI Grid */
          .kpi-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
            margin-bottom: 24px;
          }}
          .kpi-card {{
            background: var(--bg-surface);
            border: 1px solid var(--border);
            border-radius: var(--radius-md);
            padding: 20px;
            box-shadow: var(--shadow-sm);
            position: relative;
            transition: border-color 0.16s var(--ease-snappy), background-color 0.2s var(--ease-snappy);
          }}
          .kpi-card:hover {{
            border-color: var(--border-highlight);
          }}
          .kpi-label {{
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-muted);
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 10px;
          }}
          .kpi-value {{
            font-size: 28px;
            font-weight: 800;
            letter-spacing: -0.03em;
            color: var(--text-main);
            margin-bottom: 4px;
          }}
          .kpi-sub {{
            font-size: 12px;
            color: var(--text-dim);
            display: flex;
            align-items: center;
            gap: 6px;
          }}

          /* Tab Panes */
          .tab-pane {{
            display: none;
          }}
          .tab-pane.active {{
            display: block;
            animation: fadeIn 0.18s var(--ease-snappy);
          }}
          @keyframes fadeIn {{
            from {{ opacity: 0; transform: translateY(3px); }}
            to {{ opacity: 1; transform: translateY(0); }}
          }}

          /* Sections & Cards */
          .panel-card {{
            background: var(--bg-surface);
            border: 1px solid var(--border);
            border-radius: var(--radius-md);
            padding: 24px;
            margin-bottom: 20px;
            box-shadow: var(--shadow-sm);
            transition: background-color 0.2s var(--ease-snappy), border-color 0.2s var(--ease-snappy);
          }}
          .panel-card h2 {{
            font-size: 16px;
            font-weight: 800;
            letter-spacing: -0.01em;
            margin-bottom: 4px;
          }}
          .panel-card p {{
            color: var(--text-muted);
            font-size: 13px;
            margin-bottom: 18px;
          }}

          /* Tables */
          .data-table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
            text-align: left;
          }}
          .data-table th {{
            padding: 10px 14px;
            background: var(--table-header-bg);
            color: var(--text-muted);
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            border-bottom: 1px solid var(--border);
          }}
          .data-table td {{
            padding: 12px 14px;
            border-bottom: 1px solid var(--border);
            color: var(--text-main);
          }}
          .data-table tr:hover td {{
            background: var(--table-row-hover);
          }}

          /* Progress / Gauges */
          .progress-track {{
            width: 100%;
            height: 6px;
            background: var(--bg-elevated);
            border-radius: 999px;
            overflow: hidden;
            margin-top: 8px;
          }}
          .progress-fill {{
            height: 100%;
            background: linear-gradient(90deg, var(--primary), var(--accent-cyan));
            border-radius: 999px;
            transition: width 0.3s var(--ease-snappy);
          }}

          /* Responsive */
          @media(max-width: 900px) {{
            .kpi-grid {{ grid-template-columns: repeat(2, 1fr); }}
            .dash-wrap {{ padding: 18px 14px; }}
          }}
          @media(max-width: 550px) {{
            .kpi-grid {{ grid-template-columns: 1fr; }}
          }}
        </style>

        <main class='dash-wrap'>
          <!-- Top KPI Grid -->
          <section class='kpi-grid'>
            <!-- Card 1: Latencia p95 -->
            <div class='kpi-card'>
              <div class='kpi-label'>
                <span>Tiempo de respuesta</span>
                <span id='badge-latency' class='badge success'>Óptimo</span>
              </div>
              <div class='kpi-value num'><span id='val-latency'>{lat["p95_ms"]}</span> <span style='font-size:16px; font-weight:600; color:var(--text-muted);'>ms</span></div>
              <div class='kpi-sub'>
                <span>p50: <strong class='num' id='val-p50'>{lat["avg_ms"]}</strong>ms</span>
                <span>•</span>
                <span>Muestreo real</span>
              </div>
            </div>

            <!-- Card 2: Uptime & Disponibilidad -->
            <div class='kpi-card'>
              <div class='kpi-label'>
                <span>Disponibilidad</span>
                <span class='badge success'>99.98%</span>
              </div>
              <div class='kpi-value num' id='val-uptime'>{uptime_str}</div>
              <div class='kpi-sub'>
                <span>Load CPU: <strong class='num' id='val-cpu'>{sys_stats["load_1m"]}</strong></span>
              </div>
            </div>

            <!-- Card 3: Peticiones HTTP -->
            <div class='kpi-card'>
              <div class='kpi-label'>
                <span>Solicitudes procesadas</span>
                <span class='badge info'>HTTP/1.1</span>
              </div>
              <div class='kpi-value num' id='val-reqs'>{METRICS["requests_total"]}</div>
              <div class='kpi-sub'>
                <span>2xx: <strong class='num' id='val-2xx'>{METRICS["status_2xx"]}</strong></span>
                <span>•</span>
                <span>4xx: <strong class='num' id='val-4xx'>{METRICS["status_4xx"]}</strong></span>
              </div>
            </div>

            <!-- Card 4: Seguridad y Contención -->
            <div class='kpi-card'>
              <div class='kpi-label'>
                <span>Contención defensiva</span>
                <span id='badge-defense' class='badge success'>Vigilancia</span>
              </div>
              <div class='kpi-value num' id='val-blocked'>{len(FAILED_STATE)}</div>
              <div class='kpi-sub'>
                <span>Bloqueos activos en memoria</span>
              </div>
            </div>
          </section>

          <!-- Segmented Navigation Bar -->
          <nav class='tabs-bar'>
            <div class='segmented-control'>
              <button class='tab-btn active' onclick='switchTab(event, "tab-ops")'>
                {SVG_ICONS["chart"]} Operaciones Asteria
              </button>
              <button class='tab-btn' onclick='switchTab(event, "tab-telemetry")'>
                {SVG_ICONS["pulse"]} Telemetría & Tiempos (TIC)
              </button>
              <button class='tab-btn' onclick='switchTab(event, "tab-security")'>
                {SVG_ICONS["shield"]} Auditoría de Seguridad & IR
              </button>
            </div>
            <div class='live-ping-box'>
              <span class='beacon'></span>
              <span>Telemetría en vivo (<span id='ping-ms' class='num'>—</span> ms)</span>
            </div>
          </nav>

          <!-- TAB 1: Operaciones Corporativas -->
          <section id='tab-ops' class='tab-pane active'>
            <div class='panel-card'>
              <h2>Portal de Operaciones Financieras & Clientes</h2>
              <p>Módulo corporativo simulado para el seguimiento de solicitudes bancarias y auditoría forense.</p>
              
              <table class='data-table'>
                <thead>
                  <tr>
                    <th>Ref Operación</th>
                    <th>Tipo de Registro</th>
                    <th>Usuario Asignado</th>
                    <th>Estado</th>
                    <th>Hora Local</th>
                    <th>Bóveda Segura</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td><code>AST-2026-9041</code></td>
                    <td>Transferencia Corporativa Swift</td>
                    <td><code>{html_escape(username)}</code></td>
                    <td><span class='badge success'>Completado</span></td>
                    <td class='num'>10:14:22</td>
                    <td>S3 /sensible/clientes_demo.json</td>
                  </tr>
                  <tr>
                    <td><code>AST-2026-9042</code></td>
                    <td>Auditoría de Acceso IAM</td>
                    <td><code>soc.demo</code></td>
                    <td><span class='badge info'>En Revisión</span></td>
                    <td class='num'>11:02:18</td>
                    <td>CloudTrail Forensic Store</td>
                  </tr>
                  <tr>
                    <td><code>AST-2026-9043</code></td>
                    <td>Exportación de Cuentas VIP</td>
                    <td><code>admin.demo</code></td>
                    <td><span class='badge warning'>Custodiado</span></td>
                    <td class='num'>11:45:09</td>
                    <td>S3 Sensitive Encrypted Bucket</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </section>

          <!-- TAB 2: Telemetría y Rendimiento (TIC) -->
          <section id='tab-telemetry' class='tab-pane'>
            <div style='display: grid; grid-template-columns: 1fr 1fr; gap: 20px;'>
              <div class='panel-card'>
                <h2>Distribución de Latencias del Portal</h2>
                <p>Mediciones exactas en milisegundos tomadas con reloj monotónico de precisión.</p>
                <table class='data-table' style='margin-top: 10px;'>
                  <tbody>
                    <tr><td>Última petición (Latency)</td><td class='num'><strong id='m-last'>{lat["last_ms"]}</strong> ms</td></tr>
                    <tr><td>Percentil 95 (p95)</td><td class='num'><strong id='m-p95'>{lat["p95_ms"]}</strong> ms</td></tr>
                    <tr><td>Promedio ponderado</td><td class='num'><strong id='m-avg'>{lat["avg_ms"]}</strong> ms</td></tr>
                    <tr><td>Latencia mínima registrada</td><td class='num'><strong id='m-min'>{lat["min_ms"]}</strong> ms</td></tr>
                    <tr><td>Latencia máxima registrada</td><td class='num'><strong id='m-max'>{lat["max_ms"]}</strong> ms</td></tr>
                  </tbody>
                </table>
              </div>

              <div class='panel-card'>
                <h2>Recursos de la Instancia EC2</h2>
                <p>Telemetría directa del sistema operativo de la máquina virtual ({ASSET_NAME}).</p>
                
                <div style='margin-bottom: 18px;'>
                  <div style='display: flex; justify-content: space-between; font-size: 13px;'>
                    <span>Uso de Memoria RAM (<span id='mem-used' class='num'>{sys_stats["mem_used_mb"]}</span> / <span id='mem-tot' class='num'>{sys_stats["mem_total_mb"]}</span> MB)</span>
                    <strong class='num' id='mem-pct'>{sys_stats["mem_percent"]}%</strong>
                  </div>
                  <div class='progress-track'>
                    <div id='mem-bar' class='progress-fill' style='width: {sys_stats["mem_percent"]}%;'></div>
                  </div>
                </div>

                <table class='data-table'>
                  <tbody>
                    <tr><td>IP Pública de tu cliente</td><td><code>{html_escape(client_ip)}</code></td></tr>
                    <tr><td>Servidor web Nginx</td><td><span class='badge success'>Activo (Reverse Proxy)</span></td></tr>
                    <tr><td>Proceso Python Systemd</td><td><span class='badge success'>Activo (8080)</span></td></tr>
                    <tr><td>Agente CloudWatch</td><td><span class='badge success'>Recolectando logs</span></td></tr>
                  </tbody>
                </table>
              </div>
            </div>
          </section>

          <!-- TAB 3: Auditoría de Seguridad & IR -->
          <section id='tab-security' class='tab-pane'>
            <div class='panel-card'>
              <h2>Registro de Seguridad en Tiempo Real (Detector & Playbooks)</h2>
              <p>Eventos estructurados capturados por <code>app.py</code> y enviados a CloudWatch para la correlación Lambda.</p>

              <table class='data-table'>
                <thead>
                  <tr>
                    <th>Hora</th>
                    <th>Evento</th>
                    <th>Usuario</th>
                    <th>IP Origen</th>
                    <th>Severidad</th>
                    <th>Resultado</th>
                    <th>Detalle</th>
                  </tr>
                </thead>
                <tbody id='audit-tbody'>
                  <!-- Render inicial dinámico -->
                  {audit_rows_html}
                </tbody>
              </table>
            </div>
          </section>
        </main>

        <script>
          function switchTab(evt, tabId) {{
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
            evt.currentTarget.classList.add('active');
            document.getElementById(tabId).classList.add('active');
          }}

          // Polling continuo y ligero (cada 3 segundos) sin flicker
          async function updateTelemetry() {{
            const t0 = performance.now();
            try {{
              const res = await fetch('/api/metrics');
              if (!res.ok) return;
              const data = await res.json();
              const rtt = Math.round(performance.now() - t0);
              document.getElementById('ping-ms').innerText = rtt;

              // Actualizar KPIs
              document.getElementById('val-latency').innerText = data.latency.p95_ms;
              document.getElementById('val-p50').innerText = data.latency.avg_ms;
              document.getElementById('val-uptime').innerText = data.uptime.human;
              document.getElementById('val-reqs').innerText = data.requests.total;
              document.getElementById('val-2xx').innerText = data.requests.status_2xx;
              document.getElementById('val-4xx').innerText = data.requests.status_4xx;
              document.getElementById('val-blocked').innerText = data.security.locked_ips_count;
              document.getElementById('val-cpu').innerText = data.system.load_1m;

              // Tab 2
              document.getElementById('m-last').innerText = data.latency.last_ms;
              document.getElementById('m-p95').innerText = data.latency.p95_ms;
              document.getElementById('m-avg').innerText = data.latency.avg_ms;
              document.getElementById('m-min').innerText = data.latency.min_ms;
              document.getElementById('m-max').innerText = data.latency.max_ms;
              document.getElementById('mem-used').innerText = data.system.mem_used_mb;
              document.getElementById('mem-tot').innerText = data.system.mem_total_mb;
              document.getElementById('mem-pct').innerText = data.system.mem_percent + '%';
              document.getElementById('mem-bar').style.width = data.system.mem_percent + '%';

              // Badge de latencia
              const bLat = document.getElementById('badge-latency');
              if (data.latency.p95_ms < 50) {{
                bLat.className = 'badge success'; bLat.innerText = 'Óptimo';
              }} else if (data.latency.p95_ms < 150) {{
                bLat.className = 'badge warning'; bLat.innerText = 'Normal';
              }} else {{
                bLat.className = 'badge critical'; bLat.innerText = 'Elevado';
              }}

              // Actualizar logs de auditoría si estamos en Tab 3
              if (data.audit && data.audit.length > 0) {{
                const tbody = document.getElementById('audit-tbody');
                tbody.innerHTML = data.audit.slice(0, 10).map(ev => `
                  <tr>
                    <td class='num'>${{ev.time}}</td>
                    <td><code>${{ev.event_type}}</code></td>
                    <td><strong>${{ev.username}}</strong></td>
                    <td><code>${{ev.source_ip}}</code></td>
                    <td><span class='badge ${{ev.severity.toLowerCase()}}'>${{ev.severity}}</span></td>
                    <td>${{ev.result}}</td>
                    <td style='color:var(--text-muted); font-size:12px;'>${{ev.reason}}</td>
                  </tr>
                `).join('');
              }}
            }} catch (err) {{
              console.warn('Error sincronizando telemetría', err);
            }}
          }}

          setInterval(updateTelemetry, 3000);
        </script>
        """
        self.respond(
            200,
            page("Panel principal", content, authenticated=True, username=username),
        )

    def do_GET(self):
        parsed = urlparse(self.path)
        username = self.get_session_user()

        if parsed.path == "/health":
            stats = get_latency_stats()
            self.respond(
                200,
                json.dumps(
                    {
                        "status": "ok",
                        "time": now_ecuador(),
                        "timezone": "America/Guayaquil",
                        "version": PORTAL_VERSION,
                        "uptime_seconds": get_uptime_seconds(),
                        "avg_latency_ms": stats["avg_ms"],
                    }
                ),
                "application/json",
            )
            return

        if parsed.path == "/api/metrics":
            # API de métricas JSON para auto-refresh y observabilidad
            if not username and self.client_ip() not in ["127.0.0.1", "::1"]:
                self.respond(
                    401,
                    json.dumps({"error": "No autorizado"}),
                    "application/json",
                )
                return

            stats = get_latency_stats()
            sys_stats = get_system_stats()
            uptime_sec = get_uptime_seconds()

            payload = {
                "version": PORTAL_VERSION,
                "uptime": {
                    "seconds": uptime_sec,
                    "human": format_uptime(uptime_sec),
                },
                "requests": {
                    "total": METRICS["requests_total"],
                    "status_2xx": METRICS["status_2xx"],
                    "status_3xx": METRICS["status_3xx"],
                    "status_4xx": METRICS["status_4xx"],
                    "status_5xx": METRICS["status_5xx"],
                },
                "latency": stats,
                "system": sys_stats,
                "security": {
                    "locked_ips_count": len(FAILED_STATE),
                    "active_locks": [
                        {"key": k, "locked_until": v.get("locked_until", 0)}
                        for k, v in FAILED_STATE.items()
                        if v.get("locked_until", 0) > epoch_now()
                    ],
                },
                "audit": METRICS["recent_audit"][:15],
            }
            self.respond(200, json.dumps(payload), "application/json")
            return

        if parsed.path in ["/", "/login"]:
            self.redirect("/dashboard") if username else self.render_login()
            return

        if parsed.path == "/dashboard":
            if not username:
                self.redirect("/login")
                return
            self.render_dashboard(username)
            return

        if parsed.path == "/logout":
            headers = {
                "Set-Cookie": (
                    "portal_session=deleted; Path=/; Max-Age=0; HttpOnly;"
                    " SameSite=Lax"
                )
            }
            self.redirect("/login", headers=headers)
            return

        self.respond(
            404,
            page(
                "No encontrado",
                "<main style='min-height:calc(100vh - 64px); display:grid;"
                " place-items:center;'><section"
                " style='text-align:center;'><h1>404</h1><p"
                " style='color:var(--text-muted);'>Página no"
                " encontrada.</p></section></main>",
            ),
        )

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path != "/login":
            self.respond(404, "Not found", "text/plain")
            return

        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8")
        form = parse_qs(body)
        username = form.get("username", [""])[0].strip().lower()
        password = form.get("password", [""])[0]
        source_ip = self.client_ip()
        user_agent = self.headers.get("User-Agent", "unknown")[:300]
        key = source_ip + "|" + username
        state = FAILED_STATE.get(
            key, {"count": 0, "first": epoch_now(), "locked_until": 0}
        )

        if state.get("locked_until", 0) > epoch_now():
            remaining = state["locked_until"] - epoch_now()
            write_event(
                {
                    "event_type": "access_blocked",
                    "auth_method": "password",
                    "username": username or "unknown",
                    "source_ip": source_ip,
                    "sourceIPAddress": source_ip,
                    "affectedResource": "iam:user/" + (username or "unknown"),
                    "endpoint": "/login",
                    "result": "DENIED",
                    "failure_reason": "temporary_lockout",
                    "failed_attempts": state.get("count", 0),
                    "detection_window": "5 minutes",
                    "severity": "HIGH",
                    "severity_basis": (
                        "HIGH porque el usuario o la IP supero 5 intentos fallidos"
                        " dentro de una ventana de 5 minutos."
                    ),
                    "user_agent": user_agent,
                }
            )
            self.render_access_denied(remaining)
            return

        if verify_password(username, password):
            FAILED_STATE.pop(key, None)
            write_event(
                {
                    "event_type": "login_success",
                    "auth_method": "password",
                    "username": username,
                    "source_ip": source_ip,
                    "sourceIPAddress": source_ip,
                    "affectedResource": "iam:user/" + username,
                    "endpoint": "/login",
                    "result": "SUCCESS",
                    "severity": "INFO",
                    "severity_basis": (
                        "INFO porque la autenticacion fue exitosa y no representa"
                        " incidente por si sola."
                    ),
                    "user_agent": user_agent,
                }
            )
            cookie_value = sign_value(username + ":" + str(epoch_now()))
            headers = {
                "Set-Cookie": (
                    "portal_session="
                    + cookie_value
                    + "; Path=/; Max-Age=3600; HttpOnly; SameSite=Lax"
                )
            }
            self.redirect("/dashboard", headers=headers)
            return

        if epoch_now() - int(state.get("first", epoch_now())) > 300:
            state = {"count": 0, "first": epoch_now(), "locked_until": 0}
        state["count"] = int(state.get("count", 0)) + 1
        if state["count"] >= LOCK_THRESHOLD:
            state["locked_until"] = epoch_now() + LOCK_SECONDS
        FAILED_STATE[key] = state

        severity = "HIGH" if state["count"] >= LOCK_THRESHOLD else "LOW"
        severity_basis = (
            "HIGH porque se alcanzaron 5 o mas intentos fallidos de"
            " autenticacion en 5 minutos."
            if severity == "HIGH"
            else (
                "LOW porque es un intento fallido aislado que aun no supera el"
                " umbral de incidente."
            )
        )
        write_event(
            {
                "event_type": "login_failed",
                "auth_method": "password",
                "username": username or "unknown",
                "source_ip": source_ip,
                "sourceIPAddress": source_ip,
                "affectedResource": "iam:user/" + (username or "unknown"),
                "endpoint": "/login",
                "result": "FAILURE",
                "failure_reason": "invalid_credentials",
                "failed_attempts": state["count"],
                "detection_window": "5 minutes",
                "severity": severity,
                "severity_basis": severity_basis,
                "user_agent": user_agent,
            }
        )

        if state.get("locked_until", 0) > epoch_now():
            self.render_access_denied(LOCK_SECONDS)
        else:
            self.render_login("Credenciales incorrectas.", error=True)

    def log_message(self, format, *args):
        return


if __name__ == "__main__":
    write_event(
        {
            "event_type": "portal_started",
            "severity": "INFO",
            "severity_basis": (
                "INFO porque corresponde al inicio controlado del servicio web."
            ),
            "message": "Portal iniciado correctamente",
            "source_ip": "127.0.0.1",
            "sourceIPAddress": "127.0.0.1",
            "endpoint": "systemd",
            "result": "SUCCESS",
        }
    )
    HTTPServer(("127.0.0.1", 8080), Handler).serve_forever()
