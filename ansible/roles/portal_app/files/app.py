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
SESSION_SECRET_FILE = os.environ.get("PORTAL_SESSION_SECRET_FILE", "/opt/tesis-portal/session_secret")
LOCK_THRESHOLD = 5
LOCK_SECONDS = 300
EC_TZ = timezone(timedelta(hours=-5), name="America/Guayaquil")
AFFECTED_SERVICE = "Portal de autenticacion corporativo"
ASSET_NAME = os.environ.get("PORTAL_ASSET_NAME", "tesis-ir-portal-ec2")
ASSET_TYPE = "EC2 web application"
COMPANY_NAME = "Asteria Operaciones"

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


def now_ecuador():
    return datetime.now(EC_TZ).isoformat()


def now_utc():
    return datetime.now(timezone.utc).isoformat()


def epoch_now():
    return int(time.time())


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
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(base_event(event), ensure_ascii=False, separators=(",", ":")) + "\n")


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
    expected = hmac.new(SESSION_SECRET, payload.encode("utf-8"), hashlib.sha256).hexdigest()
    if hmac.compare_digest(sig, expected):
        return payload
    return None


def html_escape(value):
    return html.escape(str(value if value is not None else ""))


def page(title, content, authenticated=False, username=None):
    session_area = ""
    if authenticated:
        session_area = f"<span>{html_escape(username)}</span><a href='/logout'>Salir</a>"
    return f"""<!DOCTYPE html>
<html lang='es'>
<head>
  <meta charset='UTF-8'>
  <meta name='viewport' content='width=device-width, initial-scale=1.0'>
  <title>{html_escape(title)}</title>
  <style>
    :root {{ --bg:#0b1120; --panel:#ffffff; --muted:#64748b; --text:#0f172a; --blue:#1d4ed8; --red:#b91c1c; --border:#e2e8f0; }}
    * {{ box-sizing:border-box; }}
    body {{ margin:0; min-height:100vh; font-family:Inter, Segoe UI, Roboto, Arial, sans-serif; background:linear-gradient(135deg,#0f172a,#1e3a8a); color:var(--text); }}
    .header {{ height:68px; display:flex; align-items:center; justify-content:space-between; padding:0 34px; color:white; }}
    .brand {{ font-weight:800; letter-spacing:.2px; font-size:19px; }}
    .session a {{ margin-left:16px; color:white; text-decoration:none; border:1px solid rgba(255,255,255,.35); border-radius:999px; padding:8px 13px; font-weight:700; }}
    .login-wrap {{ min-height:calc(100vh - 68px); display:grid; place-items:center; padding:30px; }}
    .login-card {{ width:100%; max-width:430px; background:var(--panel); border:1px solid var(--border); border-radius:26px; padding:34px; box-shadow:0 24px 70px rgba(0,0,0,.30); }}
    h1 {{ margin:0 0 8px; font-size:29px; }}
    p {{ color:var(--muted); line-height:1.55; }}
    label {{ display:block; font-weight:750; margin:16px 0 7px; }}
    input {{ width:100%; padding:14px 14px; border:1px solid #cbd5e1; border-radius:13px; font-size:15px; outline:none; }}
    input:focus {{ border-color:var(--blue); box-shadow:0 0 0 4px #dbeafe; }}
    button,.btn {{ width:100%; display:inline-block; text-align:center; border:0; background:var(--blue); color:white; padding:13px 16px; border-radius:13px; font-weight:800; text-decoration:none; cursor:pointer; margin-top:20px; }}
    .alert {{ border-radius:14px; padding:13px 15px; margin:16px 0; font-weight:650; }}
    .alert.error {{ background:#fee2e2; color:#7f1d1d; border:1px solid #fecaca; }}
    .alert.info {{ background:#eff6ff; color:#1e3a8a; border:1px solid #bfdbfe; }}
    .app {{ background:#f8fafc; min-height:calc(100vh - 68px); padding:34px; }}
    .grid {{ max-width:980px; margin:0 auto; display:grid; grid-template-columns:repeat(3,1fr); gap:18px; }}
    .card {{ background:#fff; border:1px solid var(--border); border-radius:22px; padding:24px; box-shadow:0 14px 32px rgba(15,23,42,.08); }}
    .wide {{ grid-column:1 / -1; }}
    .metric {{ font-size:30px; font-weight:850; margin:10px 0 2px; }}
    @media(max-width:820px){{ .grid {{ grid-template-columns:1fr; }} .header {{ padding:0 18px; }} }}
  </style>
</head>
<body>
  <div class='header'><div class='brand'>{COMPANY_NAME}</div><div class='session'>{session_area}</div></div>
  {content}
</body>
</html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "AsteriaPortal/1.0"

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

    def respond(self, status, body, content_type="text/html; charset=utf-8", headers=None):
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(encoded)))
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
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Cache-Control", "no-store")
        if headers:
            for key, value in headers.items():
                self.send_header(key, value)
        self.end_headers()

    def render_login(self, message=None, error=False):
        alert = ""
        if message:
            kind = "error" if error else "info"
            alert = f"<div class='alert {kind}'>{html_escape(message)}</div>"
        content = f"""
        <main class='login-wrap'>
          <section class='login-card'>
            <h1>Iniciar sesion</h1>
            <p>Acceda con sus credenciales corporativas.</p>
            {alert}
            <form method='POST' action='/login' autocomplete='off'>
              <label for='username'>Usuario</label>
              <input id='username' name='username' required maxlength='64' autocomplete='username'>
              <label for='password'>Contrasena</label>
              <input id='password' name='password' type='password' required maxlength='128' autocomplete='current-password'>
              <button type='submit'>Ingresar</button>
            </form>
          </section>
        </main>
        """
        self.respond(200, page("Inicio de sesion", content))

    def render_dashboard(self, username):
        role = USERS.get(username, {}).get("display", "Usuario")
        content = f"""
        <main class='app'>
          <section class='grid'>
            <div class='card wide'>
              <h1>Panel principal</h1>
              <p>Bienvenido, {html_escape(username)}. Perfil asignado: {html_escape(role)}.</p>
            </div>
            <div class='card'><p>Solicitudes</p><div class='metric'>12</div><p>En revision</p></div>
            <div class='card'><p>Operaciones</p><div class='metric'>98%</div><p>Disponibilidad</p></div>
            <div class='card'><p>Cuenta</p><div class='metric'>Activa</div><p>Sesion protegida</p></div>
          </section>
        </main>
        """
        self.respond(200, page("Panel principal", content, authenticated=True, username=username))

    def render_access_denied(self, remaining):
        content = f"""
        <main class='login-wrap'>
          <section class='login-card'>
            <h1>Acceso temporalmente restringido</h1>
            <p>Se detectaron demasiados intentos incorrectos. Intente nuevamente en unos minutos.</p>
            <div class='alert error'>Tiempo restante aproximado: {remaining} segundos</div>
            <a class='btn' href='/login'>Volver</a>
          </section>
        </main>
        """
        self.respond(403, page("Acceso restringido", content))

    def do_GET(self):
        parsed = urlparse(self.path)
        username = self.get_session_user()
        if parsed.path == "/health":
            self.respond(200, json.dumps({"status": "ok", "time": now_ecuador(), "timezone": "America/Guayaquil"}), "application/json")
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
            headers = {"Set-Cookie": "portal_session=deleted; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"}
            self.redirect("/login", headers=headers)
            return
        self.respond(404, page("No encontrado", "<main class='login-wrap'><section class='login-card'><h1>404</h1><p>Pagina no encontrada.</p></section></main>"))

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
        state = FAILED_STATE.get(key, {"count": 0, "first": epoch_now(), "locked_until": 0})

        if state.get("locked_until", 0) > epoch_now():
            remaining = state["locked_until"] - epoch_now()
            write_event({
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
                "severity_basis": "HIGH porque el usuario o la IP supero 5 intentos fallidos dentro de una ventana de 5 minutos.",
                "user_agent": user_agent,
            })
            self.render_access_denied(remaining)
            return

        if verify_password(username, password):
            FAILED_STATE.pop(key, None)
            write_event({
                "event_type": "login_success",
                "auth_method": "password",
                "username": username,
                "source_ip": source_ip,
                "sourceIPAddress": source_ip,
                "affectedResource": "iam:user/" + username,
                "endpoint": "/login",
                "result": "SUCCESS",
                "severity": "INFO",
                "severity_basis": "INFO porque la autenticacion fue exitosa y no representa incidente por si sola.",
                "user_agent": user_agent,
            })
            cookie_value = sign_value(username + ":" + str(epoch_now()))
            headers = {"Set-Cookie": "portal_session=" + cookie_value + "; Path=/; Max-Age=3600; HttpOnly; SameSite=Lax"}
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
            "HIGH porque se alcanzaron 5 o mas intentos fallidos de autenticacion en 5 minutos."
            if severity == "HIGH" else
            "LOW porque es un intento fallido aislado que aun no supera el umbral de incidente."
        )
        write_event({
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
        })

        if state.get("locked_until", 0) > epoch_now():
            self.render_access_denied(LOCK_SECONDS)
        else:
            self.render_login("Credenciales incorrectas.", error=True)

    def log_message(self, format, *args):
        return


if __name__ == "__main__":
    write_event({
        "event_type": "portal_started",
        "severity": "INFO",
        "severity_basis": "INFO porque corresponde al inicio controlado del servicio web.",
        "message": "Portal iniciado correctamente",
        "source_ip": "127.0.0.1",
        "sourceIPAddress": "127.0.0.1",
        "endpoint": "systemd",
        "result": "SUCCESS",
    })
    HTTPServer(("127.0.0.1", 8080), Handler).serve_forever()
