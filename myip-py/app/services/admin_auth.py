import base64
import hmac

from fastapi import Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app.core.config import Settings, get_settings
from app.services.admin_config import read_provider_config, verify_admin_password

SESSION_COOKIE = "myip_admin_session"
SESSION_VALUE = "authenticated"
SESSION_AUTH_VERSION = "0"
LOGIN_HTML = """<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>后台登录 - myip-py</title>
  <style>
    body { margin:0; min-height:100vh; display:grid; place-items:center; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; background:#f8fafc; color:#0f172a; }
    form { width:min(420px, calc(100vw - 32px)); padding:24px; border:1px solid #dbe4ee; border-radius:18px; background:#fff; box-shadow:0 16px 36px rgba(15,23,42,.08); }
    h1 { margin:0 0 12px; font-size:26px; }
    p { color:#64748b; line-height:1.6; }
    input { width:100%; box-sizing:border-box; padding:12px; margin:8px 0; border:1px solid #dbe4ee; border-radius:10px; }
    button { width:100%; padding:12px; margin-top:10px; border:0; border-radius:10px; background:#2563eb; color:white; font-weight:700; }
  </style>
</head>
<body>
  <form method="post" action="/admin/login">
    <h1>后台登录</h1>
    <p>请输入后台用户名和密码。</p>
    <input name="username" autocomplete="username" placeholder="用户名">
    <input name="password" type="password" autocomplete="current-password" placeholder="密码">
    <button type="submit">登录</button>
  </form>
</body>
</html>"""


def current_admin_auth() -> dict:
    config = read_provider_config(include_secrets=True)
    if config.get("exists"):
        return config.get("admin_auth", {})
    return {}


def admin_auth_enabled(settings: Settings) -> bool:
    return bool(settings.myip_admin_password) or bool(current_admin_auth().get("password_hash"))


def admin_credentials_match(username: str, password: str, settings: Settings) -> bool:
    auth = current_admin_auth()
    if username == auth.get("username", "admin") and verify_admin_password(password, auth.get("password_hash", "")):
        return True
    if auth.get("password_hash"):
        return False
    return username == settings.myip_admin_username and password == settings.myip_admin_password


def signed_session_value(settings: Settings) -> str:
    auth = current_admin_auth()
    auth_version = auth.get("password_hash") or settings.myip_admin_password or SESSION_AUTH_VERSION
    payload = f"{SESSION_VALUE}:{auth_version}"
    signature = hmac.new(
        settings.myip_admin_session_secret.encode("utf-8"),
        payload.encode("utf-8"),
        "sha256",
    ).hexdigest()
    token = f"{payload}|{signature}"
    return base64.urlsafe_b64encode(token.encode("utf-8")).decode("ascii")


def session_is_valid(request: Request, settings: Settings) -> bool:
    expected = signed_session_value(settings)
    return hmac.compare_digest(request.cookies.get(SESSION_COOKIE, ""), expected)


def require_admin_auth(request: Request, settings: Settings = Depends(get_settings)) -> None:
    if admin_auth_enabled(settings) and not session_is_valid(request, settings):
        raise HTTPException(status_code=401, detail="Admin authentication required")


def admin_login_page() -> HTMLResponse:
    return HTMLResponse(LOGIN_HTML, status_code=401)


def admin_login_response(settings: Settings) -> RedirectResponse:
    response = RedirectResponse("/admin", status_code=303)
    response.set_cookie(
        SESSION_COOKIE,
        signed_session_value(settings),
        httponly=True,
        samesite="lax",
        secure=False,
    )
    return response


def admin_logout_response() -> RedirectResponse:
    response = RedirectResponse("/admin", status_code=303)
    response.delete_cookie(SESSION_COOKIE)
    return response
