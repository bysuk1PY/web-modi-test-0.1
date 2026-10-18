import os
import secrets
from pathlib import Path
from html import escape
from urllib.parse import urlencode

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

import sqlite3
from fastapi.responses import JSONResponse


BASE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = BASE_DIR.parent

load_dotenv(PROJECT_DIR / ".env")

DATABASE_PATH = Path(
    os.getenv("DATABASE_PATH", "database/mod_i.sqlite3")
)

if not DATABASE_PATH.is_absolute():
    DATABASE_PATH = PROJECT_DIR / DATABASE_PATH


CLIENT_ID = os.getenv("DISCORD_CLIENT_ID", "").strip()
CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET", "").strip()
BOT_TOKEN = os.getenv("DISCORD_TOKEN", "").strip()
REDIRECT_URI = os.getenv(
    "DISCORD_REDIRECT_URI",
    "http://127.0.0.1:8000/auth/callback",
).strip()
OWNER_ID = os.getenv("DISCORD_OWNER_ID", "").strip()
SESSION_SECRET = os.getenv("SESSION_SECRET", "").strip()

app = FastAPI(
    title="mod-I Control Panel",
    docs_url=None,
    redoc_url=None,
)

if SESSION_SECRET:
    app.add_middleware(
        SessionMiddleware,
        secret_key=SESSION_SECRET,
        same_site="lax",
        https_only=False,
        max_age=8 * 60 * 60,
    )

app.mount(
    "/static",
    StaticFiles(directory=BASE_DIR / "static"),
    name="static",
)


def configuration_error() -> str | None:
    missing = []

    if not CLIENT_ID:
        missing.append("DISCORD_CLIENT_ID")
    if not CLIENT_SECRET:
        missing.append("DISCORD_CLIENT_SECRET")
    if not OWNER_ID:
        missing.append("DISCORD_OWNER_ID")
    if not SESSION_SECRET:
        missing.append("SESSION_SECRET")

    if missing:
        return "Не заполнены настройки в .env: " + ", ".join(missing)

    return None


@app.get("/")
async def dashboard(request: Request):
    error = configuration_error()
    if error:
        return PlainTextResponse(error, status_code=500)

    if request.session.get("owner_id") != OWNER_ID:
        return RedirectResponse("/login", status_code=303)

    username = escape(
        str(request.session.get("username", "Владелец"))
    )

    html = (BASE_DIR / "index.html").read_text(encoding="utf-8")

    owner_panel = f"""
    <div style="
        position:fixed;
        top:16px;
        right:20px;
        z-index:9999;
        display:flex;
        align-items:center;
        gap:12px;
        padding:10px 14px;
        background:#171923;
        border:1px solid #343746;
        border-radius:12px;
        color:#ffffff;
        font:14px Arial,sans-serif;
    ">
        <span>👤 {username}</span>
        <a href="/logout" style="
            color:#b5a7ff;
            text-decoration:none;
            font-weight:bold;
        ">Выйти</a>
    </div>
    """

    html = html.replace("</body>", owner_panel + "</body>")

    from fastapi.responses import HTMLResponse
    return HTMLResponse(html)


@app.get("/login")
async def login(request: Request):
    error = configuration_error()
    if error:
        return PlainTextResponse(error, status_code=500)

    if request.session.get("owner_id") == OWNER_ID:
        return RedirectResponse("/", status_code=303)

    return FileResponse(BASE_DIR / "login.html")


@app.get("/auth/discord")
async def discord_login(request: Request):
    error = configuration_error()
    if error:
        return PlainTextResponse(error, status_code=500)

    state = secrets.token_urlsafe(32)
    request.session["oauth_state"] = state

    params = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "redirect_uri": REDIRECT_URI,
        "scope": "identify",
        "state": state,
    }

    url = "https://discord.com/oauth2/authorize?" + urlencode(params)
    return RedirectResponse(url, status_code=302)


@app.get("/auth/callback")
async def auth_callback(request: Request, code: str = "", state: str = ""):
    error = configuration_error()
    if error:
        return PlainTextResponse(error, status_code=500)

    saved_state = request.session.pop("oauth_state", None)

    if not code or not state or not saved_state or state != saved_state:
        request.session.clear()
        return PlainTextResponse(
            "Авторизация не прошла проверку безопасности. Вернись на сайт и попробуй снова.",
            status_code=400,
        )

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            token_response = await client.post(
                "https://discord.com/api/oauth2/token",
                data={
                    "client_id": CLIENT_ID,
                    "client_secret": CLIENT_SECRET,
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": REDIRECT_URI,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )

            if token_response.status_code != 200:
                return PlainTextResponse(
                    "Discord не подтвердил авторизацию. Проверь OAuth2-настройки и Redirect URI.",
                    status_code=502,
                )

            access_token = token_response.json().get("access_token")
            if not access_token:
                return PlainTextResponse(
                    "Discord не вернул токен авторизации.",
                    status_code=502,
                )

            user_response = await client.get(
                "https://discord.com/api/users/@me",
                headers={"Authorization": f"Bearer {access_token}"},
            )

            if user_response.status_code != 200:
                return PlainTextResponse(
                    "Не удалось получить профиль Discord.",
                    status_code=502,
                )

            user = user_response.json()

    except httpx.HTTPError:
        return PlainTextResponse(
            "Не удалось связаться с Discord. Проверь интернет и попробуй ещё раз.",
            status_code=502,
        )

    if str(user.get("id", "")) != OWNER_ID:
        request.session.clear()
        return PlainTextResponse(
            "Доступ запрещён: этот Discord-аккаунт не является владельцем mod-I.",
            status_code=403,
        )

    request.session.clear()
    request.session["owner_id"] = OWNER_ID
    request.session["username"] = user.get("global_name") or user.get("username", "Владелец")

    return RedirectResponse("/", status_code=303)


@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)

@app.get("/api/status")
async def api_status(request: Request):
    if request.session.get("owner_id") != OWNER_ID:
        return JSONResponse(
            {"error": "Доступ запрещён"},
            status_code=403,
        )

    if not DATABASE_PATH.is_file():
        return JSONResponse({
            "database": "не найдена",
            "violations": None,
        })

    try:
        database_uri = DATABASE_PATH.as_uri() + "?mode=ro"

        with sqlite3.connect(
            database_uri,
            uri=True,
            timeout=5,
        ) as connection:
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master "
                    "WHERE type = 'table'"
                )
            }

            violations = None

            if "moderator_violations" in tables:
                violations = connection.execute(
                    "SELECT COUNT(*) FROM moderator_violations"
                ).fetchone()[0]

        return JSONResponse({
            "database": "подключена",
            "violations": violations,
        })

    except sqlite3.Error:
        return JSONResponse({
            "database": "ошибка чтения",
            "violations": None,
        })

@app.get("/api/bot-status")
async def api_bot_status(request: Request):
    if request.session.get("owner_id") != OWNER_ID:
        return JSONResponse(
            {"error": "Доступ запрещён"},
            status_code=403,
        )

    if not BOT_TOKEN:
        return JSONResponse({
            "connected": False,
            "name": None,
            "message": "DISCORD_TOKEN не найден в .env",
        })

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(
                "https://discord.com/api/v10/users/@me",
                headers={
                    "Authorization": f"Bot {BOT_TOKEN}"
                },
            )

        if response.status_code == 200:
            bot = response.json()

            return JSONResponse({
                "connected": True,
                "name": bot.get("username", "mod-I"),
                "message": "Discord API доступен",
            })

        if response.status_code == 401:
            return JSONResponse({
                "connected": False,
                "name": None,
                "message": "Discord отклонил токен",
            })

        return JSONResponse({
            "connected": False,
            "name": None,
            "message": f"Discord API ответил: {response.status_code}",
        })

    except httpx.HTTPError:
        return JSONResponse({
            "connected": False,
            "name": None,
            "message": "Не удалось связаться с Discord",
        })


@app.get("/api/gateway-status")
async def api_gateway_status(request: Request):
    if request.session.get("owner_id") != OWNER_ID:
        return JSONResponse(
            {"error": "Доступ запрещён"},
            status_code=403,
        )

    status_file = PROJECT_DIR / "web_panel" / "bot_status.json"

    if not status_file.exists():
        return JSONResponse({
            "connected": False,
            "latency_ms": None,
            "message": "Бот ещё не передал статус",
        })

    try:
        import json
        import time

        data = json.loads(
            status_file.read_text(encoding="utf-8")
        )

        if time.time() - data.get("updated_at", 0) > 20:
            return JSONResponse({
                "connected": False,
                "latency_ms": None,
                "message": "Нет свежего статуса от бота",
            })

        return JSONResponse({
            "connected": data.get("connected", False),
            "latency_ms": data.get("latency_ms"),
            "message": (
                "Бот подключён к Discord"
                if data.get("connected")
                else "Бот не подключён к Discord"
            ),
        })

    except (OSError, ValueError, TypeError):
        return JSONResponse({
            "connected": False,
            "latency_ms": None,
            "message": "Не удалось прочитать статус",
        })


@app.get("/api/panel-info")
async def api_panel_info(request: Request):
    if request.session.get("owner_id") != OWNER_ID:
        return JSONResponse(
            {"error": "Доступ запрещён"},
            status_code=403,
        )

    return JSONResponse({
        "panel": "mod-I",
        "version": "0.1.0",
        "sections": [
            "dashboard",
            "server",
            "commands",
            "command-builder",
            "categories",
            "automation",
            "ranks",
            "limits",
            "logs",
            "settings",
            "security",
        ],
    })


@app.get("/api/server-settings")
async def api_server_settings(request: Request):
    if request.session.get("owner_id") != OWNER_ID:
        return JSONResponse(
            {"error": "Доступ запрещён"},
            status_code=403,
        )

    import sqlite3

    try:
        with sqlite3.connect(
            f"file:{DATABASE_PATH.as_posix()}?mode=ro",
            uri=True,
            timeout=5,
        ) as connection:
            rows = connection.execute(
                """
                SELECT key, value
                FROM guild_config
                ORDER BY key
                """
            ).fetchall()

        return JSONResponse({
            "settings": {
                key: value
                for key, value in rows
            }
        })

    except sqlite3.Error:
        return JSONResponse(
            {"error": "Не удалось прочитать настройки"},
            status_code=500,
        )


from pydantic import BaseModel, Field


class ServerSettingsUpdate(BaseModel):
    limit_warn: int = Field(ge=1, le=100)
    limit_timeout: int = Field(ge=1, le=100)
    auto_timeout_threshold: int = Field(ge=1, le=100)
    auto_timeout_minutes: int = Field(ge=1, le=40320)


@app.post("/api/server-settings")
async def update_server_settings(
    request: Request,
    payload: ServerSettingsUpdate,
):
    if request.session.get("owner_id") != OWNER_ID:
        return JSONResponse(
            {"error": "Доступ запрещён"},
            status_code=403,
        )

    import sqlite3

    guild_id = 1560318271801135265

    settings = {
        "limit_warn": payload.limit_warn,
        "limit_timeout": payload.limit_timeout,
        "auto_timeout_threshold": payload.auto_timeout_threshold,
        "auto_timeout_minutes": payload.auto_timeout_minutes,
    }

    try:
        with sqlite3.connect(
            str(DATABASE_PATH),
            timeout=5,
        ) as connection:
            connection.execute("BEGIN IMMEDIATE")

            for key, value in settings.items():
                connection.execute(
                    """
                    INSERT INTO guild_config
                        (guild_id, key, value, updated_by)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(guild_id, key)
                    DO UPDATE SET
                        value = excluded.value,
                        updated_by = excluded.updated_by,
                        updated_at = strftime(
                            '%Y-%m-%dT%H:%M:%fZ', 'now'
                        )
                    """,
                    (guild_id, key, str(value), int(OWNER_ID)),
                )

        return JSONResponse({
            "success": True,
            "message": "Настройки сохранены",
        })

    except sqlite3.Error:
        return JSONResponse(
            {"error": "Не удалось сохранить настройки"},
            status_code=500,
        )
