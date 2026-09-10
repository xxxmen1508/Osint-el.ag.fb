
import os, re, secrets, sqlite3, json, base64, hashlib
from pathlib import Path
from urllib.parse import urlencode

from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from cryptography.fernet import Fernet, InvalidToken

DATA_DIR = Path(os.getenv("DATA_DIR", "/tmp/unified_ai_lab"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB = DATA_DIR / "lab.db"

ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "change-me")
SESSION_SECRET = os.getenv("SESSION_SECRET", secrets.token_hex(32))
DRIVE_FOLDER_ID = os.getenv("DRIVE_FOLDER_ID", "").strip()
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "").strip()
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "").strip()
GOOGLE_REFRESH_TOKEN = os.getenv("GOOGLE_REFRESH_TOKEN", "").strip()
TOKEN_COOKIE = "unified_ai_drive_token"
DISABLED_COOKIE = "unified_ai_drive_disabled"

SCOPES = ["https://www.googleapis.com/auth/drive.readonly"]
REDIRECT_URI = os.getenv(
    "GOOGLE_REDIRECT_URI",
    "https://osint-el-ag-fb.onrender.com/oauth2callback",
)

app = FastAPI(title="Unified AI Data Intelligence Lab V5 OAuth Reconnect")
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET)
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    c.execute("""CREATE TABLE IF NOT EXISTS drive_sources(
      id INTEGER PRIMARY KEY AUTOINCREMENT,file_id TEXT UNIQUE,name TEXT,mime_type TEXT,
      size INTEGER,status TEXT,sha256 TEXT,created_at TEXT DEFAULT CURRENT_TIMESTAMP)""")
    c.commit()
    return c

def is_admin(r: Request):
    return r.session.get("admin") is True

def token_fernet():
    key = base64.urlsafe_b64encode(hashlib.sha256(SESSION_SECRET.encode("utf-8")).digest())
    return Fernet(key)

def encrypt_refresh_token(token: str) -> str:
    return token_fernet().encrypt(token.encode("utf-8")).decode("ascii")

def decrypt_refresh_token(value: str) -> str | None:
    if not value:
        return None
    try:
        return token_fernet().decrypt(value.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError, TypeError):
        return None

def refresh_token_from_request(request: Request) -> str:
    # A Render environment token is legacy configuration only. It must never
    # make the UI look connected or override an explicit browser disconnect.
    # Fresh OAuth credentials are stored in the encrypted HttpOnly cookie.
    if request.cookies.get(DISABLED_COOKIE) == "1":
        return ""
    return decrypt_refresh_token(request.cookies.get(TOKEN_COOKIE, "")) or ""

def browser_drive_connected(request: Request) -> bool:
    return bool(refresh_token_from_request(request))

def credentials_from_request(request: Request):
    refresh = refresh_token_from_request(request)
    if not (GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET and refresh):
        return None
    return Credentials(
        token=None,
        refresh_token=refresh,
        token_uri="https://oauth2.googleapis.com/token",
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET,
        scopes=SCOPES,
    )

def client_config():
    return {
        "web": {
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [REDIRECT_URI],
        }
    }

def oauth_flow(state=None):
    flow = Flow.from_client_config(client_config(), scopes=SCOPES, state=state)
    flow.redirect_uri = REDIRECT_URI
    return flow

@app.get("/health")
def health():
    return {
        "ok": True,
        "version": "v5-oauth-reconnect",
        "drive_folder_configured": bool(DRIVE_FOLDER_ID),
        "oauth_client_configured": bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET),
        "refresh_token_configured": bool(GOOGLE_REFRESH_TOKEN),
    }

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    rows = db().execute("SELECT * FROM drive_sources ORDER BY id DESC").fetchall()
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "request": request,
            "admin": is_admin(request),
            "rows": rows,
            "folder": DRIVE_FOLDER_ID,
            "oauth_ready": bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET),
            "drive_ready": browser_drive_connected(request),
            "legacy_refresh_configured": bool(GOOGLE_REFRESH_TOKEN),
        },
    )

@app.post("/login")
def login(request: Request, password: str = Form(...)):
    if not secrets.compare_digest(password, ADMIN_PASSWORD):
        raise HTTPException(401, "סיסמה שגויה")
    request.session["admin"] = True
    return RedirectResponse("/", status_code=303)

@app.post("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/", status_code=303)

@app.get("/google/login")
def google_login(request: Request):
    if not is_admin(request):
        raise HTTPException(403)
    if not (GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET):
        raise HTTPException(400, "GOOGLE_CLIENT_ID/GOOGLE_CLIENT_SECRET חסרים ב-Render")
    flow = oauth_flow()
    # Google may require PKCE for this OAuth client. The verifier must survive
    # the redirect and be supplied again when exchanging the authorization code.
    code_verifier = secrets.token_urlsafe(64)
    flow.code_verifier = code_verifier
    authorization_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent",
        code_challenge_method="S256",
    )
    request.session["oauth_state"] = state
    request.session["oauth_code_verifier"] = code_verifier
    return RedirectResponse(authorization_url)

@app.get("/oauth2callback", response_class=HTMLResponse)
def oauth2callback(request: Request, code: str = "", state: str = ""):
    if not code:
        return HTMLResponse("<h2>Google OAuth failed</h2><p>לא התקבל קוד הרשאה.</p>", status_code=400)
    saved_state = request.session.get("oauth_state")
    if saved_state and state and saved_state != state:
        return HTMLResponse("<h2>OAuth state mismatch</h2>", status_code=400)

    flow = oauth_flow(state=state or None)
    code_verifier = request.session.get("oauth_code_verifier")
    if not code_verifier:
        return HTMLResponse(
            "<h2>Google OAuth error</h2><p>חסר code_verifier של PKCE. התחל התחברות מחדש.</p>",
            status_code=400,
        )
    try:
        flow.fetch_token(code=code, code_verifier=code_verifier)
    except Exception as e:
        # Show the OAuth error category/details to the admin, but never expose
        # client secrets or tokens. This makes configuration errors diagnosable.
        import html
        err_type = html.escape(type(e).__name__)
        err_text = html.escape(str(e))
        return HTMLResponse(
            f"""<!doctype html><html lang=\"he\" dir=\"rtl\"><meta charset=\"utf-8\">
            <body style=\"font-family:Arial;max-width:800px;margin:40px auto;padding:20px\">
            <h2>Google OAuth error</h2>
            <p>Google דחה את החלפת קוד ההרשאה ב-token.</p>
            <p><b>סוג שגיאה:</b> <code>{err_type}</code></p>
            <p><b>פרטי השגיאה:</b></p>
            <pre style=\"white-space:pre-wrap;background:#eee;padding:14px;direction:ltr;text-align:left\">{err_text}</pre>
            <p>אל תשלח סודות או tokens. את הטקסט הזה אפשר לשלוח לבדיקה.</p>
            </body></html>""",
            status_code=400,
        )

    creds = flow.credentials
    refresh = creds.refresh_token or ""
    if not refresh:
        return HTMLResponse(
            "<h2>Google OAuth הצליח, אבל Google לא החזיר Refresh Token חדש.</h2>"
            "<p>לחץ על חיבור מחדש ונסה שוב.</p>", status_code=400
        )

    response = RedirectResponse("/", status_code=303)
    response.set_cookie(
        TOKEN_COOKIE,
        encrypt_refresh_token(refresh),
        max_age=60 * 60 * 24 * 180,
        httponly=True,
        secure=True,
        samesite="lax",
        path="/",
    )
    response.delete_cookie(DISABLED_COOKIE, path="/")
    request.session.pop("oauth_state", None)
    request.session.pop("oauth_code_verifier", None)
    request.session["google_drive_connected"] = True
    return response


@app.post("/google/disconnect")
def google_disconnect(request: Request):
    if not is_admin(request):
        raise HTTPException(403)
    response = RedirectResponse("/", status_code=303)
    response.delete_cookie(TOKEN_COOKIE, path="/")
    # Persist the explicit disconnect across Admin logout and new sessions.
    # This also prevents a stale GOOGLE_REFRESH_TOKEN from being retried.
    response.set_cookie(
        DISABLED_COOKIE,
        "1",
        max_age=60 * 60 * 24 * 365,
        httponly=True,
        secure=True,
        samesite="lax",
        path="/",
    )
    request.session.pop("google_drive_connected", None)
    return response

@app.get("/api/drive/files")
def drive_files(request: Request):
    if not is_admin(request):
        raise HTTPException(403)
    if not DRIVE_FOLDER_ID:
        return JSONResponse({"ok": False, "message": "DRIVE_FOLDER_ID חסר"}, status_code=400)
    creds = credentials_from_request(request)
    if not creds:
        return JSONResponse({"ok": False, "message": "Google OAuth עדיין לא מחובר"}, status_code=400)

    # Do not log or return tokens/secrets. Refresh explicitly so failures are
    # distinguishable from folder/permission failures.
    try:
        from google.auth.transport.requests import Request as GoogleRequest
        if not creds.valid:
            creds.refresh(GoogleRequest())
    except Exception as e:
        import html
        return JSONResponse({
            "ok": False,
            "stage": "token_refresh",
            "error_type": type(e).__name__,
            "error": html.escape(str(e)),
            "message": "Google הצליח לאמת את האפליקציה, אבל לא הצלחנו לרענן את הרשאת Drive. בדוק שה-GOOGLE_REFRESH_TOKEN שייך לאותו OAuth Client."
        }, status_code=400)

    try:
        service = build("drive", "v3", credentials=creds, cache_discovery=False)

        # First verify that the configured ID is a readable folder. This gives
        # a much more useful diagnosis than a generic files.list failure.
        folder = service.files().get(
            fileId=DRIVE_FOLDER_ID,
            fields="id,name,mimeType,driveId,trashed,capabilities(canListChildren)",
            supportsAllDrives=True,
        ).execute()

        if folder.get("mimeType") != "application/vnd.google-apps.folder":
            return JSONResponse({
                "ok": False,
                "stage": "folder_check",
                "error": "not_a_folder",
                "message": "ה-FOLDER ID שהוגדר אינו מצביע על תיקיית Google Drive.",
                "item": folder,
            }, status_code=400)

        # Google Drive's list API uses '<folderId>' in parents for children.
        # Include all drives so the same code also works if the folder is moved
        # to a Shared Drive.
        q = f"'{DRIVE_FOLDER_ID}' in parents and trashed = false"
        result = service.files().list(
            q=q,
            spaces="drive",
            fields="nextPageToken,files(id,name,mimeType,size,modifiedTime,webViewLink,driveId)",
            pageSize=1000,
            orderBy="name_natural",
            includeItemsFromAllDrives=True,
            supportsAllDrives=True,
        ).execute()

        return {
            "ok": True,
            "stage": "list",
            "folder": {
                "id": folder.get("id"),
                "name": folder.get("name"),
                "mimeType": folder.get("mimeType"),
                "driveId": folder.get("driveId"),
                "canListChildren": (folder.get("capabilities") or {}).get("canListChildren"),
            },
            "count": len(result.get("files", [])),
            "files": result.get("files", []),
        }
    except Exception as e:
        import html
        text = str(e)
        # Return only diagnostic API information, never credentials.
        details = text
        try:
            import json as _json
            if hasattr(e, "content") and e.content:
                raw = e.content.decode("utf-8", "replace") if isinstance(e.content, (bytes, bytearray)) else str(e.content)
                try:
                    payload = _json.loads(raw)
                    details = _json.dumps(payload, ensure_ascii=False)
                except Exception:
                    details = raw
        except Exception:
            pass
        return JSONResponse({
            "ok": False,
            "stage": "drive_api",
            "error_type": type(e).__name__,
            "error": html.escape(details),
            "message": "Google Drive דחה את הבקשה. הפרטים למטה מיועדים לאבחון ואינם כוללים token או secret."
        }, status_code=400)

@app.get("/api/status")
def status(request: Request):
    if not is_admin(request):
        raise HTTPException(403)
    c = db()
    return {
        "drive_folder_id": DRIVE_FOLDER_ID or None,
        "oauth_client_configured": bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET),
        "refresh_token_configured": bool(GOOGLE_REFRESH_TOKEN),
        "sources": [dict(x) for x in c.execute("SELECT * FROM drive_sources ORDER BY id DESC").fetchall()],
    }

@app.get("/api/search")
def search(request: Request, q: str = ""):
    if not is_admin(request):
        raise HTTPException(403)
    # V3 keeps the zero-hallucination rule: until real indexing exists,
    # metadata search must not pretend to have record-level results.
    return {"status": "לא נמצא", "results": []}
