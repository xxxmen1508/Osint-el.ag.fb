
import os, re, secrets, sqlite3, json, base64, hashlib
from collections import deque
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
      size INTEGER,status TEXT,sha256 TEXT,parent_id TEXT,path TEXT,is_folder INTEGER DEFAULT 0,
      modified_time TEXT,created_at TEXT DEFAULT CURRENT_TIMESTAMP)""")
    columns = {row[1] for row in c.execute("PRAGMA table_info(drive_sources)").fetchall()}
    for name, definition in {
        "parent_id": "TEXT",
        "path": "TEXT",
        "is_folder": "INTEGER DEFAULT 0",
        "modified_time": "TEXT",
    }.items():
        if name not in columns:
            c.execute(f"ALTER TABLE drive_sources ADD COLUMN {name} {definition}")
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

def safe_drive_error(error):
    """Return API diagnostics without credentials, tokens, or client secrets."""
    import html
    text = str(error)
    for secret in (GOOGLE_CLIENT_SECRET, GOOGLE_REFRESH_TOKEN):
        if secret:
            text = text.replace(secret, "[REDACTED]")
    return {
        "error_type": type(error).__name__,
        "error": html.escape(text),
    }

def drive_item_summary(item):
    return {
        "id": item.get("id"),
        "name": item.get("name"),
        "mimeType": item.get("mimeType"),
        "size": item.get("size"),
        "modifiedTime": item.get("modifiedTime"),
        "parents": item.get("parents", []),
        "driveId": item.get("driveId"),
        "trashed": item.get("trashed"),
    }

@app.get("/api/drive/diagnostics")
def drive_diagnostics(request: Request):
    """Diagnose Drive visibility using the exact credential already in session."""
    if not is_admin(request):
        raise HTTPException(403)
    if not DRIVE_FOLDER_ID:
        return JSONResponse({"ok": False, "message": "DRIVE_FOLDER_ID חסר"}, status_code=400)
    creds = credentials_from_request(request)
    if not creds:
        return JSONResponse({"ok": False, "message": "Google OAuth עדיין לא מחובר"}, status_code=400)

    try:
        from google.auth.transport.requests import Request as GoogleRequest
        if not creds.valid:
            creds.refresh(GoogleRequest())
        service = build("drive", "v3", credentials=creds, cache_discovery=False)
    except Exception as e:
        return JSONResponse({"ok": False, "stage": "token_refresh", **safe_drive_error(e)}, status_code=400)

    result = {
        "ok": True,
        "stage": "diagnostics",
        "credential_source": "encrypted_browser_cookie",
        "account": None,
        "folder": None,
        "folder_check": None,
        "parent_query": None,
        "user_corpus_query": None,
        "shared_drive_query": None,
        "interpretation": [],
    }

    try:
        about = service.about().get(fields="user(displayName,emailAddress,permissionId)").execute()
        user = about.get("user") or {}
        result["account"] = {
            "displayName": user.get("displayName"),
            "emailAddress": user.get("emailAddress"),
            "permissionId": user.get("permissionId"),
        }
    except Exception as e:
        result["account"] = {"ok": False, **safe_drive_error(e)}

    item_fields = "id,name,mimeType,size,modifiedTime,webViewLink,driveId,parents,trashed"
    try:
        folder = service.files().get(
            fileId=DRIVE_FOLDER_ID,
            fields=f"{item_fields},capabilities(canListChildren)",
            supportsAllDrives=True,
        ).execute()
        folder_drive_id = folder.get("driveId")
        result["folder"] = drive_item_summary(folder)
        result["folder"].update({
            "capabilities": folder.get("capabilities", {}),
            "isFolder": folder.get("mimeType") == "application/vnd.google-apps.folder",
            "location": "shared_drive" if folder_drive_id else "my_drive_or_shared_folder",
        })
        result["folder_check"] = {
            "ok": True,
            "canListChildren": (folder.get("capabilities") or {}).get("canListChildren"),
            "driveId": folder_drive_id,
        }
    except Exception as e:
        result["folder_check"] = {"ok": False, **safe_drive_error(e)}
        result["ok"] = False
        return JSONResponse(result, status_code=400)

    def run_list(label, **kwargs):
        options = {
            "spaces": "drive",
            "fields": f"nextPageToken,files({item_fields})",
            "pageSize": 20,
            "includeItemsFromAllDrives": True,
            "supportsAllDrives": True,
        }
        options.update(kwargs)
        try:
            response = service.files().list(**options).execute()
            items = response.get("files", [])
            return {
                "ok": True,
                "label": label,
                "options": {key: value for key, value in options.items() if key not in {"fields"}},
                "count": len(items),
                "hasNextPage": bool(response.get("nextPageToken")),
                "items": [drive_item_summary(item) for item in items],
            }
        except Exception as e:
            return {"ok": False, "label": label, **safe_drive_error(e)}

    result["parent_query"] = run_list(
        "configured_folder_children",
        q=f"'{DRIVE_FOLDER_ID}' in parents and trashed = false",
    )
    result["user_corpus_query"] = run_list(
        "user_corpus_without_parent_filter",
        q="trashed = false",
        corpora="user",
    )
    if result["folder"].get("driveId"):
        result["shared_drive_query"] = run_list(
            "shared_drive_root_sample",
            q="trashed = false",
            corpora="drive",
            driveId=result["folder"]["driveId"],
        )
    else:
        result["shared_drive_query"] = {
            "ok": True,
            "skipped": True,
            "reason": "folder metadata has no driveId",
        }

    parent_count = (result["parent_query"] or {}).get("count", 0)
    user_count = (result["user_corpus_query"] or {}).get("count", 0)
    if parent_count == 0 and user_count == 0:
        result["interpretation"].append("The credential can read folder metadata but user-corpus listing returned no visible items in the sample.")
    elif parent_count == 0 and user_count > 0:
        result["interpretation"].append("The account can see Drive items, but none are directly children of the configured folder ID.")
    elif parent_count > 0:
        result["interpretation"].append("The account can list direct children of the configured folder; recursive discovery can traverse them.")
    if result["folder"].get("driveId"):
        result["interpretation"].append("The configured folder is in a Shared Drive; driveId/corpora=drive results should be checked.")
    else:
        result["interpretation"].append("The folder metadata has no driveId; it appears to be in My Drive or a shared folder, not a Shared Drive root.")
    return result

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
            "message": "Google הצליח לאמת את האפליקציה, אבל לא הצלחנו לרענן את הרשאת Drive."
        }, status_code=400)

    try:
        service = build("drive", "v3", credentials=creds, cache_discovery=False)
        item_fields = "id,name,mimeType,size,modifiedTime,webViewLink,driveId,parents,trashed"
        folder = service.files().get(
            fileId=DRIVE_FOLDER_ID,
            fields=f"{item_fields},capabilities(canListChildren)",
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

        # Discovery is metadata-only: no files().get_media() or file content
        # is ever requested. The queue keeps only folder IDs and paths, while
        # each Drive list page is processed immediately instead of loading a
        # whole dataset into memory.
        queue = deque([(DRIVE_FOLDER_ID, folder.get("name") or DRIVE_FOLDER_ID)])
        visited = set()
        discovered_files = []
        discovered_folders = []
        c = db()
        c.execute("DELETE FROM drive_sources")

        while queue:
            parent_id, parent_path = queue.popleft()
            if parent_id in visited:
                continue
            visited.add(parent_id)
            page_token = None
            while True:
                result = service.files().list(
                    q=f"'{parent_id}' in parents and trashed = false",
                    spaces="drive",
                    fields=f"nextPageToken,files({item_fields})",
                    pageSize=1000,
                    orderBy="name_natural",
                    pageToken=page_token,
                    includeItemsFromAllDrives=True,
                    supportsAllDrives=True,
                ).execute()
                for item in result.get("files", []):
                    item_path = f"{parent_path}/{item.get('name', item.get('id', ''))}"
                    is_folder = item.get("mimeType") == "application/vnd.google-apps.folder"
                    size = item.get("size")
                    size_value = int(size) if size and str(size).isdigit() else None
                    c.execute(
                        """INSERT OR REPLACE INTO drive_sources
                        (file_id,name,mime_type,size,status,sha256,parent_id,path,is_folder,modified_time)
                        VALUES (?,?,?,?,?,?,?,?,?,?)""",
                        (item.get("id"), item.get("name"), item.get("mimeType"), size_value,
                         "discovered", None, parent_id, item_path, 1 if is_folder else 0,
                         item.get("modifiedTime")),
                    )
                    metadata = {
                        "name": item.get("name"),
                        "id": item.get("id"),
                        "mimeType": item.get("mimeType"),
                        "size": size,
                        "modifiedTime": item.get("modifiedTime"),
                        "path": item_path,
                        "parents": item.get("parents", []),
                        "webViewLink": item.get("webViewLink"),
                        "driveId": item.get("driveId"),
                    }
                    if is_folder:
                        discovered_folders.append(metadata)
                        queue.append((item.get("id"), item_path))
                    else:
                        discovered_files.append(metadata)
                page_token = result.get("nextPageToken")
                if not page_token:
                    break
        c.commit()
        c.close()

        return {
            "ok": True,
            "stage": "recursive_discovery",
            "folder": {
                "id": folder.get("id"),
                "name": folder.get("name"),
                "mimeType": folder.get("mimeType"),
                "driveId": folder.get("driveId"),
                "canListChildren": (folder.get("capabilities") or {}).get("canListChildren"),
            },
            "count": len(discovered_files),
            "folder_count": len(discovered_folders),
            "files": discovered_files,
            "folders": discovered_folders,
            "downloaded": False,
        }
    except Exception as e:
        import html
        text = str(e)
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
            "message": "Google Drive דחה את בקשת ה-Discovery. הפרטים למטה אינם כוללים token או secret."
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
