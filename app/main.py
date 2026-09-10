
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

DATA_DIR = Path(os.getenv("DATA_DIR", "/tmp/unified_ai_lab"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB = DATA_DIR / "lab.db"

ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "change-me")
SESSION_SECRET = os.getenv("SESSION_SECRET", secrets.token_hex(32))
DRIVE_FOLDER_ID = os.getenv("DRIVE_FOLDER_ID", "").strip()
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "").strip()
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "").strip()
GOOGLE_REFRESH_TOKEN = os.getenv("GOOGLE_REFRESH_TOKEN", "").strip()

SCOPES = ["https://www.googleapis.com/auth/drive.readonly"]
REDIRECT_URI = os.getenv(
    "GOOGLE_REDIRECT_URI",
    "https://osint-el-ag-fb.onrender.com/oauth2callback",
)

app = FastAPI(title="Unified AI Data Intelligence Lab V3")
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

def credentials_from_env():
    if not (GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET and GOOGLE_REFRESH_TOKEN):
        return None
    return Credentials(
        token=None,
        refresh_token=GOOGLE_REFRESH_TOKEN,
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
        "version": "v3",
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
            "drive_ready": bool(credentials_from_env()),
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
    # The refresh token is intentionally not sent to the server logs.
    safe = refresh.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return HTMLResponse(f"""
    <!doctype html><html lang="he" dir="rtl"><meta charset="utf-8">
    <body style="font-family:Arial;max-width:760px;margin:40px auto;padding:20px">
      <h2>החיבור ל-Google הצליח ✅</h2>
      <p>קיבלת Refresh Token. זה סוד אבטחה — <b>אל תשלח אותו אליי ואל תעלה אותו ל-GitHub.</b></p>
      <p>העתק אותו ישירות ל-Render Environment בשם:</p>
      <pre style="white-space:pre-wrap;background:#eee;padding:12px">{safe}</pre>
      <p>לאחר שהוספת אותו ל-Render, בצע Deploy מחדש.</p>
    </body></html>
    """)

@app.get("/api/drive/files")
def drive_files(request: Request):
    if not is_admin(request):
        raise HTTPException(403)
    if not DRIVE_FOLDER_ID:
        return JSONResponse({"ok": False, "message": "DRIVE_FOLDER_ID חסר"})
    creds = credentials_from_env()
    if not creds:
        return JSONResponse({"ok": False, "message": "Google OAuth עדיין לא מחובר"})
    try:
        service = build("drive", "v3", credentials=creds, cache_discovery=False)
        q = f"'{DRIVE_FOLDER_ID}' in parents and trashed = false"
        result = service.files().list(
            q=q,
            fields="files(id,name,mimeType,size,modifiedTime,webViewLink)",
            pageSize=1000,
            orderBy="name",
        ).execute()
        return {"ok": True, "files": result.get("files", [])}
    except Exception:
        return JSONResponse(
            {"ok": False, "message": "לא ניתן לקרוא את תיקיית Google Drive. בדוק הרשאה ו-FOLDER ID."},
            status_code=400,
        )

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
