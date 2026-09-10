import os, re, secrets, sqlite3, json, base64, hashlib, csv, io
from collections import deque
from pathlib import Path

from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseDownload
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


app = FastAPI(title="Unified AI Data Intelligence Lab V6 Analyze")

app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET
)

templates = Jinja2Templates(
    directory=str(Path(__file__).parent / "templates")
)


# ============================================================
# DATABASE
# ============================================================

def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row

    c.execute("""
        CREATE TABLE IF NOT EXISTS drive_sources(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id TEXT UNIQUE,
            name TEXT,
            mime_type TEXT,
            size INTEGER,
            status TEXT,
            sha256 TEXT,
            parent_id TEXT,
            path TEXT,
            is_folder INTEGER DEFAULT 0,
            modified_time TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS dataset_analysis(
            file_id TEXT PRIMARY KEY,
            name TEXT,
            analyzed_at TEXT DEFAULT CURRENT_TIMESTAMP,
            status TEXT,
            encoding TEXT,
            encoding_confidence TEXT,
            delimiter TEXT,
            delimiter_confidence TEXT,
            column_count INTEGER,
            header_detected INTEGER,
            columns_json TEXT,
            type_candidates_json TEXT,
            quality_json TEXT,
            sample_json TEXT,
            error TEXT
        )
    """)

    columns = {
        row[1]
        for row in c.execute(
            "PRAGMA table_info(drive_sources)"
        ).fetchall()
    }

    for name, definition in {
        "parent_id": "TEXT",
        "path": "TEXT",
        "is_folder": "INTEGER DEFAULT 0",
        "modified_time": "TEXT",
    }.items():
        if name not in columns:
            c.execute(
                f"ALTER TABLE drive_sources ADD COLUMN {name} {definition}"
            )

    c.commit()

    return c


# ============================================================
# ADMIN
# ============================================================

def is_admin(request: Request):
    return request.session.get("admin") is True


# ============================================================
# GOOGLE TOKEN
# ============================================================

def token_fernet():
    key = base64.urlsafe_b64encode(
        hashlib.sha256(
            SESSION_SECRET.encode("utf-8")
        ).digest()
    )
    return Fernet(key)


def encrypt_refresh_token(token: str) -> str:
    return token_fernet().encrypt(
        token.encode("utf-8")
    ).decode("ascii")


def decrypt_refresh_token(value: str):
    if not value:
        return None

    try:
        return token_fernet().decrypt(
            value.encode("ascii")
        ).decode("utf-8")

    except (InvalidToken, ValueError, TypeError):
        return None


def refresh_token_from_request(request: Request) -> str:

    if request.cookies.get(DISABLED_COOKIE) == "1":
        return ""

    return (
        decrypt_refresh_token(
            request.cookies.get(TOKEN_COOKIE, "")
        )
        or ""
    )


def browser_drive_connected(request: Request) -> bool:
    return bool(
        refresh_token_from_request(request)
    )


def credentials_from_request(request: Request):

    refresh = refresh_token_from_request(request)

    if not (
        GOOGLE_CLIENT_ID
        and GOOGLE_CLIENT_SECRET
        and refresh
    ):
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

    flow = Flow.from_client_config(
        client_config(),
        scopes=SCOPES,
        state=state
    )

    flow.redirect_uri = REDIRECT_URI

    return flow


# ============================================================
# HEALTH
# ============================================================


# V7.1: persistent Admin Review / Import Plan.
# Metadata only; raw source files remain in Google Drive.

def ensure_import_plans_table(c):
    c.execute("""
        CREATE TABLE IF NOT EXISTS import_plans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id TEXT NOT NULL,
            file_name TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'draft',
            plan_json TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    c.commit()

@app.get("/api/analysis/{file_id}")
def get_analysis(file_id: str, request: Request):
    if not is_admin(request):
        raise HTTPException(403)
    c = db()
    row = c.execute("SELECT * FROM dataset_analysis WHERE file_id=?", (file_id,)).fetchone()
    c.close()
    # Render Free has an ephemeral filesystem, so a successful Analyze from a
    # previous deployment may no longer exist in SQLite. If it is missing,
    # transparently re-run the lightweight sample-only Analyze from Google Drive.
    if not row:
        return analyze_drive_file(request=request, file_id=file_id)
    d = dict(row)
    for k in ("columns_json", "type_candidates_json", "quality_json", "sample_json"):
        if d.get(k):
            try: d[k[:-5] if k.endswith('_json') else k] = json.loads(d[k])
            except Exception: pass
    return {"ok": True, "analysis": d}

@app.get("/api/import-plan/{file_id}")
def get_import_plan(file_id: str, request: Request):
    if not is_admin(request):
        raise HTTPException(403)
    c = db(); ensure_import_plans_table(c)
    row = c.execute("SELECT id,file_id,file_name,status,plan_json,created_at,updated_at FROM import_plans WHERE file_id=? ORDER BY id DESC LIMIT 1", (file_id,)).fetchone()
    c.close()
    if not row:
        return {"ok": True, "status": "not_created", "file_id": file_id, "plan": None}
    return {"ok": True, "status": row[3], "plan_id": row[0], "file_id": row[1], "file_name": row[2], "plan": json.loads(row[4]), "created_at": row[5], "updated_at": row[6]}

@app.post("/api/import-plan")
async def save_import_plan(request: Request):
    if not is_admin(request):
        raise HTTPException(403)
    body = await request.json()
    file_id = str(body.get("file_id", "")).strip()
    file_name = str(body.get("file_name", "")).strip()
    mappings = body.get("mappings")
    if not file_id or not file_name or not isinstance(mappings, list):
        return JSONResponse({"ok": False, "error": "נדרש file_id, file_name ו-mappings"}, status_code=400)
    c = db(); ensure_import_plans_table(c)
    analysis = c.execute("SELECT file_id,name,status,encoding,delimiter,column_count,header_detected FROM dataset_analysis WHERE file_id=?", (file_id,)).fetchone()
    if not analysis:
        c.close(); return JSONResponse({"ok": False, "error": "לא נמצאה אנליזת Analyze לקובץ. יש לבצע Analyze לפני אישור."}, status_code=400)
    allowed = {"ignore","national_id","phone","email","first_name","last_name","name","address","city","location","location_detail","birth_date","birth_year","gender","relationship_status","work","facebook_id","external_numeric_id","identifier","text"}
    normalized=[]; seen=set()
    for item in mappings:
        if not isinstance(item, dict): c.close(); return JSONResponse({"ok":False,"error":"Mapping לא תקין"},status_code=400)
        try: idx=int(item.get("column_index"))
        except Exception: c.close(); return JSONResponse({"ok":False,"error":"column_index חייב להיות מספר"},status_code=400)
        meaning=str(item.get("meaning","ignore")).strip()
        if idx<1 or idx>int(analysis[5]): c.close(); return JSONResponse({"ok":False,"error":f"עמודה מחוץ לטווח: {idx}"},status_code=400)
        if idx in seen: c.close(); return JSONResponse({"ok":False,"error":f"עמודה {idx} מופיעה יותר מפעם אחת"},status_code=400)
        if meaning not in allowed: c.close(); return JSONResponse({"ok":False,"error":f"meaning לא מוכר: {meaning}"},status_code=400)
        seen.add(idx); normalized.append({"column_index":idx,"meaning":meaning,"approved":bool(item.get("approved",True)),"notes":str(item.get("notes","")).strip()})
    if len(seen) != int(analysis[5]):
        c.close(); return JSONResponse({"ok":False,"error":f"יש לאשר מיפוי לכל {int(analysis[5])} העמודות. התקבלו {len(seen)} בלבד."},status_code=400)
    plan={"version":1,"file":{"id":file_id,"name":file_name,"encoding":analysis[3],"delimiter":analysis[4],"column_count":int(analysis[5]),"header_detected":bool(analysis[6])},"mappings":normalized,"import_allowed":True,"created_by":"admin_review"}
    c.execute("INSERT INTO import_plans(file_id,file_name,status,plan_json,updated_at) VALUES(?,?,?,?,CURRENT_TIMESTAMP)",(file_id,file_name,"approved_for_import",json.dumps(plan,ensure_ascii=False)))
    c.commit(); c.close()
    return {"ok":True,"status":"approved_for_import","message":"Import Plan נשמר. עדיין לא בוצע Import.","plan":plan}

@app.get("/health")
def health():

    return {
        "ok": True,
        "version": "v7.3-save-fix",

        "drive_folder_configured":
            bool(DRIVE_FOLDER_ID),

        "oauth_client_configured":
            bool(
                GOOGLE_CLIENT_ID
                and GOOGLE_CLIENT_SECRET
            ),

        "refresh_token_configured":
            bool(GOOGLE_REFRESH_TOKEN),
    }


# ============================================================
# HOME
# ============================================================

@app.get("/", response_class=HTMLResponse)
def home(request: Request):

    c = db()

    rows = c.execute("""
        SELECT
            s.*,
            a.status AS analysis_status,
            a.analyzed_at
        FROM drive_sources s
        LEFT JOIN dataset_analysis a
            ON a.file_id = s.file_id
        ORDER BY s.id DESC
    """).fetchall()

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "request": request,
            "admin": is_admin(request),
            "rows": rows,
            "folder": DRIVE_FOLDER_ID,

            "oauth_ready":
                bool(
                    GOOGLE_CLIENT_ID
                    and GOOGLE_CLIENT_SECRET
                ),

            "drive_ready":
                browser_drive_connected(request),

            "legacy_refresh_configured":
                bool(GOOGLE_REFRESH_TOKEN),
        },
    )


# ============================================================
# ADMIN LOGIN
# ============================================================

@app.post("/login")
def login(
    request: Request,
    password: str = Form(...)
):

    if not secrets.compare_digest(
        password,
        ADMIN_PASSWORD
    ):
        raise HTTPException(
            401,
            "סיסמה שגויה"
        )

    request.session["admin"] = True

    return RedirectResponse(
        "/",
        status_code=303
    )


@app.post("/logout")
def logout(request: Request):

    request.session.clear()

    return RedirectResponse(
        "/",
        status_code=303
    )


# ============================================================
# GOOGLE OAUTH
# ============================================================

@app.get("/google/login")
def google_login(request: Request):

    if not is_admin(request):
        raise HTTPException(403)

    if not (
        GOOGLE_CLIENT_ID
        and GOOGLE_CLIENT_SECRET
    ):
        raise HTTPException(
            400,
            "GOOGLE_CLIENT_ID/GOOGLE_CLIENT_SECRET חסרים ב-Render"
        )

    flow = oauth_flow()

    code_verifier = secrets.token_urlsafe(64)

    flow.code_verifier = code_verifier

    authorization_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent",
        code_challenge_method="S256"
    )

    request.session["oauth_state"] = state

    request.session[
        "oauth_code_verifier"
    ] = code_verifier

    return RedirectResponse(
        authorization_url
    )


@app.get(
    "/oauth2callback",
    response_class=HTMLResponse
)
def oauth2callback(
    request: Request,
    code: str = "",
    state: str = ""
):

    if not code:

        return HTMLResponse(
            """
            <h2>Google OAuth failed</h2>
            <p>לא התקבל קוד הרשאה.</p>
            """,
            status_code=400
        )

    saved_state = request.session.get(
        "oauth_state"
    )

    if (
        saved_state
        and state
        and saved_state != state
    ):

        return HTMLResponse(
            "<h2>OAuth state mismatch</h2>",
            status_code=400
        )

    flow = oauth_flow(
        state=state or None
    )

    code_verifier = request.session.get(
        "oauth_code_verifier"
    )

    if not code_verifier:

        return HTMLResponse(
            """
            <h2>Google OAuth error</h2>
            <p>
            חסר code_verifier של PKCE.
            התחל התחברות מחדש.
            </p>
            """,
            status_code=400
        )

    try:

        flow.fetch_token(
            code=code,
            code_verifier=code_verifier
        )

    except Exception as e:

        import html

        return HTMLResponse(
            f"""
            <!doctype html>
            <html lang="he" dir="rtl">
            <meta charset="utf-8">

            <body style="
                font-family:Arial;
                max-width:800px;
                margin:40px auto;
                padding:20px
            ">

            <h2>Google OAuth error</h2>

            <p>
            Google דחה את החלפת קוד ההרשאה ב-token.
            </p>

            <p>
            <b>סוג שגיאה:</b>
            <code>
            {html.escape(type(e).__name__)}
            </code>
            </p>

            <p>
            <b>פרטי השגיאה:</b>
            </p>

            <pre style="
                white-space:pre-wrap;
                background:#eee;
                padding:14px;
                direction:ltr;
                text-align:left
            ">{html.escape(str(e))}</pre>

            <p>
            אל תשלח סודות או tokens.
            </p>

            </body>
            </html>
            """,
            status_code=400
        )

    creds = flow.credentials

    refresh = creds.refresh_token or ""

    if not refresh:

        return HTMLResponse(
            """
            <h2>
            Google OAuth הצליח,
            אבל Google לא החזיר Refresh Token חדש.
            </h2>

            <p>
            לחץ על חיבור מחדש ונסה שוב.
            </p>
            """,
            status_code=400
        )

    response = RedirectResponse(
        "/",
        status_code=303
    )

    response.set_cookie(
        TOKEN_COOKIE,
        encrypt_refresh_token(refresh),

        max_age=60 * 60 * 24 * 180,

        httponly=True,
        secure=True,
        samesite="lax",
        path="/",
    )

    response.delete_cookie(
        DISABLED_COOKIE,
        path="/"
    )

    request.session.pop(
        "oauth_state",
        None
    )

    request.session.pop(
        "oauth_code_verifier",
        None
    )

    request.session[
        "google_drive_connected"
    ] = True

    return response


@app.post("/google/disconnect")
def google_disconnect(request: Request):

    if not is_admin(request):
        raise HTTPException(403)

    response = RedirectResponse(
        "/",
        status_code=303
    )

    response.delete_cookie(
        TOKEN_COOKIE,
        path="/"
    )

    response.set_cookie(
        DISABLED_COOKIE,
        "1",

        max_age=60 * 60 * 24 * 365,

        httponly=True,
        secure=True,
        samesite="lax",
        path="/",
    )

    request.session.pop(
        "google_drive_connected",
        None
    )

    return response


# ============================================================
# DRIVE ERROR HELPERS
# ============================================================

def safe_drive_error(error):

    import html

    text = str(error)

    for secret in (
        GOOGLE_CLIENT_SECRET,
        GOOGLE_REFRESH_TOKEN
    ):

        if secret:
            text = text.replace(
                secret,
                "[REDACTED]"
            )

    return {
        "error_type":
            type(error).__name__,

        "error":
            html.escape(text),
    }


def drive_item_summary(item):

    return {
        "id":
            item.get("id"),

        "name":
            item.get("name"),

        "mimeType":
            item.get("mimeType"),

        "size":
            item.get("size"),

        "modifiedTime":
            item.get("modifiedTime"),

        "parents":
            item.get("parents", []),

        "driveId":
            item.get("driveId"),

        "trashed":
            item.get("trashed"),

        "shortcutDetails":
            item.get("shortcutDetails"),
    }


def drive_permissions(
    service,
    file_id
):

    try:

        response = (
            service.permissions()
            .list(
                fileId=file_id,
                fields=(
                    "permissions("
                    "id,type,emailAddress,role,"
                    "displayName,domain,"
                    "allowFileDiscovery)"
                ),
                supportsAllDrives=True,
            )
            .execute()
        )

        return {
            "ok": True,
            "permissions":
                response.get(
                    "permissions",
                    []
                ),
        }

    except Exception as e:

        return {
            "ok": False,
            **safe_drive_error(e)
        }


# ============================================================
# DRIVE DIAGNOSTICS
# ============================================================

@app.get("/api/drive/diagnostics")
def drive_diagnostics(
    request: Request
):

    if not is_admin(request):
        raise HTTPException(403)

    if not DRIVE_FOLDER_ID:

        return JSONResponse(
            {
                "ok": False,
                "message":
                    "DRIVE_FOLDER_ID חסר"
            },
            status_code=400
        )

    creds = credentials_from_request(
        request
    )

    if not creds:

        return JSONResponse(
            {
                "ok": False,
                "message":
                    "Google OAuth עדיין לא מחובר"
            },
            status_code=400
        )

    try:

        from google.auth.transport.requests import (
            Request as GoogleRequest
        )

        if not creds.valid:
            creds.refresh(
                GoogleRequest()
            )

        service = build(
            "drive",
            "v3",
            credentials=creds,
            cache_discovery=False
        )

    except Exception as e:

        return JSONResponse(
            {
                "ok": False,
                "stage":
                    "token_refresh",
                **safe_drive_error(e)
            },
            status_code=400
        )

    result = {
        "ok": True,
        "stage":
            "diagnostics",

        "credential_source":
            "encrypted_browser_cookie",

        "account": None,
        "folder": None,
        "folder_check": None,
        "folder_permissions": None,
        "folder_name_search": None,
        "parent_query": None,
        "parent_shortcuts_query": None,
        "expected_file_searches": [],
        "user_corpus_query": None,
        "shared_drive_query": None,
        "interpretation": [],
    }

    try:

        about = (
            service.about()
            .get(
                fields=
                    "user("
                    "displayName,"
                    "emailAddress,"
                    "permissionId)"
            )
            .execute()
        )

        user = about.get("user") or {}

        result["account"] = {
            "displayName":
                user.get("displayName"),

            "emailAddress":
                user.get("emailAddress"),

            "permissionId":
                user.get("permissionId"),
        }

    except Exception as e:

        result["account"] = {
            "ok": False,
            **safe_drive_error(e)
        }

    item_fields = (
        "id,name,mimeType,size,modifiedTime,"
        "webViewLink,driveId,parents,trashed,"
        "shortcutDetails("
        "targetId,targetMimeType)"
    )

    try:

        folder = (
            service.files()
            .get(
                fileId=DRIVE_FOLDER_ID,

                fields=
                    f"{item_fields},"
                    "capabilities("
                    "canListChildren)",

                supportsAllDrives=True,
            )
            .execute()
        )

        folder_drive_id = folder.get(
            "driveId"
        )

        result["folder"] = drive_item_summary(
            folder
        )

        result["folder"].update({
            "capabilities":
                folder.get(
                    "capabilities",
                    {}
                ),

            "isFolder":
                folder.get("mimeType")
                ==
                "application/vnd.google-apps.folder",

            "location":
                "shared_drive"
                if folder_drive_id
                else
                "my_drive_or_shared_folder",
        })

        result["folder_check"] = {
            "ok": True,

            "canListChildren":
                (
                    folder.get(
                        "capabilities"
                    )
                    or {}
                ).get(
                    "canListChildren"
                ),

            "driveId":
                folder_drive_id,
        }

        result["folder_permissions"] = (
            drive_permissions(
                service,
                DRIVE_FOLDER_ID
            )
        )

    except Exception as e:

        result["folder_check"] = {
            "ok": False,
            **safe_drive_error(e)
        }

        result["ok"] = False

        return JSONResponse(
            result,
            status_code=400
        )

    def run_list(label, **kwargs):

        options = {
            "spaces": "drive",

            "fields":
                f"nextPageToken,"
                f"files({item_fields})",

            "pageSize": 20,

            "includeItemsFromAllDrives":
                True,

            "supportsAllDrives":
                True,
        }

        options.update(kwargs)

        try:

            response = (
                service.files()
                .list(**options)
                .execute()
            )

            items = response.get(
                "files",
                []
            )

            return {
                "ok": True,
                "label": label,

                "options": {
                    key: value
                    for key, value
                    in options.items()
                    if key != "fields"
                },

                "count":
                    len(items),

                "hasNextPage":
                    bool(
                        response.get(
                            "nextPageToken"
                        )
                    ),

                "items":
                    [
                        drive_item_summary(item)
                        for item in items
                    ],
            }

        except Exception as e:

            return {
                "ok": False,
                "label": label,
                **safe_drive_error(e)
            }

    result["parent_query"] = run_list(
        "configured_folder_children",

        q=(
            f"'{DRIVE_FOLDER_ID}' "
            "in parents and trashed = false"
        )
    )

    result["parent_shortcuts_query"] = run_list(
        "configured_folder_shortcuts",

        q=(
            f"'{DRIVE_FOLDER_ID}' "
            "in parents and "
            "mimeType = "
            "'application/vnd.google-apps.shortcut' "
            "and trashed = false"
        )
    )

    result["folder_name_search"] = run_list(
        "folders_named_מאגרים",

        q=(
            "name = 'מאגרים' "
            "and mimeType = "
            "'application/vnd.google-apps.folder' "
            "and trashed = false"
        ),

        corpora="user"
    )

    result["folder_name_search"]["matches"] = [
        {
            "id":
                item.get("id"),

            "name":
                item.get("name"),

            "parents":
                item.get("parents", []),

            "driveId":
                item.get("driveId"),

            "mimeType":
                item.get("mimeType"),
        }

        for item
        in result[
            "folder_name_search"
        ].get(
            "items",
            []
        )
    ]

    expected_terms = [
        "AGRON2006",
        "Elector",
        "Facebook"
    ]

    for term in expected_terms:

        search = run_list(
            f"expected_name_search_{term}",

            q=(
                f"name contains '{term}' "
                "and trashed = false"
            ),

            corpora="user"
        )

        candidates = []

        for item in search.get(
            "items",
            []
        )[:20]:

            candidate = drive_item_summary(
                item
            )

            candidate["permissions"] = (
                drive_permissions(
                    service,
                    item.get("id")
                )
            )

            candidates.append(
                candidate
            )

        search["matches"] = candidates

        result[
            "expected_file_searches"
        ].append(search)

    result["user_corpus_query"] = run_list(
        "user_corpus_without_parent_filter",

        q="trashed = false",

        corpora="user"
    )

    if result["folder"].get("driveId"):

        result["shared_drive_query"] = run_list(
            "shared_drive_root_sample",

            q="trashed = false",

            corpora="drive",

            driveId=
                result["folder"]["driveId"]
        )

    else:

        result["shared_drive_query"] = {
            "ok": True,
            "skipped": True,
            "reason":
                "folder metadata has no driveId"
        }

    parent_count = (
        result["parent_query"] or {}
    ).get(
        "count",
        0
    )

    user_count = (
        result["user_corpus_query"] or {}
    ).get(
        "count",
        0
    )

    if (
        parent_count == 0
        and user_count == 0
    ):

        result["interpretation"].append(
            "The credential can read folder metadata "
            "but user-corpus listing returned no visible "
            "items in the sample."
        )

    elif (
        parent_count == 0
        and user_count > 0
    ):

        result["interpretation"].append(
            "The account can see Drive items, "
            "but none are directly children "
            "of the configured folder ID."
        )

    elif parent_count > 0:

        result["interpretation"].append(
            "The account can list direct children "
            "of the configured folder; "
            "recursive discovery can traverse them."
        )

    if result["folder"].get("driveId"):

        result["interpretation"].append(
            "The configured folder is in a Shared Drive; "
            "driveId/corpora=drive results should be checked."
        )

    else:

        result["interpretation"].append(
            "The folder metadata has no driveId; "
            "it appears to be in My Drive or a shared folder, "
            "not a Shared Drive root."
        )

    return result


# ============================================================
# DRIVE FILE DISCOVERY
# ============================================================

@app.get("/api/drive/files")
def drive_files(request: Request):

    if not is_admin(request):
        raise HTTPException(403)

    if not DRIVE_FOLDER_ID:

        return JSONResponse(
            {
                "ok": False,
                "message":
                    "DRIVE_FOLDER_ID חסר"
            },
            status_code=400
        )

    creds = credentials_from_request(
        request
    )

    if not creds:

        return JSONResponse(
            {
                "ok": False,
                "message":
                    "Google OAuth עדיין לא מחובר"
            },
            status_code=400
        )

    try:

        from google.auth.transport.requests import (
            Request as GoogleRequest
        )

        if not creds.valid:

            creds.refresh(
                GoogleRequest()
            )

    except Exception as e:

        import html

        return JSONResponse(
            {
                "ok": False,

                "stage":
                    "token_refresh",

                "error_type":
                    type(e).__name__,

                "error":
                    html.escape(str(e)),

                "message":
                    "Google הצליח לאמת את האפליקציה, "
                    "אבל לא הצלחנו לרענן את הרשאת Drive."
            },
            status_code=400
        )

    try:

        service = build(
            "drive",
            "v3",
            credentials=creds,
            cache_discovery=False
        )

        item_fields = (
            "id,name,mimeType,size,modifiedTime,"
            "webViewLink,driveId,parents,trashed"
        )

        folder = (
            service.files()
            .get(
                fileId=DRIVE_FOLDER_ID,

                fields=
                    f"{item_fields},"
                    "capabilities("
                    "canListChildren)",

                supportsAllDrives=True
            )
            .execute()
        )

        if (
            folder.get("mimeType")
            !=
            "application/vnd.google-apps.folder"
        ):

            return JSONResponse(
                {
                    "ok": False,

                    "stage":
                        "folder_check",

                    "error":
                        "not_a_folder",

                    "message":
                        "ה-FOLDER ID שהוגדר "
                        "אינו מצביע על תיקיית Google Drive.",

                    "item":
                        folder,
                },
                status_code=400
            )

        queue = deque([
            (
                DRIVE_FOLDER_ID,
                folder.get("name")
                or DRIVE_FOLDER_ID
            )
        ])

        visited = set()

        discovered_files = []
        discovered_folders = []

        c = db()

        c.execute(
            "DELETE FROM drive_sources"
        )

        while queue:

            parent_id, parent_path = (
                queue.popleft()
            )

            if parent_id in visited:
                continue

            visited.add(parent_id)

            page_token = None

            while True:

                result = (
                    service.files()
                    .list(
                        q=(
                            f"'{parent_id}' "
                            "in parents "
                            "and trashed = false"
                        ),

                        spaces="drive",

                        fields=
                            f"nextPageToken,"
                            f"files({item_fields})",

                        pageSize=1000,

                        orderBy="name_natural",

                        pageToken=page_token,

                        includeItemsFromAllDrives=True,

                        supportsAllDrives=True
                    )
                    .execute()
                )

                for item in result.get(
                    "files",
                    []
                ):

                    item_path = (
                        f"{parent_path}/"
                        f"{item.get('name', item.get('id', ''))}"
                    )

                    is_folder = (
                        item.get("mimeType")
                        ==
                        "application/vnd.google-apps.folder"
                    )

                    size = item.get("size")

                    size_value = (
                        int(size)
                        if size
                        and str(size).isdigit()
                        else None
                    )

                    c.execute(
                        """
                        INSERT OR REPLACE INTO drive_sources
                        (
                            file_id,
                            name,
                            mime_type,
                            size,
                            status,
                            sha256,
                            parent_id,
                            path,
                            is_folder,
                            modified_time
                        )
                        VALUES (?,?,?,?,?,?,?,?,?,?)
                        """,

                        (
                            item.get("id"),
                            item.get("name"),
                            item.get("mimeType"),
                            size_value,
                            "discovered",
                            None,
                            parent_id,
                            item_path,
                            1 if is_folder else 0,
                            item.get("modifiedTime"),
                        )
                    )

                    metadata = {
                        "name":
                            item.get("name"),

                        "id":
                            item.get("id"),

                        "mimeType":
                            item.get("mimeType"),

                        "size":
                            size,

                        "modifiedTime":
                            item.get("modifiedTime"),

                        "path":
                            item_path,

                        "parents":
                            item.get(
                                "parents",
                                []
                            ),

                        "webViewLink":
                            item.get(
                                "webViewLink"
                            ),

                        "driveId":
                            item.get(
                                "driveId"
                            ),
                    }

                    if is_folder:

                        discovered_folders.append(
                            metadata
                        )

                        queue.append(
                            (
                                item.get("id"),
                                item_path
                            )
                        )

                    else:

                        discovered_files.append(
                            metadata
                        )

                page_token = result.get(
                    "nextPageToken"
                )

                if not page_token:
                    break

        c.commit()
        c.close()

        return {
            "ok": True,

            "stage":
                "recursive_discovery",

            "folder": {
                "id":
                    folder.get("id"),

                "name":
                    folder.get("name"),

                "mimeType":
                    folder.get("mimeType"),

                "driveId":
                    folder.get("driveId"),

                "canListChildren":
                    (
                        folder.get(
                            "capabilities"
                        )
                        or {}
                    ).get(
                        "canListChildren"
                    ),
            },

            "count":
                len(discovered_files),

            "folder_count":
                len(discovered_folders),

            "files":
                discovered_files,

            "folders":
                discovered_folders,

            "downloaded":
                False,
        }

    except Exception as e:

        import html

        text = str(e)

        details = text

        try:

            import json as _json

            if (
                hasattr(e, "content")
                and e.content
            ):

                raw = (
                    e.content.decode(
                        "utf-8",
                        "replace"
                    )
                    if isinstance(
                        e.content,
                        (bytes, bytearray)
                    )
                    else str(e.content)
                )

                try:

                    payload = _json.loads(
                        raw
                    )

                    details = _json.dumps(
                        payload,
                        ensure_ascii=False
                    )

                except Exception:

                    details = raw

        except Exception:
            pass

        return JSONResponse(
            {
                "ok": False,

                "stage":
                    "drive_api",

                "error_type":
                    type(e).__name__,

                "error":
                    html.escape(details),

                "message":
                    "Google Drive דחה את בקשת ה-Discovery."
            },
            status_code=400
        )


# ============================================================
# ANALYZE / DRY RUN
# ============================================================

def guess_encoding(raw: bytes):
    """Conservative encoding detection; never treats a guess as certainty."""

    def score(decoded):
        if not decoded:
            return -999.0

        n = len(decoded)
        replacements = decoded.count("\ufffd")
        controls = sum(
            1 for ch in decoded
            if ord(ch) < 32 and ch not in "\r\n\t"
        )

        mojibake = sum(
            decoded.count(x)
            for x in ("Ã", "Â", "â", "ð", "×", "Ø", "Ù", "Ú", "�")
        )

        printable = sum(
            1 for ch in decoded
            if ch.isprintable() or ch in "\r\n\t"
        )

        score = printable / max(n, 1) * 100
        score -= replacements * 20
        score -= controls * 5
        score -= mojibake * 0.5

        hebrew = sum(1 for ch in decoded if "\u0590" <= ch <= "\u05FF")
        if hebrew:
            score += min(20, hebrew / max(n, 1) * 100)

        return score

    candidates = [
        ("utf-8-sig", "גבוהה"),
        ("utf-8", "גבוהה"),
        ("cp1255", "בינונית"),
        ("windows-1255", "בינונית"),
        ("iso-8859-8", "בינונית"),
        ("cp1252", "נמוכה"),
        ("latin-1", "נמוכה"),
    ]

    best = None
    for encoding, confidence in candidates:
        try:
            decoded = raw.decode(encoding, errors="strict")
        except UnicodeDecodeError:
            continue
        item = (score(decoded), encoding, confidence)
        if best is None or item[0] > best[0]:
            best = item

    if best is None:
        return "utf-8", "נמוכה"

    value, encoding, confidence = best
    if value < 70:
        confidence = "נמוכה"
    elif value < 90:
        confidence = "בינונית"

    return encoding, confidence

def detect_delimiter(lines):

    candidates = [
        "\t",
        ",",
        ";",
        "|",
        ":"
    ]

    best = None

    for delimiter in candidates:

        counts = []

        for line in lines[:100]:

            try:

                count = line.count(
                    delimiter
                )

                if count > 0:
                    counts.append(count)

            except Exception:
                pass

        if not counts:
            continue

        average = (
            sum(counts)
            / len(counts)
        )

        consistency = (
            len(set(counts))
            == 1
        )

        score = (
            average
            + (1 if consistency else 0)
        )

        if best is None or score > best[0]:

            best = (
                score,
                delimiter,
                average,
                consistency
            )

    if best is None:

        return (
            None,
            "low",
            1
        )

    _, delimiter, average, consistency = best

    confidence = (
        "strong"
        if consistency and average >= 1
        else "medium"
    )

    try:

        column_count = (
            len(
                next(
                    csv.reader(
                        [lines[0]],
                        delimiter=delimiter
                    )
                )
            )
            if lines
            else 1
        )

    except Exception:

        column_count = 1

    return (
        delimiter,
        confidence,
        column_count
    )


def parse_rows(
    lines,
    delimiter
):

    rows = []
    errors = 0

    if delimiter is None:

        for line in lines:

            rows.append([
                line
            ])

        return rows, errors

    for line in lines:

        try:

            parsed = next(
                csv.reader(
                    [line],
                    delimiter=delimiter
                )
            )

            rows.append(parsed)

        except Exception:

            errors += 1

    return rows, errors


def looks_like_header(row):

    if not row:
        return False

    alpha = 0

    for value in row:

        value = str(value).strip()

        if (
            value
            and re.search(
                r"[A-Za-zא-ת]",
                value
            )
        ):

            if not re.fullmatch(
                r"[A-Za-zא-ת\s._-]*\d[A-Za-zא-ת\s._-]*",
                value
            ):

                alpha += 1

    return alpha >= max(
        1,
        len(row) // 3
    )


def normalize_header(
    value,
    index
):

    value = str(
        value or ""
    ).strip()

    value = value.strip(
        '"'
    ).strip(
        "'"
    )

    if value:
        return value

    return f"column_{index + 1}"


def infer_field_type(values):

    vals = [
        str(v).strip()
        for v in values
        if str(v).strip()
    ]

    if not vals:
        return "empty"

    digit_like = sum(
        bool(
            re.fullmatch(
                r"\+?\d[\d\s().-]{5,}",
                v
            )
        )
        for v in vals
    ) / len(vals)

    email_like = sum(
        bool(
            re.fullmatch(
                r"[^@\s]+@[^@\s]+\.[^@\s]+",
                v
            )
        )
        for v in vals
    ) / len(vals)

    date_like = sum(
        bool(
            re.fullmatch(
                r"\d{1,4}[-/.]\d{1,2}[-/.]\d{1,4}",
                v
            )
        )
        for v in vals
    ) / len(vals)

    numeric = 0

    for v in vals:

        try:

            float(
                v.replace(",", "")
            )

            numeric += 1

        except ValueError:
            pass

    if email_like >= 0.7:
        return "email_candidate"

    if digit_like >= 0.7:
        return "phone_or_numeric_candidate"

    if date_like >= 0.7:
        return "date_candidate"

    if (
        numeric / len(vals)
        >= 0.9
    ):
        return "numeric"

    if (
        sum(
            bool(
                re.fullmatch(
                    r"\d{7,10}",
                    v
                )
            )
            for v in vals
        )
        / len(vals)
        >= 0.7
    ):
        return "identifier_candidate"

    return "text"


def semantic_candidates(
    name,
    values
):

    target = (
        f"{name.lower().strip()} "
        f"{name.strip()}"
    )

    candidates = []

    patterns = [

        (
            r"(id|ת.?ז|זהות|national.?id|identity)",
            "national_id",
            "strong"
        ),

        (
            r"(phone|mobile|טלפון|נייד|פלאפון)",
            "phone",
            "strong"
        ),

        (
            r"(email|e.?mail|דוא.?ל|מייל)",
            "email",
            "strong"
        ),

        (
            r"(name|שם|full.?name|שם.?מלא)",
            "name",
            "medium"
        ),

        (
            r"(address|כתובת|רחוב)",
            "address",
            "medium"
        ),

        (
            r"(city|עיר|יישוב|ישוב)",
            "city",
            "medium"
        ),

        (
            r"(birth|לידה|תאריך.?לידה|birthdate)",
            "birthdate",
            "medium"
        ),

        (
            r"(facebook|fb)",
            "facebook_id",
            "medium"
        ),

        (
            r"(gender|מין|מגדר)",
            "gender",
            "medium"
        ),
    ]

    for pattern, meaning, confidence in patterns:

        if re.search(
            pattern,
            target,
            re.I
        ):

            candidates.append({
                "meaning":
                    meaning,

                "confidence":
                    confidence
            })

    if not candidates:

        typ = infer_field_type(
            values
        )

        if typ == "email_candidate":

            candidates.append({
                "meaning":
                    "email",

                "confidence":
                    "medium"
            })

        elif typ == "phone_or_numeric_candidate":

            candidates.append({
                "meaning":
                    "phone_or_numeric",

                "confidence":
                    "low"
            })

        elif typ == "identifier_candidate":

            candidates.append({
                "meaning":
                    "identifier",

                "confidence":
                    "low"
            })

    return candidates


def positional_semantic_candidates(
    position,
    vals
):
    """
    הצעת מיפוי סמנטי עבור Dataset ללא Header.

    חשוב מאוד:
    אלה הצעות בלבד.
    הן אינן הופכות את הנתון לעובדה מאומתת,
    ואסור לבצע לפיהן Merge אוטומטי ללא אישור Admin.
    """

    values = [
        str(v).strip()
        for v in (vals or [])
        if v is not None
        and str(v).strip()
    ]

    if not values:
        return []

    sample = values[:200]

    def looks_like_phone_or_numeric_id(v):

        digits = re.sub(
            r"\D",
            "",
            v
        )

        if not digits:
            return False

        return len(digits) in (
            9,
            10,
            11,
            12,
            13,
            14,
            15
        )

    def looks_like_email(v):

        return bool(
            re.match(
                r"^[^@\s]+@[^@\s]+\.[^@\s]+$",
                v
            )
        )

    def looks_like_year(v):

        return bool(
            re.match(
                r"^(19|20)\d{2}$",
                v
            )
        )

    def looks_like_date(v):

        return bool(
            re.match(
                r"^\d{1,2}[/-]\d{1,2}([/-]\d{2,4})?$",
                v
            )
        )

    def looks_like_gender(v):

        normalized = v.lower().strip()

        return normalized in {
            "male",
            "female",
            "m",
            "f",
            "man",
            "woman",
            "זכר",
            "נקבה",
            "גבר",
            "אישה",
        }

    def looks_like_location(v):

        if "," in v:
            return True

        location_words = [
            "israel",
            "russia",
            "usa",
            "united states",
            "uk",
            "canada",
            "ישראל",
            "רוסיה",
            "ארה״ב",
            "ארהב",
        ]

        normalized = v.lower()

        return any(
            word in normalized
            for word in location_words
        )

    email_ratio = sum(
        looks_like_email(v)
        for v in sample
    ) / max(
        len(sample),
        1
    )

    phone_ratio = sum(
        looks_like_phone_or_numeric_id(v)
        for v in sample
    ) / max(
        len(sample),
        1
    )

    year_ratio = sum(
        looks_like_year(v)
        for v in sample
    ) / max(
        len(sample),
        1
    )

    date_ratio = sum(
        looks_like_date(v)
        for v in sample
    ) / max(
        len(sample),
        1
    )

    gender_ratio = sum(
        looks_like_gender(v)
        for v in sample
    ) / max(
        len(sample),
        1
    )

    location_ratio = sum(
        looks_like_location(v)
        for v in sample
    ) / max(
        len(sample),
        1
    )

    positional_map = {

        1: [
            {
                "meaning":
                    "phone",

                "confidence":
                    "medium",

                "reason":
                    "Column contains phone-like numeric values",
            },

            {
                "meaning":
                    "facebook_phone",

                "confidence":
                    "low",

                "reason":
                    "Could represent a Facebook-associated phone value",
            },
        ],

        2: [
            {
                "meaning":
                    "facebook_id",

                "confidence":
                    "medium",

                "reason":
                    "Column contains numeric identifier-like values",
            },
        ],

        3: [
            {
                "meaning":
                    "first_name",

                "confidence":
                    "medium",

                "reason":
                    "Column contains short person-name-like text",
            },
        ],

        4: [
            {
                "meaning":
                    "last_name",

                "confidence":
                    "medium",

                "reason":
                    "Column contains short person-name-like text",
            },
        ],

        5: [
            {
                "meaning":
                    "gender",

                "confidence":
                    (
                        "high"
                        if gender_ratio >= 0.80
                        else "medium"
                    ),

                "reason":
                    "Values match common gender labels",
            },
        ],

        6: [
            {
                "meaning":
                    "location",

                "confidence":
                    "medium",

                "reason":
                    "Values look like geographic locations",
            },
        ],

        7: [
            {
                "meaning":
                    "location_detail",

                "confidence":
                    "low",

                "reason":
                    "Values look like secondary geographic information",
            },
        ],

        8: [
            {
                "meaning":
                    "relationship_status",

                "confidence":
                    "medium",

                "reason":
                    "Values look like relationship-status text",
            },
        ],

        9: [
            {
                "meaning":
                    "work",

                "confidence":
                    "medium",

                "reason":
                    "Values contain free-form occupation/work descriptions",
            },
        ],

        10: [
            {
                "meaning":
                    "birth_year",

                "confidence":
                    (
                        "high"
                        if year_ratio >= 0.80
                        else "medium"
                    ),

                "reason":
                    "Values predominantly look like four-digit years",
            },
        ],

        11: [
            {
                "meaning":
                    "email",

                "confidence":
                    (
                        "high"
                        if email_ratio >= 0.80
                        else "medium"
                    ),

                "reason":
                    "Values predominantly match email syntax",
            },
        ],

        12: [
            {
                "meaning":
                    "birth_date",

                "confidence":
                    (
                        "high"
                        if date_ratio >= 0.80
                        else "medium"
                    ),

                "reason":
                    "Values predominantly match date syntax",
            },
        ],
    }

    candidates = positional_map.get(
        position,
        []
    )

    filtered = []

    for candidate in candidates:

        field = candidate["meaning"]

        if field == "email":

            if email_ratio >= 0.50:
                filtered.append(candidate)

        elif field == "birth_year":

            if year_ratio >= 0.50:
                filtered.append(candidate)

        elif field == "birth_date":

            if date_ratio >= 0.30:
                filtered.append(candidate)

        elif field == "gender":

            if gender_ratio >= 0.30:
                filtered.append(candidate)

        elif field in (
            "location",
            "location_detail"
        ):

            if location_ratio >= 0.20:
                filtered.append(candidate)

        elif field in (
            "phone",
            "facebook_phone"
        ):

            if phone_ratio >= 0.50:
                filtered.append(candidate)

        else:

            filtered.append(candidate)

    return filtered


def analyze_sample_bytes(
    raw,
    total_size
):

    encoding, enc_conf = guess_encoding(
        raw
    )

    text = raw.decode(
        encoding,
        errors="replace"
    )

    lines = (
        text
        .replace("\r\n", "\n")
        .replace("\r", "\n")
        .split("\n")
    )

    nonempty = [
        x
        for x in lines
        if x.strip()
    ]

    delimiter, delim_conf, column_count = (
        detect_delimiter(
            nonempty
        )
    )

    rows, parse_errors = parse_rows(
        nonempty[:200],
        delimiter
    )

    if not rows:

        raise ValueError(
            "לא נמצאו שורות נתונים בדגימה"
        )

    header = (
        rows[0]
        if looks_like_header(rows[0])
        else None
    )

    data_rows = (
        rows[1:]
        if header
        else rows
    )

    width = len(
        header or rows[0]
    )

    names = (
        [
            normalize_header(
                value,
                index
            )
            for index, value
            in enumerate(header)
        ]
        if header
        else
        [
            f"column_{i + 1}"
            for i in range(width)
        ]
    )

    columns = []

    for i, name in enumerate(names):

        vals = [
            r[i]
            if i < len(r)
            else ""
            for r in data_rows[:100]
        ]

        columns.append({

            "index":
                i + 1,

            "name":
                name,

            "inferred_type":
                infer_field_type(vals),

            "semantic_candidates":
                (
                    semantic_candidates(
                        name,
                        vals
                    )
                    or
                    positional_semantic_candidates(
                        i + 1,
                        vals
                    )
                ),

            "non_empty_sample_count":
                sum(
                    bool(
                        str(v).strip()
                    )
                    for v in vals
                ),

            "examples":
                [
                    str(v)[:120]
                    for v in vals
                    if str(v).strip()
                ][:3],
        })

    widths = [
        len(r)
        for r in rows
    ]

    anomalies = sum(
        1
        for w in widths
        if w != width
    )

    avg_line = (
        sum(
            len(
                x.encode("utf-8")
            )
            for x in nonempty[:100]
        )
        /
        max(
            1,
            min(
                100,
                len(nonempty)
            )
        )
    )

    estimated_rows = (
        int(
            total_size / avg_line
        )
        if total_size
        and avg_line > 0
        else None
    )

    requires_admin_review = any(
        c["semantic_candidates"]
        and
        c["semantic_candidates"][0]["confidence"]
        == "low"
        for c in columns
    )

    return {

        "status":
            "analyzed",

        "encoding":
            encoding,

        "encoding_confidence":
            enc_conf,

        "delimiter":
            delimiter or "NONE",

        "delimiter_confidence":
            delim_conf,

        "column_count":
            width,

        "header_detected":
            bool(header),

        "columns":
            columns,

        "quality": {

            "sample_lines":
                len(nonempty),

            "sample_rows_parsed":
                len(rows),

            "parse_errors":
                parse_errors,

            "row_length_anomalies_in_sample":
                anomalies,

            "estimated_total_rows":
                estimated_rows,

            "estimate_note":
                "הערכת כמות רשומות לפי גודל הקובץ "
                "ואורך שורה ממוצע; אינה ספירה מדויקת.",
        },

        "sample": {

            "header":
                [
                    str(x)[:120]
                    for x in header
                ]
                if header
                else None,

            "rows":
                [
                    [
                        str(v)[:120]
                        for v in r
                    ]
                    for r in data_rows[:5]
                ],
        },

        "requires_admin_review":
            requires_admin_review,
    }


# ============================================================
# ANALYZE DRIVE FILE
# ============================================================

@app.get("/api/drive/analyze/{file_id}")
def analyze_drive_file(
    request: Request,
    file_id: str
):

    if not is_admin(request):
        raise HTTPException(403)

    if not re.fullmatch(
        r"[-\w]{10,}",
        file_id
    ):

        raise HTTPException(
            400,
            "file_id לא תקין"
        )

    creds = credentials_from_request(
        request
    )

    if not creds:

        return JSONResponse(
            {
                "ok": False,
                "message":
                    "Google OAuth עדיין לא מחובר"
            },
            status_code=400
        )

    try:

        from google.auth.transport.requests import (
            Request as GoogleRequest
        )

        if not creds.valid:

            creds.refresh(
                GoogleRequest()
            )

        service = build(
            "drive",
            "v3",
            credentials=creds,
            cache_discovery=False
        )

        meta = (
            service.files()
            .get(
                fileId=file_id,

                fields=
                    "id,name,mimeType,"
                    "size,modifiedTime",

                supportsAllDrives=True
            )
            .execute()
        )

        if (
            meta.get("mimeType")
            ==
            "application/vnd.google-apps.folder"
        ):

            return JSONResponse(
                {
                    "ok": False,
                    "message":
                        "אי אפשר לנתח תיקייה"
                },
                status_code=400
            )

        filename = str(
            meta.get("name", "")
        ).lower()

        allowed_extensions = (
            ".txt",
            ".csv",
            ".tsv",
            ".jsonl"
        )

        if (
            meta.get("mimeType")
            != "text/plain"
            and not filename.endswith(
                allowed_extensions
            )
        ):

            return JSONResponse(
                {
                    "ok": False,

                    "message":
                        "בשלב זה Analyze תומך "
                        "ב-TXT/CSV/TSV/JSONL"
                },
                status_code=400
            )

        # ====================================================
        # IMPORTANT:
        # We intentionally download only a small prefix.
        # The whole dataset is NOT downloaded.
        # ====================================================

        request_media = (
            service.files()
            .get_media(
                fileId=file_id,
                acknowledgeAbuse=False
            )
        )

        buf = io.BytesIO()

        downloader = MediaIoBaseDownload(
            buf,
            request_media,
            chunksize=1024 * 1024
        )

        done = False

        MAX_SAMPLE_BYTES = 4 * 1024 * 1024

        while (
            not done
            and buf.tell()
            < MAX_SAMPLE_BYTES
        ):

            status, done = (
                downloader.next_chunk()
            )

        raw = buf.getvalue()

        if not raw:

            raise ValueError(
                "Google Drive לא החזיר "
                "תוכן לדגימה"
            )

        result = analyze_sample_bytes(
            raw,

            int(
                meta.get("size")
            )
            if meta.get("size")
            else None
        )

        result.update({

            "ok":
                True,

            "file": {

                "id":
                    meta.get("id"),

                "name":
                    meta.get("name"),

                "mimeType":
                    meta.get("mimeType"),

                "size":
                    meta.get("size"),

                "modifiedTime":
                    meta.get("modifiedTime"),
            },

            "sample_bytes_read":
                len(raw),

            "sample_limit_bytes":
                MAX_SAMPLE_BYTES,

            "full_file_downloaded":
                False,

            "message":
                "נותחה דגימה בלבד. "
                "הקובץ המלא לא הורד.",
        })

        c = db()

        c.execute(
            """
            INSERT OR REPLACE INTO dataset_analysis
            (
                file_id,
                name,
                status,
                encoding,
                encoding_confidence,
                delimiter,
                delimiter_confidence,
                column_count,
                header_detected,
                columns_json,
                type_candidates_json,
                quality_json,
                sample_json,
                error
            )
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,

            (
                file_id,

                meta.get("name"),

                result["status"],

                result["encoding"],

                result[
                    "encoding_confidence"
                ],

                result["delimiter"],

                result[
                    "delimiter_confidence"
                ],

                result[
                    "column_count"
                ],

                1
                if result[
                    "header_detected"
                ]
                else 0,

                json.dumps(
                    result["columns"],
                    ensure_ascii=False
                ),

                json.dumps(
                    [
                        c["semantic_candidates"]
                        for c in result["columns"]
                    ],
                    ensure_ascii=False
                ),

                json.dumps(
                    result["quality"],
                    ensure_ascii=False
                ),

                json.dumps(
                    result["sample"],
                    ensure_ascii=False
                ),

                None
            )
        )

        c.execute(
            """
            UPDATE drive_sources
            SET status=?
            WHERE file_id=?
            """,
            (
                "analyzed",
                file_id
            )
        )

        c.commit()
        c.close()

        return result

    except Exception as e:

        import html

        text = html.escape(
            str(e)
        )

        c = db()

        c.execute(
            """
            INSERT OR REPLACE INTO dataset_analysis
            (
                file_id,
                name,
                status,
                error
            )
            VALUES (?,?,?,?)
            """,
            (
                file_id,
                "",
                "error",
                text
            )
        )

        c.commit()
        c.close()

        return JSONResponse(
            {
                "ok": False,

                "stage":
                    "analyze",

                "error_type":
                    type(e).__name__,

                "error":
                    text,

                "full_file_downloaded":
                    False,
            },
            status_code=400
        )


# ============================================================
# STATUS
# ============================================================

@app.get("/api/status")
def status(request: Request):

    if not is_admin(request):
        raise HTTPException(403)

    c = db()

    rows = c.execute(
        """
        SELECT
            s.*,
            a.status AS analysis_status,
            a.analyzed_at
        FROM drive_sources s
        LEFT JOIN dataset_analysis a
            ON a.file_id = s.file_id
        ORDER BY s.id DESC
        """
    ).fetchall()

    analyses = c.execute("SELECT file_id,name,status,analyzed_at,encoding,delimiter,column_count,header_detected,quality_json FROM dataset_analysis ORDER BY analyzed_at DESC").fetchall()
    analysis_list=[]
    for a in analyses:
        x=dict(a)
        if x.get("quality_json"):
            try: x["quality"]=json.loads(x["quality_json"])
            except Exception: pass
        analysis_list.append(x)

    return {

        "analyses": analysis_list,

        "drive_folder_id":
            DRIVE_FOLDER_ID or None,

        "oauth_client_configured":
            bool(
                GOOGLE_CLIENT_ID
                and GOOGLE_CLIENT_SECRET
            ),

        "refresh_token_configured":
            bool(GOOGLE_REFRESH_TOKEN),

        "sources":
            [
                dict(x)
                for x in rows
            ],
    }


# ============================================================
# SEARCH
# ============================================================

@app.get("/api/search")
def search(
    request: Request,
    q: str = ""
):

    if not is_admin(request):
        raise HTTPException(403)

    # ZERO-HALLUCINATION RULE:
    # Until real record-level indexing exists,
    # never pretend that metadata is an actual
    # database search result.

    return {
        "status":
            "לא נמצא",

        "results":
            []
    }