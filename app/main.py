
import os, sqlite3, hashlib, csv, io, json, re, secrets
from pathlib import Path
from fastapi import FastAPI, UploadFile, File, Form, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

DATA_DIR = Path(os.getenv("DATA_DIR", "/tmp/unified_data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB = DATA_DIR / "lab.db"
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "change-me-now")
app = FastAPI(title="Unified AI Data Intelligence Lab")
app.add_middleware(SessionMiddleware, secret_key=os.getenv("SESSION_SECRET", secrets.token_hex(32)))
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    c.execute("""CREATE TABLE IF NOT EXISTS datasets(
        id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, filename TEXT, size INTEGER,
        sha256 TEXT, status TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP)""")
    c.execute("""CREATE TABLE IF NOT EXISTS records(
        id INTEGER PRIMARY KEY AUTOINCREMENT, dataset_id INTEGER, row_no INTEGER,
        raw_json TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS fields(
        dataset_id INTEGER, name TEXT, normalized TEXT, sample TEXT, count INTEGER,
        PRIMARY KEY(dataset_id,name))""")
    c.commit()
    return c

def norm(s):
    return re.sub(r'[^0-9a-zא-ת]+', '', str(s or '').lower())

def is_admin(request):
    return request.session.get("admin") is True

@app.get("/health")
def health():
    return {"ok": True, "service": "unified-ai-data-lab"}

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    c = db()
    datasets = c.execute("SELECT * FROM datasets ORDER BY id DESC").fetchall()
    return templates.TemplateResponse("index.html", {"request": request, "datasets": datasets, "admin": is_admin(request)})

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

@app.post("/upload")
async def upload(request: Request, file: UploadFile = File(...)):
    if not is_admin(request):
        raise HTTPException(403, "נדרשת הרשאת Admin")
    name = file.filename or "unknown"
    h = hashlib.sha256()
    total = 0
    # Prototype intentionally streams to disk instead of reading the whole file into RAM.
    safe = re.sub(r'[^A-Za-z0-9._-]+', '_', name)
    target = DATA_DIR / f"{secrets.token_hex(8)}_{safe}"
    with open(target, "wb") as out:
        while True:
            chunk = await file.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk); total += len(chunk); out.write(chunk)

    c = db()
    cur = c.execute("INSERT INTO datasets(name,filename,size,sha256,status) VALUES(?,?,?,?,?)",
                    (name, name, total, h.hexdigest(), "uploaded"))
    dataset_id = cur.lastrowid

    # Parse common delimited text formats conservatively.
    fields = {}
    try:
        with open(target, "rb") as f:
            sample = f.read(1024 * 1024)
        text = sample.decode("utf-8-sig", errors="replace")
        dialect = csv.Sniffer().sniff(text[:100000], delimiters=",\t;|")
        reader = csv.reader(io.StringIO(text), dialect)
        header = next(reader, [])
        if header:
            for row in reader:
                for i, val in enumerate(row[:len(header)]):
                    k = header[i].strip() or f"column_{i+1}"
                    rec = fields.setdefault(k, {"sample": val[:200], "count": 0})
                    rec["count"] += 1
                if sum(x["count"] for x in fields.values()) > 50000:
                    break
            for k,v in fields.items():
                c.execute("INSERT OR REPLACE INTO fields(dataset_id,name,normalized,sample,count) VALUES(?,?,?,?,?)",
                          (dataset_id,k,norm(k),v["sample"],v["count"]))
            c.execute("UPDATE datasets SET status=? WHERE id=?", ("schema_detected", dataset_id))
        else:
            c.execute("UPDATE datasets SET status=? WHERE id=?", ("no_header_detected", dataset_id))
    except Exception as e:
        c.execute("UPDATE datasets SET status=? WHERE id=?", ("stored_not_parsed", dataset_id))
    c.commit()
    return RedirectResponse("/", status_code=303)

@app.get("/api/search")
def search(request: Request, q: str = ""):
    if not is_admin(request):
        raise HTTPException(403, "נדרשת הרשאת Admin")
    q = q.strip()
    if not q:
        return {"status":"לא נמצא","results":[]}
    c = db()
    ds = c.execute("SELECT * FROM datasets ORDER BY id DESC").fetchall()
    results=[]
    nq=norm(q)
    for d in ds:
        fields = c.execute("SELECT * FROM fields WHERE dataset_id=?", (d["id"],)).fetchall()
        for f in fields:
            if nq in f["normalized"] or nq in norm(f["sample"]):
                results.append({
                    "dataset": d["name"], "field": f["name"],
                    "sample": f["sample"], "count": f["count"],
                    "source": "stored dataset metadata"
                })
    return {"status":"נמצא" if results else "לא נמצא", "results":results[:100]}

@app.get("/api/datasets")
def datasets(request: Request):
    if not is_admin(request):
        raise HTTPException(403)
    c=db()
    return {"datasets":[dict(x) for x in c.execute("SELECT * FROM datasets ORDER BY id DESC").fetchall()]}

