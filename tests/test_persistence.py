import os
import tempfile
from pathlib import Path

os.environ.pop("DATABASE_URL", None)
os.environ["APP_ENV"] = "development"
os.environ["DATA_DIR"] = tempfile.mkdtemp(prefix="lab-db-")

from app.db import get_db, metadata_status

c = get_db()
expected = {
    "datasets", "drive_sources", "dataset_analysis", "schema_versions",
    "import_plans", "import_jobs", "checkpoints", "raw_objects",
    "raw_records_metadata", "provenance", "conflicts", "import_history",
    "audit_events", "schema_migrations",
}
actual = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
missing = expected - actual
assert not missing, missing
c.execute("INSERT INTO datasets(source_file_id,source_file_name,source_modified_time,source_size_bytes) VALUES(?,?,?,?)", ("test-file", "test.txt", "2026-01-01T00:00:00Z", 10))
c.commit()
assert c.execute("SELECT source_file_name FROM datasets WHERE source_file_id=?", ("test-file",)).fetchone()[0] == "test.txt"
c.execute("INSERT INTO dataset_analysis(file_id,analysis_version,name,status,source_modified_time,source_size_bytes) VALUES(?,?,?,?,?,?)", ("test-file", 1, "test.txt", "analyzed", "2026-01-01T00:00:00Z", 10))
c.execute("INSERT INTO import_plans(file_id,file_name,plan_version,status,plan_json,source_modified_time,source_size_bytes) VALUES(?,?,?,?,?,?,?)", ("test-file", "test.txt", 1, "approved_for_import", "{}", "2026-01-01T00:00:00Z", 10))
c.commit()
assert c.execute("SELECT plan_version FROM import_plans WHERE file_id=?", ("test-file",)).fetchone()[0] == 1
c.close()
assert metadata_status()["backend"] == "sqlite_development_fallback"
print("local persistence adapter: PASS")
