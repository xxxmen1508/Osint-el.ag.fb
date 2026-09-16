ALTER TABLE raw_records_metadata ADD COLUMN IF NOT EXISTS raw_values_json TEXT;
ALTER TABLE raw_records_metadata ADD COLUMN IF NOT EXISTS normalized_values_json TEXT;
ALTER TABLE raw_records_metadata ADD COLUMN IF NOT EXISTS source_file_id TEXT;
ALTER TABLE raw_records_metadata ADD COLUMN IF NOT EXISTS import_job_id BIGINT;
ALTER TABLE raw_records_metadata ADD COLUMN IF NOT EXISTS error_json TEXT;
ALTER TABLE import_jobs ADD COLUMN IF NOT EXISTS full_file_downloaded BOOLEAN NOT NULL DEFAULT FALSE;
CREATE INDEX IF NOT EXISTS idx_raw_records_job_row ON raw_records_metadata(job_id, row_number);
CREATE INDEX IF NOT EXISTS idx_import_jobs_sample_identity ON import_jobs(job_type, source_file_id, import_plan_id, source_modified_time, source_size_bytes);
