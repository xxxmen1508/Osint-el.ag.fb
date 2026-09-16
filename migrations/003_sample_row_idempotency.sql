CREATE UNIQUE INDEX IF NOT EXISTS uq_raw_records_sample_job_row ON raw_records_metadata(job_id, row_number);

CREATE INDEX IF NOT EXISTS idx_import_jobs_sample_pending ON import_jobs(job_type, status, created_at);
