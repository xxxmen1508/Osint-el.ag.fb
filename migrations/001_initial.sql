CREATE TABLE IF NOT EXISTS datasets (
    id BIGSERIAL PRIMARY KEY,
    source_file_id TEXT NOT NULL,
    source_file_name TEXT NOT NULL,
    source_modified_time TEXT,
    source_size_bytes BIGINT,
    dataset_version INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'discovered',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(source_file_id, dataset_version)
);

CREATE TABLE IF NOT EXISTS drive_sources (
    id BIGSERIAL PRIMARY KEY,
    file_id TEXT NOT NULL,
    name TEXT,
    mime_type TEXT,
    size BIGINT,
    status TEXT,
    sha256 TEXT,
    parent_id TEXT,
    path TEXT,
    is_folder BOOLEAN NOT NULL DEFAULT FALSE,
    modified_time TEXT,
    dataset_id BIGINT REFERENCES datasets(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(file_id, modified_time)
);

CREATE TABLE IF NOT EXISTS dataset_analysis (
    id BIGSERIAL PRIMARY KEY,
    file_id TEXT NOT NULL,
    dataset_id BIGINT REFERENCES datasets(id),
    analysis_version INTEGER NOT NULL DEFAULT 1,
    name TEXT,
    analyzed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    status TEXT,
    encoding TEXT,
    encoding_confidence TEXT,
    delimiter TEXT,
    delimiter_confidence TEXT,
    column_count INTEGER,
    header_detected BOOLEAN,
    columns_json TEXT,
    type_candidates_json TEXT,
    quality_json TEXT,
    sample_json TEXT,
    source_modified_time TEXT,
    source_size_bytes BIGINT,
    analyzer_version TEXT,
    error TEXT,
    UNIQUE(file_id, analysis_version)
);

CREATE TABLE IF NOT EXISTS schema_versions (
    id BIGSERIAL PRIMARY KEY,
    dataset_id BIGINT REFERENCES datasets(id),
    version_number INTEGER NOT NULL,
    schema_json TEXT NOT NULL,
    mapping_json TEXT,
    created_by TEXT NOT NULL DEFAULT 'admin_review',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    UNIQUE(dataset_id, version_number)
);

CREATE TABLE IF NOT EXISTS import_plans (
    id BIGSERIAL PRIMARY KEY,
    dataset_id BIGINT REFERENCES datasets(id),
    file_id TEXT NOT NULL,
    file_name TEXT NOT NULL,
    schema_version_id BIGINT REFERENCES schema_versions(id),
    analysis_id BIGINT REFERENCES dataset_analysis(id),
    plan_version INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'draft',
    plan_json TEXT NOT NULL,
    source_modified_time TEXT,
    source_size_bytes BIGINT,
    approved_by TEXT,
    approved_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(file_id, plan_version)
);

CREATE TABLE IF NOT EXISTS import_jobs (
    id BIGSERIAL PRIMARY KEY,
    dataset_id BIGINT REFERENCES datasets(id),
    import_plan_id BIGINT REFERENCES import_plans(id),
    job_type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued',
    requested_by TEXT,
    source_file_id TEXT,
    source_modified_time TEXT,
    source_size_bytes BIGINT,
    rows_read BIGINT NOT NULL DEFAULT 0,
    rows_written BIGINT NOT NULL DEFAULT 0,
    rows_failed BIGINT NOT NULL DEFAULT 0,
    bytes_read BIGINT NOT NULL DEFAULT 0,
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS raw_objects (
    id BIGSERIAL PRIMARY KEY,
    job_id BIGINT REFERENCES import_jobs(id),
    dataset_id BIGINT REFERENCES datasets(id),
    object_key TEXT NOT NULL,
    object_version TEXT,
    content_type TEXT,
    compression TEXT,
    size_bytes BIGINT,
    sha256 TEXT,
    etag TEXT,
    first_row_number BIGINT,
    last_row_number BIGINT,
    source_byte_start BIGINT,
    source_byte_end BIGINT,
    status TEXT NOT NULL DEFAULT 'planned',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(job_id, object_key)
);

CREATE TABLE IF NOT EXISTS checkpoints (
    id BIGSERIAL PRIMARY KEY,
    job_id BIGINT NOT NULL REFERENCES import_jobs(id),
    source_file_id TEXT NOT NULL,
    source_byte_offset BIGINT NOT NULL DEFAULT 0,
    source_line_number BIGINT NOT NULL DEFAULT 0,
    chunk_number BIGINT NOT NULL DEFAULT 0,
    raw_object_key TEXT,
    raw_object_etag TEXT,
    rows_processed BIGINT NOT NULL DEFAULT 0,
    rows_failed BIGINT NOT NULL DEFAULT 0,
    rolling_hash TEXT,
    parser_state_json TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(job_id, chunk_number)
);

CREATE TABLE IF NOT EXISTS raw_records_metadata (
    id BIGSERIAL PRIMARY KEY,
    dataset_id BIGINT REFERENCES datasets(id),
    job_id BIGINT REFERENCES import_jobs(id),
    raw_object_id BIGINT REFERENCES raw_objects(id),
    row_number BIGINT NOT NULL,
    source_byte_offset BIGINT,
    record_hash TEXT,
    record_status TEXT,
    parse_status TEXT,
    provenance_id BIGINT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS provenance (
    id BIGSERIAL PRIMARY KEY,
    dataset_id BIGINT REFERENCES datasets(id),
    job_id BIGINT REFERENCES import_jobs(id),
    raw_object_id BIGINT REFERENCES raw_objects(id),
    source_file_id TEXT NOT NULL,
    source_row_number BIGINT,
    source_byte_offset BIGINT,
    source_column_index INTEGER,
    source_column_name TEXT,
    original_value_hash TEXT,
    transformation_json TEXT,
    parser_version TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS conflicts (
    id BIGSERIAL PRIMARY KEY,
    dataset_id BIGINT REFERENCES datasets(id),
    job_id BIGINT REFERENCES import_jobs(id),
    record_reference TEXT,
    conflict_type TEXT NOT NULL,
    field_name TEXT,
    left_value_reference TEXT,
    right_value_reference TEXT,
    reason TEXT,
    severity TEXT,
    status TEXT NOT NULL DEFAULT 'open',
    resolved_by TEXT,
    resolution_json TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS import_history (
    id BIGSERIAL PRIMARY KEY,
    dataset_id BIGINT REFERENCES datasets(id),
    job_id BIGINT REFERENCES import_jobs(id),
    event_type TEXT NOT NULL,
    event_payload_json TEXT,
    actor TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_events (
    id BIGSERIAL PRIMARY KEY,
    actor_type TEXT,
    actor_id TEXT,
    action TEXT NOT NULL,
    entity_type TEXT,
    entity_id TEXT,
    request_id TEXT,
    details_json TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_drive_sources_file_id ON drive_sources(file_id);
CREATE INDEX IF NOT EXISTS idx_dataset_analysis_file_id ON dataset_analysis(file_id);
CREATE INDEX IF NOT EXISTS idx_import_plans_file_id ON import_plans(file_id);
CREATE INDEX IF NOT EXISTS idx_checkpoints_job_id ON checkpoints(job_id);
CREATE INDEX IF NOT EXISTS idx_provenance_source ON provenance(source_file_id, source_row_number);
CREATE INDEX IF NOT EXISTS idx_audit_events_created_at ON audit_events(created_at);
