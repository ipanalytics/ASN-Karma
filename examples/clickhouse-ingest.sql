CREATE TABLE asn_karma
(
    asn UInt32,
    asn_name String,
    country LowCardinality(String),
    risk_score UInt8,
    risk_level LowCardinality(String),
    confidence_score UInt8,
    confidence LowCardinality(String),
    recommended_action LowCardinality(String),
    observed_records UInt64,
    unique_observed_cidrs UInt64,
    source_count UInt32,
    active_days_30d UInt8,
    trend LowCardinality(String),
    evidence_delta_1d Int64,
    expanded_prefix_count UInt64,
    built_at DateTime
)
ENGINE = MergeTree
ORDER BY (built_at, risk_level, asn);

-- Example load:
-- curl -fsSL https://github.com/ipanalytics/ASN-Karma/releases/latest/download/asn-risk.jsonl \
--   | clickhouse-client --query "INSERT INTO asn_karma FORMAT JSONEachRow"
