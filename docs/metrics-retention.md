# Metrics retention and indexing

OpenVPN telemetry is kept in dedicated tables without automatic deletion. The intended retention window is 14–30 days, but data is not purged by default so operators can enforce their own policies.

Primary indexes ensure fast lookups on hot fields:

- `metrics_samples` – indexes on `name` and `recorded_at`.
- `client_sessions` – unique `lookup_key` for upserts.
- `client_events` – indexes on `client_id` + `ts` and `common_name` + `ts` (via indexed fields in the model).
- `routing_ccd` – indexes on `net` plus `client_id`.
- `daemon_info` – indexed `pid` and `daemon_start` to anchor uptime calculations.

Keep labels JSON deterministic (sorted keys) so rows can be deduplicated reliably when exported to external stores.
