-- Yashiki local registry (11-yashiki-design.md section 3).
-- Infrastructure state only. Business domain rows (requests, gates, chat
-- threads, delegation) belong to the meidoya repository and must never appear
-- here (03-repository-boundaries.md section 2.2).

CREATE TABLE nodes (
  name TEXT PRIMARY KEY,
  provider TEXT NOT NULL CHECK (provider IN ('lima', 'native')),
  profile TEXT NOT NULL CHECK (profile IN ('mac-restricted', 'linux-restricted', 'lima-trusted')),
  platform TEXT NOT NULL CHECK (platform IN ('darwin', 'linux')),
  arch TEXT NOT NULL CHECK (arch IN ('arm64', 'x64')),
  cpus INTEGER NOT NULL CHECK (cpus > 0),
  memory_mib INTEGER NOT NULL CHECK (memory_mib > 0),
  disk_gib INTEGER NOT NULL CHECK (disk_gib > 0),
  desired_config_json TEXT NOT NULL,
  desired_config_hash TEXT NOT NULL,
  version INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

-- provider_state.provider is the provider a node was OBSERVED through, and it
-- must be the provider that node is configured with: a row saying a `lima` node
-- was observed as `native` describes a machine that does not exist, and every
-- reconciliation reading it draws a conclusion about the wrong thing. A CHECK
-- cannot reach another table, so the agreement is a pair of triggers. There is
-- deliberately no enumeration CHECK on this column: nodes.provider already
-- carries one and the triggers fire first, so a value outside the enumeration
-- disagrees with nodes.provider too and a CHECK here could never be the
-- constraint that refuses anything.
CREATE TABLE provider_state (
  node_name TEXT PRIMARY KEY REFERENCES nodes(name) ON DELETE CASCADE,
  provider TEXT NOT NULL,
  external_ref TEXT,
  status TEXT NOT NULL CHECK (status IN ('absent', 'stopped', 'running', 'unknown')),
  observed_cpus INTEGER,
  observed_memory_mib INTEGER,
  observed_disk_gib INTEGER,
  observed_at INTEGER NOT NULL
);

CREATE TRIGGER provider_state_provider_matches_node_insert BEFORE INSERT ON provider_state
BEGIN
  SELECT RAISE(ABORT, 'provider_state.provider must match nodes.provider')
  WHERE (SELECT provider FROM nodes WHERE name = NEW.node_name) IS NOT NEW.provider;
END;

CREATE TRIGGER provider_state_provider_matches_node_update BEFORE UPDATE ON provider_state
BEGIN
  SELECT RAISE(ABORT, 'provider_state.provider must match nodes.provider')
  WHERE (SELECT provider FROM nodes WHERE name = NEW.node_name) IS NOT NEW.provider;
END;

-- `fence` is a per-ACQUISITION token, not a per-holder one. The CLI's holder
-- string is `cli-<pid>`, and a PID is reused: run A acquires, its TTL expires,
-- run B acquires under the very same holder string, and A's
-- `finally { release() }` then deleted B's LIVE lock mid-provision. Release is
-- fenced on this token, so a handle can only ever delete the lock it took.
CREATE TABLE node_locks (
  node_name TEXT PRIMARY KEY REFERENCES nodes(name) ON DELETE CASCADE,
  holder TEXT NOT NULL,
  fence TEXT NOT NULL,
  acquired_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE TABLE provisioning_runs (
  id TEXT PRIMARY KEY,
  node_name TEXT NOT NULL REFERENCES nodes(name) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK (kind IN ('provision', 'reprovision', 'upgrade')),
  status TEXT NOT NULL CHECK (status IN ('running', 'succeeded', 'failed')),
  last_step TEXT NOT NULL,
  error_code TEXT,
  error_message TEXT,
  started_at INTEGER NOT NULL,
  finished_at INTEGER
);

CREATE INDEX provisioning_runs_by_node ON provisioning_runs (node_name, started_at DESC);

-- Receipts are append-only and tamper-evident: sequence + previous_hash form a
-- chain, and the triggers below reject UPDATE/DELETE outright. `receipts` is the
-- chain of record; install_receipts and credential_receipts are typed
-- projections of the same appended rows.
CREATE TABLE receipts (
  content_hash TEXT PRIMARY KEY,
  sequence INTEGER NOT NULL UNIQUE,
  previous_hash TEXT,
  kind TEXT NOT NULL CHECK (
    kind IN ('install', 'credential', 'provisioning', 'health', 'backup', 'recovery')
  ),
  node_name TEXT NOT NULL,
  created_at TEXT NOT NULL,
  payload_json TEXT NOT NULL
);

CREATE INDEX receipts_by_node ON receipts (node_name, kind, sequence DESC);

CREATE TRIGGER receipts_no_update BEFORE UPDATE ON receipts
BEGIN SELECT RAISE(ABORT, 'receipts is append-only'); END;

CREATE TRIGGER receipts_no_delete BEFORE DELETE ON receipts
BEGIN SELECT RAISE(ABORT, 'receipts is append-only'); END;

-- The chain's HEAD ANCHOR, kept outside `receipts` so it survives what happens
-- to `receipts`.
--
-- Walking the chain forward from sequence 0 detects an edit, a reorder, a
-- head truncation and a removal from the middle — but NOT the removal of a
-- suffix: `[r0, r1]` and `[r0]` and `[]` are each an internally consistent
-- chain. And deriving the next sequence from `COUNT(*)` (or from
-- `MAX(sequence)`) meant the sequence a deleted row occupied was handed
-- straight back to the next append, so a receipt could be erased and replaced
-- and the chain still verified clean — tamper-evidence reporting OK about the
-- one thing it exists to catch.
--
-- `next_sequence` is a high-water mark that only ever increases, so a freed
-- sequence is never reissued, and `head_hash` plus `next_sequence` are the
-- anchor `verifyReceiptChain` needs to see a truncated tail.
CREATE TABLE receipt_chain_head (
  id INTEGER PRIMARY KEY CHECK (id = 0),
  next_sequence INTEGER NOT NULL,
  head_hash TEXT
);

INSERT INTO receipt_chain_head (id, next_sequence, head_hash) VALUES (0, 0, NULL);

CREATE TRIGGER receipt_chain_head_no_rewind BEFORE UPDATE ON receipt_chain_head
BEGIN
  SELECT RAISE(ABORT, 'receipt chain head must not rewind')
  WHERE NEW.next_sequence <= OLD.next_sequence;
END;

CREATE TRIGGER receipt_chain_head_no_delete BEFORE DELETE ON receipt_chain_head
BEGIN SELECT RAISE(ABORT, 'receipt chain head is append-only'); END;

CREATE TABLE install_receipts (
  content_hash TEXT PRIMARY KEY,
  node_name TEXT NOT NULL REFERENCES nodes(name) ON DELETE CASCADE,
  sequence INTEGER NOT NULL,
  previous_hash TEXT,
  product TEXT NOT NULL,
  node_version TEXT NOT NULL,
  protocol_version INTEGER NOT NULL,
  artifact_sha256 TEXT NOT NULL,
  installed_at TEXT NOT NULL,
  body_json TEXT NOT NULL,
  UNIQUE (node_name, sequence)
);

CREATE TRIGGER install_receipts_no_update BEFORE UPDATE ON install_receipts
BEGIN SELECT RAISE(ABORT, 'install_receipts is append-only'); END;

CREATE TRIGGER install_receipts_no_delete BEFORE DELETE ON install_receipts
BEGIN SELECT RAISE(ABORT, 'install_receipts is append-only'); END;

-- One row per credential provider (11 section 7). value_fingerprint is a salted
-- digest used to detect drift; the credential value itself is never stored.
CREATE TABLE credential_receipts (
  content_hash TEXT PRIMARY KEY,
  node_name TEXT NOT NULL REFERENCES nodes(name) ON DELETE CASCADE,
  sequence INTEGER NOT NULL,
  previous_hash TEXT,
  credential_provider TEXT NOT NULL CHECK (
    credential_provider IN ('codex', 'claude', 'node-registration', 'github')
  ),
  operation TEXT NOT NULL CHECK (operation IN ('sync', 'revoke')),
  source_ref TEXT NOT NULL,
  guest_path TEXT NOT NULL,
  guest_owner TEXT NOT NULL,
  guest_mode TEXT NOT NULL,
  value_fingerprint TEXT,
  materialized_at TEXT NOT NULL,
  body_json TEXT NOT NULL,
  UNIQUE (node_name, sequence)
);

CREATE TRIGGER credential_receipts_no_update BEFORE UPDATE ON credential_receipts
BEGIN SELECT RAISE(ABORT, 'credential_receipts is append-only'); END;

CREATE TRIGGER credential_receipts_no_delete BEFORE DELETE ON credential_receipts
BEGIN SELECT RAISE(ABORT, 'credential_receipts is append-only'); END;

CREATE TABLE health_results (
  id TEXT PRIMARY KEY,
  node_name TEXT NOT NULL REFERENCES nodes(name) ON DELETE CASCADE,
  check_id TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('ok', 'warn', 'fail', 'skipped')),
  detail TEXT NOT NULL,
  checked_at INTEGER NOT NULL
);

CREATE INDEX health_results_by_node ON health_results (node_name, checked_at DESC);

CREATE TABLE backup_operations (
  id TEXT PRIMARY KEY,
  node_name TEXT NOT NULL REFERENCES nodes(name) ON DELETE CASCADE,
  status TEXT NOT NULL CHECK (status IN ('running', 'succeeded', 'failed')),
  archive_ref TEXT,
  archive_sha256 TEXT,
  excluded_json TEXT NOT NULL DEFAULT '[]',
  started_at INTEGER NOT NULL,
  finished_at INTEGER
);

CREATE TABLE recovery_operations (
  id TEXT PRIMARY KEY,
  node_name TEXT NOT NULL REFERENCES nodes(name) ON DELETE CASCADE,
  backup_id TEXT REFERENCES backup_operations(id),
  status TEXT NOT NULL CHECK (
    status IN ('running', 'succeeded', 'failed', 'recovery_required')
  ),
  journal_json TEXT NOT NULL DEFAULT '[]',
  halted_reason TEXT,
  started_at INTEGER NOT NULL,
  finished_at INTEGER
);
