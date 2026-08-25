-- Schema for the mirror node's PostgreSQL store.
-- Applied idempotently at startup (every statement is CREATE TABLE IF NOT EXISTS).
--
-- Mapping rules from ../../proto/jkain_stream.proto:
--   uint64     -> BIGINT   (safe in practice: rounds/IDs stay far below 2^63-1)
--   uint32     -> INTEGER
--   bytes      -> BYTEA
--   optional X -> X nullable (absent = NULL, present-but-empty = '')
--   repeated M -> child table with a foreign key back to the parent

-- ---------- record stream (.rsf): one decided round per row ----------

CREATE TABLE IF NOT EXISTS record_files (
    round              BIGINT  PRIMARY KEY,
    version            INTEGER NOT NULL,
    start_running_hash BYTEA   NOT NULL CHECK (octet_length(start_running_hash) = 32),
    end_running_hash   BYTEA   NOT NULL CHECK (octet_length(end_running_hash)   = 32),

    -- SignedCheckpoint: 1:1 with the file, so scalars live inline;
    -- its repeated parts are the two child tables below.
    checkpoint_round   BIGINT,
    state_hash         BYTEA,
    roster_hash        BYTEA
);

-- repeated RecordItem items — order inside the file matters, hence item_index in the key
CREATE TABLE IF NOT EXISTS record_items (
    round      BIGINT  NOT NULL REFERENCES record_files(round),
    item_index INTEGER NOT NULL,
    event_hash BYTEA   NOT NULL CHECK (octet_length(event_hash) = 32),
    tx_index   INTEGER NOT NULL,
    tx_payload BYTEA   NOT NULL,
    PRIMARY KEY (round, item_index)
);

-- repeated CheckpointSig sigs — a signer signs once per round
CREATE TABLE IF NOT EXISTS checkpoint_sigs (
    round  BIGINT NOT NULL REFERENCES record_files(round),
    signer BIGINT NOT NULL,
    sig    BYTEA  NOT NULL CHECK (octet_length(sig) = 64),
    PRIMARY KEY (round, signer)
);

-- repeated CheckpointRosterMember roster_snapshot
CREATE TABLE IF NOT EXISTS checkpoint_roster (
    round        BIGINT  NOT NULL REFERENCES record_files(round),
    member_index INTEGER NOT NULL,
    node_id      BIGINT  NOT NULL,
    key          BYTEA   NOT NULL CHECK (octet_length(key) = 32),
    PRIMARY KEY (round, member_index)
);

-- ---------- event stream (.esf) ----------

CREATE TABLE IF NOT EXISTS events (
    creator             BIGINT  NOT NULL,
    seq                 BIGINT  NOT NULL,
    self_parent         BYTEA           CHECK (self_parent  IS NULL OR octet_length(self_parent)  = 32),
    other_parent        BYTEA           CHECK (other_parent IS NULL OR octet_length(other_parent) = 32),
    timestamp           BIGINT  NOT NULL,
    signature           BYTEA   NOT NULL DEFAULT '',
    birth_round         BIGINT  NOT NULL,
    round_received      BIGINT,
    consensus_timestamp BIGINT,
    ingested_seq        BIGSERIAL UNIQUE,
    PRIMARY KEY (creator, seq)
);

-- repeated Transaction transactions
CREATE TABLE IF NOT EXISTS event_transactions (
    creator  BIGINT  NOT NULL,
    seq      BIGINT  NOT NULL,
    tx_index INTEGER NOT NULL,
    payload  BYTEA   NOT NULL,
    PRIMARY KEY (creator, seq, tx_index),
    FOREIGN KEY (creator, seq) REFERENCES events(creator, seq)
);