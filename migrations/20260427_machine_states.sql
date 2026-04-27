-- Store VMT callback state snapshots per machine.

CREATE TABLE IF NOT EXISTS machine_states (
    id SERIAL PRIMARY KEY,
    device_sn VARCHAR(128) NOT NULL,
    state VARCHAR(128),
    source_event_time TIMESTAMPTZ,
    payload_json TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_machine_states_device_sn ON machine_states(device_sn);
CREATE INDEX IF NOT EXISTS ix_machine_states_created_at ON machine_states(created_at);
CREATE INDEX IF NOT EXISTS ix_machine_states_source_event_time ON machine_states(source_event_time);
