-- Keep only the current state per machine (one row per device_sn).

DELETE FROM machine_states
WHERE id IN (
    SELECT id
    FROM (
        SELECT
            id,
            ROW_NUMBER() OVER (
                PARTITION BY device_sn
                ORDER BY created_at DESC NULLS LAST, id DESC
            ) AS rn
        FROM machine_states
    ) ranked
    WHERE rn > 1
);

DROP INDEX IF EXISTS ix_machine_states_device_sn;

CREATE UNIQUE INDEX IF NOT EXISTS uq_machine_states_device_sn ON machine_states (device_sn);
