-- Postgres: widen Nayax external IDs from int4 to int8 ("integer out of range").
-- Safe to run repeatedly (no-op if columns are already bigint). Not for SQLite.
DO $migration$
BEGIN
  IF to_regclass('public.nayax_transactions') IS NULL THEN
    RETURN;
  END IF;

  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = 'nayax_transactions'
      AND column_name = 'nayax_transaction_id' AND udt_name = 'int4'
  ) THEN
    ALTER TABLE nayax_transactions
      ALTER COLUMN nayax_transaction_id TYPE bigint USING nayax_transaction_id::bigint;
  END IF;

  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = 'nayax_transactions'
      AND column_name = 'remote_start_transaction_id' AND udt_name = 'int4'
  ) THEN
    ALTER TABLE nayax_transactions
      ALTER COLUMN remote_start_transaction_id TYPE bigint USING remote_start_transaction_id::bigint;
  END IF;

  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = 'nayax_transactions'
      AND column_name = 'site_id' AND udt_name = 'int4'
  ) THEN
    ALTER TABLE nayax_transactions
      ALTER COLUMN site_id TYPE bigint USING site_id::bigint;
  END IF;

  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = 'nayax_transactions'
      AND column_name = 'machine_id' AND udt_name = 'int4'
  ) THEN
    ALTER TABLE nayax_transactions
      ALTER COLUMN machine_id TYPE bigint USING machine_id::bigint;
  END IF;

  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = 'nayax_transactions'
      AND column_name = 'actor_id' AND udt_name = 'int4'
  ) THEN
    ALTER TABLE nayax_transactions
      ALTER COLUMN actor_id TYPE bigint USING actor_id::bigint;
  END IF;

  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = 'nayax_transactions'
      AND column_name = 'location_code' AND udt_name = 'int4'
  ) THEN
    ALTER TABLE nayax_transactions
      ALTER COLUMN location_code TYPE bigint USING location_code::bigint;
  END IF;

  IF to_regclass('public.nayax_transaction_products') IS NULL THEN
    RETURN;
  END IF;

  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = 'nayax_transaction_products'
      AND column_name = 'product_code_in_map' AND udt_name = 'int4'
  ) THEN
    ALTER TABLE nayax_transaction_products
      ALTER COLUMN product_code_in_map TYPE bigint USING product_code_in_map::bigint;
  END IF;
END $migration$;
