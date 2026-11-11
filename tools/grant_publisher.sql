-- Run as the identity schema owner after migration. A database administrator
-- creates the LOGIN role and sets its password separately.
\set ON_ERROR_STOP on
BEGIN;
GRANT CONNECT ON DATABASE :"DBNAME" TO identity_publisher;
GRANT USAGE ON SCHEMA public TO identity_publisher;
GRANT SELECT (event_id, payload, created_at_ms, claim_token, claim_until, published_at),
      UPDATE (claim_token, claim_until, published_at)
ON public.dl_identity_outbox TO identity_publisher;
GRANT EXECUTE ON FUNCTION public.dl_identity_purge_published() TO identity_publisher;
COMMIT;
