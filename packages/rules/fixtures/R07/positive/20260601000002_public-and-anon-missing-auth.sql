-- PUBLIC and anon are REVOKE'd, but authenticated is missing.

CREATE OR REPLACE FUNCTION public.almost_locked(p_id uuid)
  RETURNS void
  LANGUAGE plpgsql
  SECURITY DEFINER
  SET search_path TO 'public', 'pg_temp'
AS $$
BEGIN
  PERFORM 1;
END;
$$;

ALTER FUNCTION public.almost_locked(p_id uuid) OWNER TO postgres;

REVOKE EXECUTE ON FUNCTION public.almost_locked(p_id uuid) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.almost_locked(p_id uuid) FROM anon;
GRANT EXECUTE ON FUNCTION public.almost_locked(p_id uuid) TO service_role;
