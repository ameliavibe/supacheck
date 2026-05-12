-- Gold standard: REVOKE FROM PUBLIC, anon, authenticated in one statement.

CREATE OR REPLACE FUNCTION public.well_locked(p_id uuid)
  RETURNS void
  LANGUAGE plpgsql
  SECURITY DEFINER
  SET search_path TO 'public', 'pg_temp'
AS $$
BEGIN
  PERFORM 1;
END;
$$;

ALTER FUNCTION public.well_locked(p_id uuid) OWNER TO postgres;

REVOKE EXECUTE ON FUNCTION public.well_locked(p_id uuid) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.well_locked(p_id uuid) TO service_role;
