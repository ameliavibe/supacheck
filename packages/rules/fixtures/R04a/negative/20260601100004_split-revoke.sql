-- Compliant: REVOKE split into three separate role-by-role statements.

CREATE OR REPLACE FUNCTION public.split_revoke(p_id uuid)
  RETURNS void
  LANGUAGE plpgsql
  SECURITY DEFINER
  SET search_path TO 'public', 'pg_temp'
AS $$
BEGIN
  PERFORM 1;
END;
$$;

ALTER FUNCTION public.split_revoke(p_id uuid) OWNER TO postgres;

REVOKE EXECUTE ON FUNCTION public.split_revoke(p_id uuid) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.split_revoke(p_id uuid) FROM anon;
REVOKE EXECUTE ON FUNCTION public.split_revoke(p_id uuid) FROM authenticated;
GRANT EXECUTE ON FUNCTION public.split_revoke(p_id uuid) TO service_role;
