-- REVOKE from anon + authenticated only, no PUBLIC. pg_dump will preserve
-- these role-by-role statements, so R07 does not fire (it only fires when
-- the PUBLIC trigger is present without role-by-role coverage).

CREATE OR REPLACE FUNCTION public.roles_only(p_id uuid)
  RETURNS void
  LANGUAGE plpgsql
  SECURITY DEFINER
  SET search_path TO 'public', 'pg_temp'
AS $$
BEGIN
  PERFORM 1;
END;
$$;

ALTER FUNCTION public.roles_only(p_id uuid) OWNER TO postgres;

REVOKE EXECUTE ON FUNCTION public.roles_only(p_id uuid) FROM anon;
REVOKE EXECUTE ON FUNCTION public.roles_only(p_id uuid) FROM authenticated;
GRANT EXECUTE ON FUNCTION public.roles_only(p_id uuid) TO service_role;
