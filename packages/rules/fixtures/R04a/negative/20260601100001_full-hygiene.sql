-- Compliant SECDEF: search_path attribute, OWNER, REVOKE all three.

CREATE OR REPLACE FUNCTION public.good_secdef(p_id uuid)
  RETURNS void
  LANGUAGE plpgsql
  SECURITY DEFINER
  SET search_path TO 'public', 'pg_temp'
AS $$
BEGIN
  PERFORM 1;
END;
$$;

ALTER FUNCTION public.good_secdef(p_id uuid) OWNER TO postgres;

REVOKE EXECUTE ON FUNCTION public.good_secdef(p_id uuid) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.good_secdef(p_id uuid) TO service_role;
