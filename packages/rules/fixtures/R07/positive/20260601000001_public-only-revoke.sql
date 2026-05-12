-- SECDEF function with REVOKE FROM PUBLIC only. pg_dump will emit
-- default-privilege GRANT TO anon + authenticated during the next squash,
-- silently undoing the lockdown.

CREATE OR REPLACE FUNCTION public.admin_only(p_id uuid)
  RETURNS void
  LANGUAGE plpgsql
  SECURITY DEFINER
  SET search_path TO 'public', 'pg_temp'
AS $$
BEGIN
  PERFORM 1;
END;
$$;

ALTER FUNCTION public.admin_only(p_id uuid) OWNER TO postgres;

REVOKE EXECUTE ON FUNCTION public.admin_only(p_id uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.admin_only(p_id uuid) TO service_role;
