-- SECDEF function without ALTER FUNCTION ... OWNER TO postgres.

CREATE OR REPLACE FUNCTION public.do_thing(p_user uuid)
  RETURNS void
  LANGUAGE plpgsql
  SECURITY DEFINER
  SET search_path TO 'public', 'pg_temp'
AS $$
BEGIN
  PERFORM 1;
END;
$$;

REVOKE EXECUTE ON FUNCTION public.do_thing(p_user uuid) FROM PUBLIC, anon, authenticated;
