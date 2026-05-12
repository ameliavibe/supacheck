-- SECDEF function without REVOKE EXECUTE statements.

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

ALTER FUNCTION public.do_thing(p_user uuid) OWNER TO postgres;
