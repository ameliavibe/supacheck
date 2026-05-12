-- SECDEF function with body-level SET search_path (pg_dump strips this).
-- Has OWNER and REVOKE, but missing the attribute-form search_path.

CREATE OR REPLACE FUNCTION public.do_thing(p_user uuid)
  RETURNS void
  LANGUAGE plpgsql
  SECURITY DEFINER
AS $$
BEGIN
  SET search_path = public, pg_temp;
  -- ...
END;
$$;

ALTER FUNCTION public.do_thing(p_user uuid) OWNER TO postgres;

REVOKE EXECUTE ON FUNCTION public.do_thing(p_user uuid) FROM PUBLIC, anon, authenticated;
