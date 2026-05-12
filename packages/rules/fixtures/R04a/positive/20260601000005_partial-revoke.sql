-- Only REVOKE from PUBLIC, missing anon and authenticated. R04a wants all three named.

CREATE OR REPLACE FUNCTION public.partial(p_id uuid)
  RETURNS void
  LANGUAGE plpgsql
  SECURITY DEFINER
  SET search_path TO 'public', 'pg_temp'
AS $$
BEGIN
  PERFORM 1;
END;
$$;

ALTER FUNCTION public.partial(p_id uuid) OWNER TO postgres;

REVOKE EXECUTE ON FUNCTION public.partial(p_id uuid) FROM PUBLIC;
