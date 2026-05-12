-- Using REVOKE ALL ... FROM PUBLIC (not just EXECUTE). Same failure mode.

CREATE OR REPLACE FUNCTION public.severely_partial(p_id uuid)
  RETURNS void
  LANGUAGE plpgsql
  SECURITY DEFINER
  SET search_path TO 'public', 'pg_temp'
AS $$
BEGIN
  PERFORM 1;
END;
$$;

ALTER FUNCTION public.severely_partial(p_id uuid) OWNER TO postgres;

REVOKE ALL ON FUNCTION public.severely_partial(p_id uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.severely_partial(p_id uuid) TO service_role;
