-- No REVOKE at all. R04a catches this case; R07 does not fire.

CREATE OR REPLACE FUNCTION public.unlocked(p_id uuid)
  RETURNS void
  LANGUAGE plpgsql
  SECURITY DEFINER
  SET search_path TO 'public', 'pg_temp'
AS $$
BEGIN
  PERFORM 1;
END;
$$;

ALTER FUNCTION public.unlocked(p_id uuid) OWNER TO postgres;
