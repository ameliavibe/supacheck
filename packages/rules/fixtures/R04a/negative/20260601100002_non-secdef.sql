-- Non-SECDEF function (no security context concern).

CREATE OR REPLACE FUNCTION public.helper(p_id uuid)
  RETURNS void
  LANGUAGE sql
  SECURITY INVOKER
  SET search_path TO 'public', 'pg_temp'
AS $$
  SELECT 1;
$$;
