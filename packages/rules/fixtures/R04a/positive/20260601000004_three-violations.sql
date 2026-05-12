-- SECDEF function missing all three attributes — produces 3 findings.

CREATE OR REPLACE FUNCTION public.bare_secdef(p_id uuid)
  RETURNS void
  LANGUAGE plpgsql
  SECURITY DEFINER
AS $$
BEGIN
  PERFORM 1;
END;
$$;
