CREATE OR REPLACE FUNCTION public.same_user(other_id uuid)
  RETURNS boolean
  LANGUAGE sql
  STABLE
AS $$
  SELECT other_id = auth.uid();
$$;
