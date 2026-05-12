CREATE POLICY "extra_parens"
  ON public.drafts FOR SELECT
  TO authenticated
  USING (user_id = (((select auth.uid()))));
