CREATE POLICY "uppercase_select"
  ON public.drafts FOR SELECT
  TO authenticated
  USING (user_id = (SELECT auth.uid()));
