CREATE POLICY "old_policy"
  ON public.drafts FOR SELECT
  TO authenticated
  USING (user_id = auth.uid());
