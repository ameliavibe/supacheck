CREATE POLICY "would_be_violation"
  ON public.drafts FOR SELECT
  TO authenticated
  USING (user_id = auth.uid());
