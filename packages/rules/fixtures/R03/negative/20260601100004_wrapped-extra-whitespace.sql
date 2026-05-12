CREATE POLICY "padded"
  ON public.drafts FOR SELECT
  TO authenticated
  USING (user_id = (select    auth.uid()));
