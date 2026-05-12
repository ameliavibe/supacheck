CREATE POLICY "users_own_drafts"
  ON public.drafts FOR SELECT
  TO authenticated
  USING (user_id = (select auth.uid()));
