CREATE POLICY "owner_or_admin"
  ON public.posts FOR SELECT
  TO authenticated
  USING (user_id = auth.uid() OR is_admin(auth.uid()));
