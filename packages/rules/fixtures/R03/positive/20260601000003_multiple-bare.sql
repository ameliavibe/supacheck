CREATE POLICY "users_own_rows"
  ON public.profiles FOR ALL
  TO authenticated
  USING (user_id = auth.uid())
  WITH CHECK (user_id = auth.uid());
