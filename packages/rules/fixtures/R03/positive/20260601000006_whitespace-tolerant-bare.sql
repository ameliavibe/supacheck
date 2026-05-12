CREATE POLICY "padded_parens"
  ON public.posts FOR SELECT
  TO authenticated
  USING (user_id = auth.uid(  ));
