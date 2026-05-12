CREATE POLICY "split_across_lines"
  ON public.events FOR SELECT
  TO authenticated
  USING (
    user_id
    =
    auth.uid()
  );
