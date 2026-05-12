CREATE POLICY "join_via_subquery"
  ON public.posts FOR SELECT
  TO authenticated
  USING (
    org_id IN (
      SELECT org_id FROM members WHERE user_id = auth.uid()
    )
  );
