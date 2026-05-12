CREATE POLICY "mixed_uses"
  ON public.threads FOR SELECT
  TO authenticated
  USING (
    user_id = (select auth.uid())
    AND last_actor_id = auth.uid()
  );
