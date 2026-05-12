CREATE POLICY "ignored_comment"
  ON public.drafts FOR SELECT
  TO authenticated
  USING (
    user_id = (select auth.uid())
    -- TODO: revisit if Postgres ever caches bare auth.uid() per query
  );
