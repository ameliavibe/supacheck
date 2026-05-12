CREATE POLICY "ignored_block_comment"
  ON public.drafts FOR SELECT
  TO authenticated
  USING (
    user_id = (select auth.uid())
    /* historical note:
       we considered bare auth.uid() here, then learned about the per-row eval cost.
    */
  );
