ALTER POLICY "existing_policy"
  ON public.drafts
  USING (owner_id = auth.uid());
