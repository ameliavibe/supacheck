CREATE POLICY "service_role_full_access"
  ON public.events
  FOR ALL
  TO service_role
  USING (true);
