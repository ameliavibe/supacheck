CREATE POLICY "service_role_full_access"
  ON public.events
  FOR ALL
  USING (true);
