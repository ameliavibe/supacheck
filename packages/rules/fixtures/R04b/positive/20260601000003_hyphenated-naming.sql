CREATE POLICY "service-role-events"
  ON public.events
  FOR ALL
  USING (true)
  WITH CHECK (true);
