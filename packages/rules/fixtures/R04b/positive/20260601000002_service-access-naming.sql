CREATE POLICY "Service role access for events"
  ON public.events
  FOR SELECT
  USING (true);
