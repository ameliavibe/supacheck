CREATE TABLE public.events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  created_by uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO public.audit_log (event, actor) VALUES ('schema_init', auth.uid());
