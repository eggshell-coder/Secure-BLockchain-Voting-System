-- Tighten the pre-existing RLS auto-enable event-trigger function. The
-- database event trigger can still invoke it; API roles do not need EXECUTE.
REVOKE EXECUTE ON FUNCTION public.rls_auto_enable() FROM PUBLIC, anon, authenticated;

-- Cover foreign keys used for joins and parent-row updates/deletes.
CREATE INDEX audit_events_action_code_idx ON public.audit_events (action_code);
CREATE INDEX audit_events_actor_user_idx ON public.audit_events (actor_user_id)
  WHERE actor_user_id IS NOT NULL;
CREATE INDEX audit_events_candidate_idx ON public.audit_events (subject_candidate_id)
  WHERE subject_candidate_id IS NOT NULL;
CREATE INDEX audit_events_challenge_idx ON public.audit_events (subject_challenge_id)
  WHERE subject_challenge_id IS NOT NULL;
CREATE INDEX candidate_results_candidate_fk_idx
  ON public.candidate_results (election_id, candidate_id);
CREATE INDEX election_voters_reviewed_by_idx ON public.election_voters (reviewed_by)
  WHERE reviewed_by IS NOT NULL;
CREATE INDEX user_roles_role_code_idx ON public.user_roles (role_code);
CREATE INDEX user_roles_granted_by_idx ON public.user_roles (granted_by)
  WHERE granted_by IS NOT NULL;
CREATE INDEX voters_registration_reviewed_by_idx ON public.voters (registration_reviewed_by)
  WHERE registration_reviewed_by IS NOT NULL;
