import copy
from pathlib import Path
import tempfile
import unittest

from rs9.errors import ContractError
from rs9.publication import mutation_attempt, publication_receipt, next_action, check_precondition
from rs9.scratch import canonical
from tests.publication_fixtures import fixture, observation, make_plan, T0,T1,T2,T3


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.bundle=fixture(Path(self.tmp.name).resolve());self.output=self.bundle[3]
        self.plan=make_plan(self.bundle)

    def attempt(self,outcome="confirmed",**kwargs):
        return mutation_attempt(self.plan,executor_role="synthetic-test",started_at=T1,finished_at=T2,transport_outcome=outcome,request_identity="synthetic-request",**kwargs)

    def test_no_publication_without_actual_attempt_and_post_exact(self):
        exact=observation(self.output,"exact",at=T3)
        self.assertEqual(publication_receipt(self.plan,[],exact)["final_state"],"not-attempted")
        self.assertEqual(publication_receipt(self.plan,[self.attempt("not_attempted")],exact)["final_state"],"not-attempted")
        self.assertEqual(publication_receipt(self.plan,[self.attempt()],observation(self.output,"exact",at=T1))["final_state"],"unconfirmed")
        for state,final in (("absent","unconfirmed"),("incomplete","incomplete"),("conflict","conflict"),("unknown","unconfirmed")):
            self.assertEqual(publication_receipt(self.plan,[self.attempt()],observation(self.output,state,at=T3))["final_state"],final)
        self.assertEqual(publication_receipt(self.plan,[self.attempt()],exact)["final_state"],"published")

    def test_forged_attempt_and_readback_rejected(self):
        attempt=self.attempt();attempt["plan_sha256"]="c"*64
        with self.assertRaises(ContractError):publication_receipt(self.plan,[attempt],observation(self.output,"exact",at=T3))
        post=observation(self.output);post["state"]="exact"
        with self.assertRaises(ContractError):publication_receipt(self.plan,[self.attempt()],post)
        attempt=self.attempt();attempt["transport_outcome"]="success"
        with self.assertRaises(ContractError):publication_receipt(self.plan,[attempt],observation(self.output,"exact",at=T3))

    def test_exact_noop_receipt_cannot_attempt_mutation(self):
        plan=make_plan(self.bundle,"exact")
        self.assertEqual(publication_receipt(plan,[],observation(self.output,"exact"))["final_state"],"already-exact")
        with self.assertRaises(ContractError):mutation_attempt(plan,executor_role="synthetic-test",started_at=T1,finished_at=T2,transport_outcome="confirmed")

    def test_ambiguous_and_failed_transport_require_reread_before_retry(self):
        for outcome in ("ambiguous","failed","confirmed"):
            attempt=self.attempt(outcome)
            self.assertEqual(next_action(self.plan,[attempt],observation(self.output),evaluated_at=T3),"reread-required")
            self.assertEqual(next_action(self.plan,[attempt],observation(self.output,at=T3),evaluated_at=T3),"replan-required")
            self.assertEqual(next_action(self.plan,[attempt],observation(self.output,"exact",at=T3),evaluated_at=T3),"noop")
            self.assertEqual(next_action(self.plan,[attempt],observation(self.output,"conflict",at=T3),evaluated_at=T3),"block-conflict")

    def test_confirmed_receipt_replay_duplicate_request_and_partial_fanout(self):
        attempt=self.attempt();post=observation(self.output,"exact",at=T3)
        receipt=publication_receipt(self.plan,[attempt],post)
        self.assertEqual(next_action(self.plan,[attempt],post,evaluated_at=T3,receipt=receipt),"noop")
        with self.assertRaises(ContractError):publication_receipt(self.plan,[attempt,attempt],post)
        other=copy.deepcopy(receipt);other["final_state"]="published";other["post_observation_sha256"]="a"*64
        with self.assertRaises(ContractError):next_action(self.plan,[attempt],post,evaluated_at=T3,receipt=other)
        self.assertEqual(next_action(self.plan,[],observation(self.output),evaluated_at=T0),"publish-intent")

    def test_stale_observation_and_remote_precondition_require_replan(self):
        self.assertEqual(check_precondition(self.plan,observation(self.output),evaluated_at=T0),"ready")
        self.assertEqual(check_precondition(self.plan,observation(self.output,remote={"etag":"changed"}),evaluated_at=T0),"stale-plan")
        self.assertEqual(next_action(self.plan,[],observation(self.output,"exact"),evaluated_at="2026-10-03T13:00:00Z"),"reread-required")

    def test_receipt_replay_retains_attempts_and_rejects_older_readback(self):
        attempt=self.attempt();post=observation(self.output,"exact",at=T3)
        receipt=publication_receipt(self.plan,[attempt],post)
        for old in (observation(self.output), observation(self.output,"exact",at=T1),
                    observation(self.output,at=T3)):
            with self.subTest(state=old["state"],at=old["observed_at"]):
                self.assertEqual(next_action(self.plan,[],old,evaluated_at=T3,receipt=receipt),"reread-required")
        self.assertEqual(next_action(self.plan,[],post,evaluated_at=T3,receipt=receipt),"noop")
        later="2026-10-03T12:00:04Z"
        for state,action in (("absent","replan-required"),("exact","noop"),("conflict","block-conflict")):
            with self.subTest(state=state):
                self.assertEqual(next_action(self.plan,[],observation(self.output,state,at=later),
                                            evaluated_at=later,receipt=receipt),action)

    def test_ambiguous_receipt_and_new_attempt_require_current_readback(self):
        post=observation(self.output,at=T3)
        receipt=publication_receipt(self.plan,[self.attempt("ambiguous")],post)
        self.assertEqual(next_action(self.plan,[],observation(self.output),evaluated_at=T3,receipt=receipt),"reread-required")
        self.assertEqual(next_action(self.plan,[],post,evaluated_at=T3,receipt=receipt),"replan-required")
        later="2026-10-03T12:00:04Z"
        attempt=mutation_attempt(self.plan,executor_role="synthetic-test",started_at=T3,finished_at=later,
                                 transport_outcome="ambiguous",request_identity="second-request")
        self.assertEqual(next_action(self.plan,[attempt],post,evaluated_at=later,receipt=receipt),"reread-required")

    def test_remote_sequence_proof_and_timestamp_fallback(self):
        attempt=self.attempt(response_remote={"sequence":2})
        early=observation(self.output,"exact",at=T1,remote={"sequence":2})
        receipt=publication_receipt(self.plan,[attempt],early)
        self.assertEqual(receipt["final_state"],"published")
        self.assertEqual(receipt["readback_proof"]["basis"],"remote-sequence")
        stale=observation(self.output,"exact",at=T3,remote={"sequence":1})
        self.assertEqual(publication_receipt(self.plan,[attempt],stale)["final_state"],"unconfirmed")
        self.assertEqual(publication_receipt(self.plan,[self.attempt()],observation(self.output,"exact",at=T3))["readback_proof"]["basis"],"timestamp-fallback")

    def test_deterministic_receipt_and_sanitized_log_reference(self):
        one=self.attempt("ambiguous");two=self.attempt(response_remote={"etag":"synthetic-etag"})
        post=observation(self.output,"exact",at=T3,remote={"etag":"synthetic-etag"})
        self.assertEqual(canonical(publication_receipt(self.plan,[one,two],post)),canonical(publication_receipt(self.plan,[two,one],post)))
        with self.assertRaises(ContractError):self.attempt(log_reference={"sha256":"a"*64,"size":2*1024*1024})
        with self.assertRaises(ContractError):self.attempt(response_remote={"credential":"synthetic"})

    def test_remote_proof_cannot_fall_back_when_missing_or_unchanged(self):
        for key,value in (("etag","old-etag"),("revision","old-revision"),("commit","a"*40),("sequence",2)):
            with self.subTest(key=key):
                plan=make_plan(self.bundle,remote={key:value})
                attempt=mutation_attempt(plan,executor_role="synthetic-test",started_at=T1,finished_at=T2,
                                         transport_outcome="confirmed",response_remote={key:value})
                post=observation(self.output,"exact",at=T3,remote={key:value})
                self.assertEqual(publication_receipt(plan,[attempt],post)["final_state"],"unconfirmed")
                missing=observation(self.output,"exact",at=T3)
                self.assertEqual(publication_receipt(self.plan,[self.attempt(response_remote={key:value})],missing)["final_state"],"unconfirmed")

    def test_all_supplied_remote_identifiers_must_agree_with_readback(self):
        attempt=self.attempt(response_remote={"sequence":2,"etag":"new-etag","commit":"b"*40})
        for remote in ({"sequence":2,"etag":"different","commit":"b"*40},
                       {"sequence":2,"etag":"new-etag"},
                       {"sequence":2,"etag":"new-etag","commit":"a"*40}):
            with self.subTest(remote=remote):
                post=observation(self.output,"exact",at=T3,remote=remote)
                self.assertEqual(publication_receipt(self.plan,[attempt],post)["final_state"],"unconfirmed")
        post=observation(self.output,"exact",at=T1,remote={"sequence":3,"etag":"new-etag","commit":"b"*40})
        self.assertEqual(publication_receipt(self.plan,[attempt],post)["final_state"],"published")
