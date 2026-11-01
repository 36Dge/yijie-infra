"""Pure lifecycle decisions. No real containers, process signals or file faults."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("session", Path(__file__).resolve().parents[1] / "scripts/workflow-session.py")
session = importlib.util.module_from_spec(spec)
spec.loader.exec_module(session)


def exited(code=0, oneoff=False):
    return {"labels": {"com.docker.compose.oneoff": str(oneoff).lower()},
            "state": {"Running": False, "OOMKilled": False, "ExitCode": code}}


class SessionPolicyTest(unittest.TestCase):
    def test_empty_dns_is_stable_across_docker_daemon_restart(self):
        old = {"Dns": None, "DnsOptions": None, "DnsSearch": None, "ReadonlyRootfs": True}
        restored = {"Dns": [], "DnsOptions": [], "DnsSearch": [], "ReadonlyRootfs": True}
        self.assertEqual(session.configuration_hash({}, old), session.configuration_hash({}, restored))

    def test_real_dns_and_other_configuration_changes_remain_distinct(self):
        base = {"Dns": [], "DnsOptions": [], "DnsSearch": [], "ReadonlyRootfs": True}
        for changed in ({**base, "Dns": ["1.1.1.1"]}, {**base, "ReadonlyRootfs": False}):
            self.assertNotEqual(session.configuration_hash({}, base), session.configuration_hash({}, changed))

    def test_clean_primary_and_completed_migrations_are_eligible_for_review(self):
        session.check_restart_states([exited(), exited(oneoff=True)])

    def test_vm_exit_observation_requires_same_storage_review_path(self):
        session.check_restart_states([exited(255), exited(oneoff=True)])

    def test_other_exit_status_stays_blocked(self):
        with self.assertRaises(session.ctl.WorkflowError):
            session.check_restart_states([exited(1)])

    def test_oneoff_is_never_treated_as_restartable_primary(self):
        with self.assertRaises(session.ctl.WorkflowError):
            session.check_restart_states([exited(255, oneoff=True)])

    def test_running_service_is_not_restarted(self):
        item = exited()
        item["state"]["Running"] = True
        with self.assertRaises(session.ctl.WorkflowError):
            session.check_restart_states([item])


if __name__ == "__main__":
    unittest.main()
