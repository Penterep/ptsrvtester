import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from unittest.mock import patch

from ptsrvtester.protocols.msrpc.utils.credential_attempts import (
    iter_credential_attempts,
)


def credential(username, password):
    return SimpleNamespace(username=username, password=password)


def schedule(credentials, attempt, workers=2, stopped_accounts=None):
    return iter_credential_attempts(
        credentials,
        attempt,
        workers=workers,
        account_key=lambda item: item.username.casefold(),
        stop_account=lambda outcome: outcome == "locked",
        stopped_accounts=stopped_accounts,
    )


class CredentialAttemptSchedulerTests(unittest.TestCase):
    def test_lockout_skips_buffered_and_future_passwords_but_other_users_continue(self):
        credentials = [credential("alice", str(index)) for index in range(10)]
        credentials += [credential("bob", "valid"), credential("ALICE", "last")]
        called = []

        def attempt(item):
            called.append((item.username, item.password))
            return "locked" if item.username.casefold() == "alice" else "accepted"

        resolved = sorted(schedule(credentials, attempt), key=lambda item: item.index)
        self.assertEqual(called, [("alice", "0"), ("bob", "valid")])
        self.assertEqual([item.index for item in resolved], list(range(12)))
        self.assertEqual([item.index for item in resolved if item.skipped], [*range(1, 10), 11])
        self.assertEqual(resolved[0].outcome, "locked")
        self.assertEqual(resolved[10].outcome, "accepted")

    def test_lockout_after_rejection_prevents_next_password_for_same_account(self):
        credentials = [credential("alice", str(index)) for index in range(3)]
        called = []

        def attempt(item):
            called.append(item.password)
            return "locked" if item.password == "1" else "rejected"

        resolved = sorted(schedule(credentials, attempt), key=lambda item: item.index)
        self.assertEqual(called, ["0", "1"])
        self.assertEqual([item.skipped for item in resolved], [False, False, True])

    def test_same_account_never_has_concurrent_attempts(self):
        credentials = [credential("alice", str(index)) for index in range(8)]
        credentials += [credential("bob", str(index)) for index in range(8)]
        active = set()
        simultaneous = []
        lock = threading.Lock()

        def attempt(item):
            with lock:
                if item.username in active:
                    simultaneous.append(item.username)
                active.add(item.username)
            try:
                # Yield to other workers while the account is marked active.
                threading.Event().wait(0.005)
                return "rejected"
            finally:
                with lock:
                    active.remove(item.username)

        resolved = list(schedule(credentials, attempt, workers=4))
        self.assertEqual(simultaneous, [])
        self.assertEqual(len(resolved), 16)
        self.assertFalse(any(item.skipped for item in resolved))

    def test_exceptions_do_not_stop_account_and_keep_original_index(self):
        failure = TimeoutError("connection timed out")

        def attempt(item):
            if item.password == "first":
                raise failure
            return "accepted"

        credentials = [credential("alice", "first"), credential("alice", "second")]
        resolved = sorted(schedule(credentials, attempt), key=lambda item: item.index)
        self.assertIs(resolved[0].error, failure)
        self.assertEqual(resolved[1].outcome, "accepted")
        self.assertFalse(any(item.skipped for item in resolved))

    def test_confirmed_lockouts_remain_stopped_in_later_runs(self):
        stopped = set()
        called = []

        def attempt(item):
            called.append(item.username)
            return "locked" if item.username.casefold() == "alice" else "accepted"

        list(schedule([credential("alice", "a")], attempt, stopped_accounts=stopped))
        self.assertEqual(stopped, {"alice"})
        resolved = list(schedule(
            [credential("ALICE", "b"), credential("bob", "b")],
            attempt,
            stopped_accounts=stopped,
        ))
        self.assertEqual(called, ["alice", "bob"])
        self.assertEqual([item.index for item in resolved if item.skipped], [0])

    def test_default_stop_state_is_not_shared_between_independent_runs(self):
        credentials = [credential("alice", "a")]
        list(schedule(credentials, lambda item: "locked"))
        resolved = list(schedule(credentials, lambda item: "accepted"))
        self.assertFalse(resolved[0].skipped)
        self.assertEqual(resolved[0].outcome, "accepted")

    def test_generator_and_submitted_futures_are_bounded(self):
        consumed = []
        consumed_window = threading.Event()
        release = threading.Event()
        submissions = []
        results = []
        errors = []

        class ObservedExecutor(ThreadPoolExecutor):
            def submit(self, fn, *args, **kwargs):
                submissions.append(args[0])
                return super().submit(fn, *args, **kwargs)

        def generated():
            for index in range(20):
                consumed.append(index)
                if len(consumed) == 4:
                    consumed_window.set()
                yield credential(str(index), "password")

        def attempt(item):
            if not release.wait(5):
                raise TimeoutError("test worker was not released")
            return "accepted"

        def run():
            try:
                results.extend(schedule(generated(), attempt))
            except Exception as exc:
                errors.append(exc)

        module = "ptsrvtester.protocols.msrpc.utils.credential_attempts.ThreadPoolExecutor"
        with patch(module, ObservedExecutor):
            thread = threading.Thread(target=run, daemon=True)
            thread.start()
            try:
                self.assertTrue(consumed_window.wait(2))
                self.assertEqual(len(consumed), 4)
                self.assertLessEqual(len(submissions), 2)
            finally:
                release.set()
                thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(sorted(item.index for item in results), list(range(20)))

    def test_completed_results_keep_input_indices_when_workers_finish_out_of_order(self):
        first_can_finish = threading.Event()

        def attempt(item):
            if item.username == "alice":
                if not first_can_finish.wait(5):
                    raise TimeoutError("second attempt never completed")
            return "accepted"

        credentials = [credential("alice", "a"), credential("bob", "b")]
        iterator = schedule(credentials, attempt)
        try:
            second = next(iterator)
            self.assertEqual(second.index, 1)
            self.assertEqual(second.credential.username, "bob")
        finally:
            first_can_finish.set()
        rest = list(iterator)
        self.assertEqual([item.index for item in rest], [0])

    def test_empty_input_and_invalid_worker_count_do_not_run_attempt(self):
        calls = []
        self.assertEqual(list(schedule([], calls.append)), [])
        with self.assertRaises(ValueError):
            list(schedule([credential("alice", "a")], calls.append, workers=0))
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
