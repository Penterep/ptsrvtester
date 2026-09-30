"""Bound credential work and stop an account after a confirmed lockout."""
from __future__ import annotations

from collections import deque
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass
from typing import Callable, Generic, Hashable, Iterable, Iterator, TypeVar


CredentialT = TypeVar("CredentialT")
OutcomeT = TypeVar("OutcomeT")


@dataclass(frozen=True)
class ResolvedAttempt(Generic[CredentialT, OutcomeT]):
    index: int
    credential: CredentialT
    outcome: OutcomeT | None = None
    error: Exception | None = None
    skipped: bool = False


def iter_credential_attempts(
    credentials: Iterable[CredentialT],
    attempt: Callable[[CredentialT], OutcomeT],
    *,
    workers: int,
    account_key: Callable[[CredentialT], Hashable],
    stop_account: Callable[[OutcomeT], bool],
    stopped_accounts: set[Hashable] | None = None,
) -> Iterator[ResolvedAttempt[CredentialT, OutcomeT]]:
    """Yield completed/skipped attempts with their original zero-based index.

    Only one attempt for an account may be in flight. A lockout therefore
    suppresses all its remaining attempts, including work already buffered,
    without having to race worker threads to cancel queued futures. Other
    accounts continue. At most ``2 * workers`` credentials are buffered or
    running, and only ``workers`` futures are submitted at once.

    Completion order may vary; callers can use ``index`` to order their output.
    Account keys and the positive lockout verdict belong to the caller, which
    knows the authentication domain and the transport's status semantics.
    Supplying ``stopped_accounts`` retains confirmed lockouts between sequential
    runs (for example, different credential modules sharing one engine).
    """
    if workers < 1:
        raise ValueError("credential workers must be positive")

    source = enumerate(credentials)
    waiting = deque()
    pending = {}
    active_accounts = set()
    if stopped_accounts is None:
        stopped_accounts = set()
    exhausted = False
    window = workers * 2

    with ThreadPoolExecutor(max_workers=workers) as executor:
        while True:
            while not exhausted and len(waiting) + len(pending) < window:
                try:
                    index, credential = next(source)
                except StopIteration:
                    exhausted = True
                    break
                account = account_key(credential)
                if account in stopped_accounts:
                    yield ResolvedAttempt(index, credential, skipped=True)
                else:
                    waiting.append((index, credential, account))

            for _ in range(len(waiting)):
                index, credential, account = waiting.popleft()
                if account in stopped_accounts:
                    yield ResolvedAttempt(index, credential, skipped=True)
                elif account not in active_accounts and len(pending) < workers:
                    future = executor.submit(attempt, credential)
                    pending[future] = (index, credential, account)
                    active_accounts.add(account)
                else:
                    waiting.append((index, credential, account))

            if not pending:
                if exhausted:
                    return
                continue

            completed, _ = wait(pending, return_when=FIRST_COMPLETED)
            for future in sorted(completed, key=lambda item: pending[item][0]):
                index, credential, account = pending.pop(future)
                active_accounts.remove(account)
                try:
                    outcome = future.result()
                except Exception as exc:
                    yield ResolvedAttempt(index, credential, error=exc)
                    continue
                if stop_account(outcome):
                    stopped_accounts.add(account)
                yield ResolvedAttempt(index, credential, outcome=outcome)
