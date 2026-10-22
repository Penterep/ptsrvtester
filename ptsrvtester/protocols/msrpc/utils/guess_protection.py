from __future__ import annotations

import math
import secrets
import time
from typing import Callable


_EVIDENCE_KEYS = {
    "interface", "rpcBind", "rpcCall", "proxyChannels", "rpcTunnel", "reason", "statusCode",
    "authenticationStatusVerified",
}
_EVIDENCE_ENUMS = {
    "rpcBind": {"not_tested", "accepted", "denied", "unconfirmed"},
    "rpcCall": {"not_tested", "confirmed", "denied", "unconfirmed"},
    "rpcTunnel": {"not_tested", "established", "denied", "unconfirmed"},
}
_OBSERVER_REASONS = {
    "invalid_tested_identity", "observer_not_configured", "observer_must_be_different_account",
    "tested_domain_required_for_observer", "observer_query_failed", "malformed_observer_result",
    "observer_access_denied", "observer_session_not_authenticated", "account_identity_ambiguous",
    "account_identity_not_verified", "account_state_fields_not_returned",
}


def run_guess_protection(
    *,
    username: str,
    password: str,
    attempts: int,
    delay_seconds: float,
    window_seconds: float,
    expect_lockout_after: int | None,
    attempt: Callable[[str], object],
    observe: Callable[[], dict] | None = None,
    progress: Callable[[dict], None] | None = None,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> dict:
    """Require signed RPC confirmation for acceptance and verified lockout statuses.

    Unsigned faults, HTTP permission errors and network failures are inconclusive.
    SAMR counter deltas do not count logical RPC Proxy attempts: one call may
    authenticate more than once. Successful logins during the series would reset
    the tested account's failure counter.
    """
    if not username or not isinstance(password, str):
        raise ValueError("a username and a valid password are required")
    if isinstance(attempts, bool) or not isinstance(attempts, int) or attempts < 1:
        raise ValueError("attempts must be a positive integer")
    if not math.isfinite(delay_seconds) or delay_seconds < 0:
        raise ValueError("delay_seconds must be finite and nonnegative")
    if not math.isfinite(window_seconds) or window_seconds <= 0:
        raise ValueError("window_seconds must be finite and positive")
    if expect_lockout_after is not None and (
        isinstance(expect_lockout_after, bool)
        or not isinstance(expect_lockout_after, int)
        or expect_lockout_after < 1
    ):
        raise ValueError("expect_lockout_after must be a positive integer")

    started_at = clock()
    planned_attempts = min(attempts, expect_lockout_after or attempts)
    secret_values = [password] if password else []
    result = {
        "status": "inconclusive",
        "outcome": "inconclusive",
        "reason": "not_started",
        "username": username,
        "configuredAttempts": attempts,
        "plannedAttempts": planned_attempts,
        "startedAttempts": 0,
        "completedAttempts": 0,
        "confirmedRejections": 0,
        "confirmedRejectionsWithinWindow": 0,
        "ambiguousAttempts": 0,
        "elapsedSeconds": 0.0,
        "windowSeconds": window_seconds,
        "expectedLockoutAfter": expect_lockout_after,
        "baseline": {"outcome": "not_run", "accepted": False, "rejected": False},
        "control": {"outcome": "not_run", "accepted": False, "rejected": False},
        "attempts": [],
    }

    def elapsed(since=started_at):
        return round(max(0.0, clock() - since), 6)

    def clean_string(value):
        for secret in secret_values:
            value = value.replace(secret, "[redacted]")
        return value[:2048]

    def evidence_of(raw):
        if not isinstance(raw, dict):
            return {}
        evidence = {}
        for key in _EVIDENCE_KEYS:
            value = raw.get(key)
            if key == "authenticationStatusVerified":
                if isinstance(value, bool):
                    evidence[key] = value
            elif key == "statusCode":
                if isinstance(value, int) and not isinstance(value, bool):
                    evidence[key] = value
            elif key == "proxyChannels" and isinstance(value, dict):
                evidence[key] = {
                    channel: clean_string(value[channel])
                    for channel in ("in", "out")
                    if isinstance(value.get(channel), str)
                }
            elif isinstance(value, str):
                evidence[key] = value if value in _EVIDENCE_ENUMS.get(key, ()) else clean_string(value)
        return evidence

    def emit(stage, **extra):
        if progress is None:
            return
        event = {
            "stage": stage,
            "username": username,
            "started": result["startedAttempts"],
            "completed": result["completedAttempts"],
            "total": planned_attempts,
            "percent": round(100 * result["completedAttempts"] / planned_attempts, 1),
            "elapsedSeconds": elapsed(),
        }
        event.update(extra)
        try:
            progress(event)
        except Exception:
            # A rendering failure must not trigger an authentication retry.
            result["progressErrors"] = result.get("progressErrors", 0) + 1

    def call(candidate):
        call_started = clock()
        try:
            response = attempt(candidate)
            evidence = evidence_of(getattr(response, "evidence", None))
            accepted = getattr(response, "accepted", False) is True
            rejected = getattr(response, "rejected", False) is True
            locked = getattr(response, "stop_account", False) is True
            outcome = "locked_out" if locked else (
                "accepted" if accepted else "rejected" if rejected else "ambiguous"
            )
            return {
                "outcome": outcome,
                "accepted": accepted,
                "rejected": rejected,
                "evidence": evidence,
                "elapsedSeconds": elapsed(call_started),
            }
        except Exception as exc:
            return {
                "outcome": "ambiguous", "accepted": False, "rejected": False,
                "errorType": type(exc).__name__, "evidence": {},
                "elapsedSeconds": elapsed(call_started),
            }

    def observation():
        if observe is None:
            return None
        try:
            raw = observe()
            if not isinstance(raw, dict):
                return {"status": "invalid", "identityVerified": False}
            item = {
                "status": "complete" if raw.get("status") == "complete" else "inconclusive",
                "identityVerified": raw.get("identityVerified") is True,
            }
            reason = raw.get("reason")
            if isinstance(reason, str) and reason in _OBSERVER_REASONS:
                item["reason"] = reason
            for field in ("sourceHost", "requestedAccount", "requestedDomain", "account", "domain", "sid"):
                value = raw.get(field)
                if isinstance(value, str):
                    item[field] = clean_string(value)
            if raw.get("identitySource") == "SAMR":
                item["identitySource"] = "SAMR"
            source_port = raw.get("sourcePort")
            if isinstance(source_port, int) and not isinstance(source_port, bool) and 1 <= source_port <= 65535:
                item["sourcePort"] = source_port
            if item["status"] == "complete" and item["identityVerified"]:
                if isinstance(raw.get("lockedOut"), bool):
                    item["lockedOut"] = raw["lockedOut"]
                count = raw.get("badPasswordCount")
                if isinstance(count, int) and not isinstance(count, bool) and count >= 0:
                    item["badPasswordCount"] = count
            return item
        except Exception as exc:
            return {"status": "error", "identityVerified": False, "errorType": type(exc).__name__}

    def finish(outcome, reason):
        result["outcome"] = outcome
        result["reason"] = reason
        result["status"] = "complete" if outcome in {
            "protection_observed", "criterion_not_met", "no_blocking_observed",
        } else "inconclusive"
        result["elapsedSeconds"] = elapsed()
        before, after = result.get("observerBefore", {}), result.get("observerAfter", {})
        counts = before.get("badPasswordCount"), after.get("badPasswordCount")
        if all(isinstance(value, int) for value in counts) and counts[1] >= counts[0]:
            result["observedBadPasswordCountDelta"] = counts[1] - counts[0]
        emit("complete", outcome=outcome)
        return result

    def accepted_control(value):
        return value["outcome"] == "accepted" and value["evidence"].get("rpcCall") == "confirmed"

    def observer_verified(value):
        return (
            value.get("status") == "complete"
            and value.get("identityVerified") is True
            and isinstance(value.get("lockedOut"), bool)
        )

    emit("baseline", outcome="running")
    result["baseline"] = call(password)
    emit("baseline", outcome=result["baseline"]["outcome"])
    if not accepted_control(result["baseline"]):
        return finish("baseline_failed", "valid_credentials_not_confirmed_by_signed_rpc")

    before = observation()
    if before is not None:
        result["observerBefore"] = before
        if not observer_verified(before):
            return finish("inconclusive", "observer_baseline_not_verified")
        if before.get("lockedOut") is True:
            return finish("inconclusive", "observer_reports_preexisting_lockout")

    burst_started = clock()
    deadline = burst_started + window_seconds
    stopped_for_lockout = False
    unexpected_acceptance = False
    latest_observation = None
    for index in range(1, planned_attempts + 1):
        if index > 1 and delay_seconds:
            remaining = deadline - clock()
            if remaining <= delay_seconds:
                break
            try:
                sleep(delay_seconds)
            except Exception as exc:
                result["delayErrorType"] = type(exc).__name__
                return finish("inconclusive", "delay_callback_failed")
        if clock() >= deadline:
            break
        candidate = "PtSrvTester-" + secrets.token_hex(24)
        while candidate == password:
            candidate = "PtSrvTester-" + secrets.token_hex(24)
        secret_values.append(candidate)
        result["startedAttempts"] += 1
        emit("attempt", index=index, outcome="running")
        item = call(candidate)
        item["index"] = index
        item["burstElapsedSeconds"] = elapsed(burst_started)
        item["completedWithinWindow"] = clock() <= deadline
        result["completedAttempts"] += 1
        if item["outcome"] == "rejected":
            result["confirmedRejections"] += 1
            if item["completedWithinWindow"]:
                result["confirmedRejectionsWithinWindow"] += 1
        elif item["outcome"] == "ambiguous":
            result["ambiguousAttempts"] += 1
        result["attempts"].append(item)
        emit("attempt", index=index, outcome=item["outcome"])
        if item["outcome"] == "locked_out":
            stopped_for_lockout = True
            break
        if item["accepted"]:
            unexpected_acceptance = True
            break
        latest_observation = observation()
        if latest_observation is not None:
            latest_observation["afterAttempt"] = index
            result["observerAfter"] = latest_observation
            if not observer_verified(latest_observation):
                result["burstElapsedSeconds"] = elapsed(burst_started)
                return finish("inconclusive", "observer_state_not_verified")
            if latest_observation.get("lockedOut") is True:
                stopped_for_lockout = True
                break

    result["burstElapsedSeconds"] = elapsed(burst_started)
    if stopped_for_lockout:
        return finish("protection_observed", "account_lockout_confirmed")
    if unexpected_acceptance:
        return finish("inconclusive", "generated_incorrect_password_was_accepted")

    # Observe counters before the successful control can reset them.
    emit("control", outcome="running")
    result["control"] = call(password)
    emit("control", outcome=result["control"]["outcome"])
    if result["control"]["outcome"] == "locked_out":
        return finish("protection_observed", "account_lockout_confirmed_on_control")
    if not accepted_control(result["control"]):
        return finish("inconclusive", "post_series_valid_credentials_not_confirmed")
    if result["ambiguousAttempts"]:
        return finish("inconclusive", "one_or_more_bad_password_attempts_were_unconfirmed")
    if not result["completedAttempts"]:
        return finish("inconclusive", "observation_window_expired_before_first_attempt")
    if expect_lockout_after is not None and (
        result["confirmedRejectionsWithinWindow"] >= expect_lockout_after
        and result["confirmedRejections"] == result["completedAttempts"]
    ):
        return finish("criterion_not_met", "configured_account_lockout_threshold_not_enforced_within_test_window")
    return finish("no_blocking_observed", "no_account_lockout_observed_in_completed_bad_password_series")
