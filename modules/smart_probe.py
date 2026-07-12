#!/usr/bin/env python3
"""
Smart probe policy for router web default-credential checks.

Tracks per-target:
  - failed attempts
  - lockout detection + unlock time
  - when the next attempt is allowed
  - adaptive max attempts / delay

Persists state via Database helpers when available; falls back to memory.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timedelta
from typing import Optional

# Brand policy: (max_attempts_per_window, min_delay_sec, lockout_seconds_default)
BRAND_POLICY = {
    "ZTE": (3, 1.5, 60),
    "Huawei": (3, 1.5, 60),
    "IAM": (3, 2.0, 60),
    "Inwi": (3, 2.0, 60),
    "OrangeMA": (3, 2.0, 60),
    "Technicolor": (3, 1.5, 60),
    "Sagemcom": (3, 1.5, 60),
    "generic": (5, 1.0, 45),
}

DEFAULT_POLICY = (5, 1.0, 45)


def _parse_dt(value):
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    text = str(value).strip()
    for fmt in (
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%SZ",
    ):
        try:
            return datetime.strptime(text.replace("Z", ""), fmt.replace("Z", ""))
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(text.replace("Z", ""))
    except Exception:
        return None


def policy_for_brand(brand):
    key = brand if brand in BRAND_POLICY else "generic"
    max_attempts, delay, lockout = BRAND_POLICY.get(key, DEFAULT_POLICY)
    return {
        "brand": key,
        "max_attempts": int(max_attempts),
        "delay": float(delay),
        "lockout_seconds": int(lockout),
    }


class SmartProbeAdvisor:
    """Decide whether probing is allowed and how to probe."""

    def __init__(self, db=None):
        self.db = db
        self._memory = {}

    def _mem_get(self, target_ip):
        return self._memory.get(target_ip) or {}

    def _mem_set(self, target_ip, state):
        self._memory[target_ip] = state

    def get_state(self, target_ip):
        target_ip = (target_ip or "").strip()
        if self.db is not None:
            try:
                row = self.db.get_probe_state(target_ip)
                if row:
                    return dict(row)
            except Exception:
                pass
        return self._mem_get(target_ip)

    def save_state(self, target_ip, **fields):
        target_ip = (target_ip or "").strip()
        current = self.get_state(target_ip) or {}
        current.update(fields)
        current["target_ip"] = target_ip
        current["updated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if self.db is not None:
            try:
                self.db.upsert_probe_state(target_ip, current)
            except Exception:
                self._mem_set(target_ip, current)
        else:
            self._mem_set(target_ip, current)
        return current

    def evaluate(self, target_ip, brand="generic"):
        """
        Return a decision dict:
          allowed, reason, wait_seconds, unlock_at, policy, state, recommendation
        """
        policy = policy_for_brand(brand)
        state = self.get_state(target_ip) or {}
        now = datetime.now()

        lockout_until = _parse_dt(state.get("lockout_until"))
        wait_seconds = 0
        allowed = True
        reason = "ok"
        recommendation = "probe_allowed"

        if lockout_until and lockout_until > now:
            wait_seconds = int((lockout_until - now).total_seconds()) + 1
            allowed = False
            reason = "lockout_active"
            recommendation = "wait_then_retry"
        else:
            # Windowed attempt budget (rolling 10 minutes)
            window_start = _parse_dt(state.get("window_started_at"))
            attempts = int(state.get("attempts_in_window") or 0)
            if window_start and (now - window_start) > timedelta(minutes=10):
                attempts = 0
                window_start = now
            if attempts >= policy["max_attempts"] and not (
                lockout_until and lockout_until <= now
            ):
                # Soft cooldown if many attempts even without explicit lockout
                last = _parse_dt(state.get("last_attempt_at"))
                cooldown = policy["lockout_seconds"]
                if last and (now - last).total_seconds() < cooldown:
                    wait_seconds = int(cooldown - (now - last).total_seconds()) + 1
                    allowed = False
                    reason = "attempt_budget_exhausted"
                    recommendation = "wait_cooldown"
                else:
                    # reset window after cooldown elapsed
                    attempts = 0
                    window_start = now

            if allowed and state.get("last_auth_status") == "success":
                recommendation = "already_verified_skip_or_manual"
                reason = "previous_success"

        unlock_at = None
        if wait_seconds > 0:
            unlock_at = (now + timedelta(seconds=wait_seconds)).strftime(
                "%Y-%m-%d %H:%M:%S"
            )

        return {
            "allowed": allowed,
            "reason": reason,
            "wait_seconds": max(0, int(wait_seconds)),
            "unlock_at": unlock_at,
            "policy": policy,
            "state": state,
            "recommendation": recommendation,
            "human": self._human_message(
                allowed, reason, wait_seconds, unlock_at, policy, state
            ),
        }

    @staticmethod
    def _human_message(allowed, reason, wait_seconds, unlock_at, policy, state):
        if allowed and reason == "previous_success":
            return (
                "Previous verified login exists for this IP. "
                "Re-probe only if you intentionally want to retest."
            )
        if allowed:
            return (
                "Probe allowed. Policy: max {max} attempts / window, "
                "delay {delay}s, expected lockout ~{lock}s.".format(
                    max=policy["max_attempts"],
                    delay=policy["delay"],
                    lock=policy["lockout_seconds"],
                )
            )
        if reason == "lockout_active":
            return (
                "Target appears locked. Wait {sec}s (until {until}) before retry.".format(
                    sec=wait_seconds, until=unlock_at or "?"
                )
            )
        if reason == "attempt_budget_exhausted":
            return (
                "Attempt budget exhausted for this window. "
                "Wait {sec}s before more Basic Auth tries.".format(sec=wait_seconds)
            )
        return "Probe not allowed ({reason}).".format(reason=reason)

    def register_attempt_result(
        self,
        target_ip,
        brand="generic",
        status="failed",
        lockout_seconds=None,
        detail="",
    ):
        """Update state after one probe attempt or aggregate probe run."""
        policy = policy_for_brand(brand)
        state = self.get_state(target_ip) or {}
        now = datetime.now()
        window_start = _parse_dt(state.get("window_started_at")) or now
        if (now - window_start) > timedelta(minutes=10):
            window_start = now
            attempts = 0
        else:
            attempts = int(state.get("attempts_in_window") or 0)

        attempts += 1
        fields = {
            "brand": brand,
            "window_started_at": window_start.strftime("%Y-%m-%d %H:%M:%S"),
            "attempts_in_window": attempts,
            "last_attempt_at": now.strftime("%Y-%m-%d %H:%M:%S"),
            "last_auth_status": status,
            "last_detail": (detail or "")[:300],
            "total_attempts": int(state.get("total_attempts") or 0) + 1,
        }

        if status == "lockout":
            pause = int(lockout_seconds or policy["lockout_seconds"])
            fields["lockout_until"] = (now + timedelta(seconds=pause)).strftime(
                "%Y-%m-%d %H:%M:%S"
            )
            fields["lockout_count"] = int(state.get("lockout_count") or 0) + 1
            fields["last_lockout_at"] = now.strftime("%Y-%m-%d %H:%M:%S")
        elif status == "success":
            fields["lockout_until"] = None
            fields["verified_at"] = now.strftime("%Y-%m-%d %H:%M:%S")
        elif status in ("failed", "possible", "skipped"):
            # clear expired lockout
            lockout_until = _parse_dt(state.get("lockout_until"))
            if lockout_until and lockout_until <= now:
                fields["lockout_until"] = None

        return self.save_state(target_ip, **fields)

    def plan_probe(self, target_ip, brand="generic"):
        """High-level plan consumed by RouterExploiter / UI."""
        decision = self.evaluate(target_ip, brand=brand)
        policy = decision["policy"]
        plan = {
            "decision": decision,
            "max_attempts": policy["max_attempts"],
            "delay": policy["delay"],
            "lockout_pause": policy["lockout_seconds"],
            "include_generic": brand in ("generic", "unknown", None, ""),
            "should_probe": bool(decision["allowed"])
            and decision.get("recommendation") != "already_verified_skip_or_manual",
        }
        # If previous success, still allow manual override by UI
        if decision.get("recommendation") == "already_verified_skip_or_manual":
            plan["should_probe"] = False
            plan["suggest_skip"] = True
        else:
            plan["suggest_skip"] = not decision["allowed"]
        return plan
