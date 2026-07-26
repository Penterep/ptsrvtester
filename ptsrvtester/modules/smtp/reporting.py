

try:
    from ntlm_auth.ntlm import NtlmContext
except ImportError:
    NtlmContext = None

from ..utils import ptprinthelper
from ..utils.service_identification import identify_service

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa
    _HAS_CRYPTOGRAPHY = True
except ImportError:
    _HAS_CRYPTOGRAPHY = False

from .helpers import *
from .results import *
from .registry import *


class ReportingMixin:

    @staticmethod
    def _mail_variant_msg_summary(
        smtp_trace: tuple[str, ...],
        *,
        accepted: int,
        rejected: int,
        error: int,
    ) -> tuple[str, ...]:
        """One-line outcome per variant (same style as -av message_summary)."""
        if error and not accepted and not rejected:
            for line in reversed(smtp_trace):
                if line.startswith(("error:", "Connect:")):
                    return (line,)
            return ("error",)
        if accepted:
            for line in reversed(smtp_trace):
                if line.startswith("DATA:"):
                    code = self._data_trace_status_code(line)
                    if code:
                        return (f"DATA: {code} (accepted)",)
        if rejected:
            for line in reversed(smtp_trace):
                if line.startswith("RCPT TO"):
                    parts = line.split(":", 1)[1].strip().split()
                    if parts:
                        return (f"RCPT: {parts[0]} (rejected)",)
                if line.startswith("MAIL FROM"):
                    parts = line.split(":", 1)[1].strip().split()
                    if parts and parts[0] not in ("250", "251"):
                        return (f"MAIL FROM: {parts[0]} (rejected)",)
                if line.startswith("DATA:"):
                    code = self._data_trace_status_code(line)
                    if code:
                        return (f"DATA: {code} (rejected)",)
        return ()

    # endregion

    # region output

    def _is_node_based_output(self) -> bool:
        """Node-based tests: run_all, banner, enumerate, bruteforce."""
        if getattr(self, "run_all_mode", False):
            return True
        if self.results.banner_requested:
            return True
        if self.results.enum_results is not None or self.results.enum_error is not None:
            return True
        if self.results.creds is not None:
            return True
        return False

    def _is_enum_only_output(self) -> bool:
        """Enumeration-only: no software node, just userAccount nodes + global vulns."""
        if getattr(self, "run_all_mode", False):
            return False
        if self.results.banner_requested:
            return False
        if self.results.commands_requested:
            return False
        if self.results.creds is not None:
            return False
        if self.results.ntlm is not None or self.results.ntlm_error is not None:
            return False
        return self.results.enum_results is not None or self.results.enum_error is not None

    @staticmethod
    def _ehlo_commands_for_flat(ehlo_raw: str | None, ehlo_starttls_raw: str | None) -> list[str]:
        """Extract EHLO extension names (excluding AUTH methods) for flat JSON description."""
        seen: set[tuple[str, bool]] = set()
        result: list[str] = []
        for raw, encrypted in ((ehlo_raw, False), (ehlo_starttls_raw, True)):
            if not raw:
                continue
            for display, _level in _parse_ehlo_commands(raw, connection_encrypted=encrypted):
                key = display.split()[0].upper() if display else ""
                if key == "AUTH":
                    continue
                if (display, encrypted) not in seen:
                    seen.add((display, encrypted))
                    label = "(STARTTLS) " if encrypted and ehlo_raw else ""
                    result.append(f"{label}{display}")
        return result

    @staticmethod
    def _ehlo_auth_for_flat(ehlo_raw: str | None, ehlo_starttls_raw: str | None) -> list[str]:
        """Extract AUTH methods only for flat JSON description (same format as commands)."""
        seen: set[tuple[str, bool]] = set()
        result: list[str] = []
        for raw, encrypted in ((ehlo_raw, False), (ehlo_starttls_raw, True)):
            if not raw:
                continue
            for display, _level in _parse_ehlo_commands(raw, connection_encrypted=encrypted):
                key = display.split()[0].upper() if display else ""
                if key != "AUTH":
                    continue
                if (display, encrypted) not in seen:
                    seen.add((display, encrypted))
                    label = "(STARTTLS) " if encrypted and ehlo_raw else ""
                    result.append(f"{label}{display}")
        return result

    @staticmethod
    def _bounce_replay_trace_line_clean(line: str) -> str:
        if line.startswith("---") and line.endswith("---"):
            return line.strip("- ").strip()
        return line

    def _bounce_replay_flat_description(self, br: BounceReplayResult) -> str:
        if br.smtp_trace:
            return "\r\n".join(
                self._bounce_replay_trace_line_clean(l) for l in br.smtp_trace
            )
        return br.detail or "Bounce replay test"

    def _build_flat_description(self) -> str:
        """Build description string for flat (non-node) JSON output."""
        parts: list[str] = []

        if (ic_err := self.results.inv_comm_error) is not None:
            return f"Invalid commands test error: {ic_err}"
        if (ic := self.results.inv_comm) is not None:
            return ic.detail or "Invalid commands test"
        if (ho_err := self.results.helo_only_error) is not None:
            return f"HELO-only test error: {ho_err}"
        if (ho := self.results.helo_only) is not None:
            return ho.detail or "HELO-only test"
        if (hb_err := self.results.helo_bypass_error) is not None:
            return f"HELO bypass test error: {hb_err}"
        if (hb := self.results.helo_bypass) is not None:
            return hb.detail or "HELO bypass test"
        if (id_err := self.results.identify_error) is not None:
            return f"Server identification error: {id_err}"
        if (id_r := self.results.identify) is not None:
            return f"Server identification: {id_r.product or 'Unknown'} ({id_r.confidence_pct}%)"
        if (br_err := self.results.bounce_replay_error) is not None:
            return f"Bounce replay test error: {br_err}"
        if (br := self.results.bounce_replay) is not None:
            return self._bounce_replay_flat_description(br)
        if (mb_err := self.results.mail_bomb_error) is not None:
            return f"Mail bomb test error: {mb_err}"
        if (mb := self.results.mail_bomb) is not None:
            return mb.detail or "Mail bomb / rate limiting test (PTL-SVC-SMTP-BOMB)"
        if (av_err := self.results.antivirus_error) is not None:
            return f"Antivirus test error: {av_err}"
        if (av := self.results.antivirus) is not None:
            return av.detail or "Antivirus / antispam test (PTL-SVC-SMTP-ANTIVIRUS)"
        if (sh_err := self.results.spoof_header_error) is not None:
            return f"Spoof header test error: {sh_err}"
        if (sh := self.results.spoof_header) is not None:
            return sh.detail or "Header spoofing test"
        if (bc_err := self.results.bcc_test_error) is not None:
            return f"BCC test error: {bc_err}"
        if (bc := self.results.bcc_test) is not None:
            return bc.detail or "BCC disclosure test – manual verification required"
        if (al_err := self.results.alias_test_error) is not None:
            return f"Alias test error: {al_err}"
        if (al := self.results.alias_test) is not None:
            return al.detail or "Alias bypass test – manual verification required"
        if (ad_err := self.results.auth_downgrade_error) is not None:
            return f"AUTH downgrade test error: {ad_err}"
        if (ad := self.results.auth_downgrade) is not None:
            if ad.indeterminate:
                return ad.detail or "Indeterminate"
            if ad.info_defensive:
                return ad.detail or "AUTH disappeared (defensive reaction)"
            if ad.vulnerable:
                return ad.detail or f"Authentication downgrade: {ad.methods_before} -> {ad.methods_after}"
            return ad.detail or "No authentication downgrade detected"

        if (af_err := self.results.auth_format_error) is not None:
            return f"AUTH format probe error: {af_err}"
        if (af := self.results.auth_format) is not None:
            return f"{af.conclusion} [{af.conclusion_id}]"

        if (ae := self.results.auth_enum) is not None:
            if ae.indeterminate:
                return ae.detail or "Indeterminate"
            if ae.vulnerable:
                base = ae.detail or "User enumeration via AUTH without password knowledge"
                if ae.enumerated_users:
                    return f"{base}; enumerated: {', '.join(ae.enumerated_users)}"
                return base
            if ae.detail:
                return ae.detail
            return "Server does not allow user enumeration via AUTH, or no valid/differentiated user in -u / -U"
        if self.results.auth_enum_error is not None:
            return f"AUTH enumeration error: {self.results.auth_enum_error}"

        if (hv := self.results.helo_validation) is not None:
            if hv.indeterminate:
                return hv.detail or "Indeterminate"
            parts_hv = [hv.detail or ""]
            if hv.accepted_vectors:
                parts_hv.append(f"accepted_vectors: {hv.accepted_vectors}")
            if hv.rejected_vectors:
                parts_hv.append(f"rejected_vectors: {hv.rejected_vectors}")
            if hv.ehlo_comparison:
                parts_hv.append(f"ehlo_comparison: {hv.ehlo_comparison}")
            return "\r\n".join(parts_hv)
        if self.results.helo_validation_error is not None:
            return f"HELO validation error: {self.results.helo_validation_error}"

        if self.results.authentications_requested:
            info = self.results.info
            if info is not None:
                auth_lines = self._ehlo_auth_for_flat(info.ehlo, info.ehlo_starttls)
                if auth_lines:
                    return "\r\n".join(auth_lines)
            return ""

        if self.results.commands_requested:
            info = self.results.info
            if info is not None:
                cmd_lines = self._ehlo_commands_for_flat(info.ehlo, info.ehlo_starttls)
                if cmd_lines:
                    parts.extend(cmd_lines)

        if (enc := self.results.encryption) is not None:
            method_names = []
            if enc.plaintext_ok:
                method_names.append("Plaintext")
            if enc.starttls_ok:
                method_names.append("STARTTLS")
            if enc.tls_ok:
                method_names.append("TLS")
            if method_names:
                parts.append(f"Available methods: {', '.join(method_names)}")

        if getattr(self.args, "smtp_role", None):
            parts.append(f"Declared server role (--role): {self.args.smtp_role}")

        if (role_r := self.results.role) is not None:
            parts.append(f"Identified role: {role_r.role}")
            if role_r.detail:
                parts.append(role_r.detail)
        elif (role_err := self.results.role_error) is not None:
            parts.append(f"Role error: {role_err}")

        if (rlim := self.results.rcpt_limit) is not None:
            # Pre-check context (role / open relay) — visible in JSON description for analysts.
            if getattr(rlim, "role", None):
                role_bits = [f"Role: {rlim.role}"]
                ar = getattr(rlim, "auth_required", None)
                if ar is True:
                    role_bits.append("AUTH required")
                elif ar is False:
                    role_bits.append("AUTH not required")
                if getattr(rlim, "auth_used", False):
                    role_bits.append("authenticated probe")
                _or = getattr(rlim, "open_relay", None)
                if _or is True:
                    role_bits.append("open relay")
                elif _or is False:
                    role_bits.append("not open relay")
                parts.append(", ".join(role_bits))
            if getattr(rlim, "skipped", False):
                parts.append(
                    f"RCPT TO limit test skipped: {getattr(rlim, 'skip_message', None) or rlim.skip_reason}"
                )
            elif getattr(rlim, "session_limit_triggered", False):
                failed = getattr(rlim, "failed_before_limit", 0)
                parts.append(f"Session limit enforced after {failed} failed RCPTs")
            elif getattr(rlim, "rejected_addresses", False) and getattr(rlim, "no_session_limit", False):
                parts.append(f"Server rejects test addresses: {rlim.server_response}")
                failed = getattr(rlim, "failed_before_limit", 0)
                parts.append(
                    f"Could not test per-message limit: allowed {failed} failed RCPTs without disconnect "
                    "(policy rejects, session not closed)"
                )
            elif rlim.limit_triggered:
                parts.append(
                    f"Max {rlim.max_accepted} recipients per message (next recipients are rejected)"
                )
                disc = getattr(rlim, "disconnect_after_limit", None)
                if disc is True:
                    parts.append("Connection was disconnected after many invalid recipients")
                elif disc is False:
                    parts.append("Connection is not disconnected after many invalid recipients")
            else:
                if rlim.max_accepted == 0:
                    parts.append("Could not determine RCPT limit")
                else:
                    parts.append(f"No limit detected (tested {rlim.max_accepted} recipients)")
        elif (rcpt_err := self.results.rcpt_limit_error) is not None:
            parts.append(f"RCPT limit error: {rcpt_err}")

        if (rdd_err := self.results.rcpt_duplicate_error) is not None:
            if _rcpt_duplicate_error_is_environmental(rdd_err):
                parts.append(
                    f"Duplicate RCPT probe could not run (server policy / auth): {rdd_err}"
                )
            else:
                parts.append(f"Duplicate RCPT probe error: {rdd_err}")
        elif (rdd := self.results.rcpt_duplicate) is not None:
            bits = [
                f"Duplicate RCPT TO: {rdd.duplicate_count}× same recipient ({rdd.recipient}) "
                f"in one MAIL transaction",
            ]
            if rdd.all_rcpt_2xx:
                bits.append("All RCPT replies were 2xx (server accepted each duplicate RCPT)")
            elif rdd.first_failure_index is not None:
                i = rdd.first_failure_index
                c = rdd.rcpt_replies[i][0] if i < len(rdd.rcpt_replies) else "?"
                bits.append(f"First non-2xx RCPT at position {i + 1} (code {c})")
            if rdd.data_sent:
                bits.append(
                    f"DATA submitted (probe {rdd.probe_uuid or 'n/a'}); verify inbox manually for copy count"
                )
            elif getattr(self.args, "send", False):
                bits.append("DATA not sent (not all RCPT were 2xx or DATA failed)")
            if rdd.all_rcpt_2xx and rdd.duplicate_count >= 3:
                bits.append(
                    "PTV-SVC-SMTP-RCPTDUP: With sound DATA handling expect one mailbox copy; several "
                    "copies = amplification risk. Check Delivered-To / Received for duplicate routing "
                    "even if only one message arrived."
                )
            parts.append("\r\n".join(bits))

        if (adp_err := self.results.accepted_domain_probe_error) is not None:
            parts.append(f"Accepted recipient domain probe error: {adp_err}")
        elif (adp := self.results.accepted_domain_probe) is not None:
            if adp.domain:
                parts.append(
                    f"Accepted recipient domain: {adp.domain} (confidence: {adp.confidence})"
                )
                if getattr(adp, "likely_placeholder_domain", False):
                    parts.append(
                        "Likely placeholder/example domain (common default configuration), "
                        "not necessarily an operational recipient namespace"
                    )
            else:
                parts.append(adp.detail or "Accepted recipient domain: not determined")

        if (open_relay := self.results.open_relay) is not None:
            pass  # description empty per JSON pattern (vuln code speaks for itself)
        elif (or_err := self.results.open_relay_error) is not None:
            parts.append(f"Open relay error: {or_err}")

        if (blacklist := self.results.blacklist) is not None:
            if blacklist.listed and (bl_results := blacklist.results):
                bl_lines = [f'{r.blacklist.strip()}: "{r.reason}" (TTL={r.ttl})' for r in bl_results]
                parts.append("\r\n".join(bl_lines))
            elif not blacklist.listed:
                parts.append("Not listed on any blacklist")
        elif self.results.blacklist_private_ip_skipped:
            parts.append("Blacklist check skipped (private IP)")

        if (nf1 := self.results.noop_flood1) is not None:
            nf1_parts = [
                f"Commands sent: {nf1.commands_sent} (ok={nf1.commands_ok}, err={nf1.commands_error})",
            ]
            if nf1.disconnected and nf1.disconnect_after is not None:
                nf1_parts.append(f"Disconnect after: {nf1.disconnect_after} NOOP commands")
            else:
                nf1_parts.append("Disconnect: none observed")
            if nf1.avg_rt_seconds is not None:
                nf1_parts.append(
                    "Time between commands: "
                    f"{_noop_rt_window_display(nf1.min_rt_seconds)} - "
                    f"{_noop_rt_window_display(nf1.max_rt_seconds)} "
                    f"(avg {_noop_rt_window_display(nf1.avg_rt_seconds)})"
                )
            nf1_parts.append(f"Slowdown detected: {'yes' if nf1.slowdown_detected else 'no'}")
            nf1_parts.append(f"Error rate: {nf1.error_rate_pct:.0f}%")
            parts.append("\r\n".join(nf1_parts))
        elif (nf1_err := self.results.noop_flood1_error) is not None:
            parts.append(f"NOOP flood (1 connection) error: {nf1_err}")

        if (nf2 := self.results.noop_flood2) is not None:
            nf2_parts = [
                f"Connections: {nf2.established_connections}/{nf2.requested_connections}",
                f"Duration: {nf2.run_duration_seconds:.0f}s",
                f"Commands sent: {nf2.commands_sent} "
                f"(ok={nf2.commands_ok}, err={nf2.commands_error})",
            ]
            if nf2.avg_rt_seconds is not None:
                nf2_parts.append(
                    "Time between commands: "
                    f"{_noop_rt_window_display(nf2.min_rt_seconds)} - "
                    f"{_noop_rt_window_display(nf2.max_rt_seconds)} "
                    f"(avg {_noop_rt_window_display(nf2.avg_rt_seconds)})"
                )
            nf2_parts.append(f"Error rate: {nf2.error_rate_pct:.0f}%")
            if nf2.reaped_before_storm > 0:
                nf2_parts.append(
                    f"Dropped while idle: {nf2.reaped_before_storm} "
                    f"(storm pool {nf2.storm_pool_connections})"
                )
            if nf2.early_exit_no_connections:
                nf2_parts.append(
                    "Server disconnected all connections before test time limit"
                )
            nf2_storm_base = nf2.storm_pool_connections or nf2.established_connections
            if nf2_storm_base > 0 and nf2.disconnected_during_test > 0:
                pct = 100.0 * nf2.disconnected_during_test / nf2_storm_base
                nf2_parts.append(
                    "Disconnected during test: "
                    f"{nf2.disconnected_during_test} from "
                    f"{nf2_storm_base} ({pct:.0f}%)"
                )
            parts.append("\r\n".join(nf2_parts))
        elif (nf2_err := self.results.noop_flood2_error) is not None:
            parts.append(f"NOOP flood DoS error: {nf2_err}")

        if rl := self.results.rate_limit:
            rl_parts = []
            rl_parts.append(f"Connected: {rl.connected if rl.connected is not None else 'N/A'}")
            # Ban duration is only meaningful when we ran the ban-duration probe.
            if rl.ban_duration_probe_ran:
                if rl.ban_duration_seconds is not None:
                    rl_parts.append(
                        "Ban duration: "
                        + _rate_limit_duration_display(
                            rl.ban_duration_seconds,
                            rl.ban_duration_exceeded,
                        )
                    )
                else:
                    rl_parts.append("Ban duration: N/A")
            if rl.initial_timeout_seconds is not None:
                rl_parts.append(
                    "Initial response timeout (without EHLO): "
                    + _rate_limit_duration_display(
                        rl.initial_timeout_seconds,
                        rl.initial_timeout_exceeded,
                    )
                )
            if rl.idle_timeout_seconds is not None:
                rl_parts.append(
                    "Idle timeout (after EHLO): "
                    + _rate_limit_duration_display(
                        rl.idle_timeout_seconds,
                        rl.idle_timeout_exceeded,
                    )
                )
            parts.append("\r\n".join(rl_parts))
        elif (rl_err := self.results.rate_limit_error) is not None:
            parts.append(f"Rate limiting error: {rl_err}")

        if (ntlm := self.results.ntlm) is not None and ntlm.ntlm is not None:
            n = ntlm.ntlm
            ntlm_lines = [
                f"Target name: {n.target_name}",
                f"NetBios domain name: {n.netbios_domain}",
                f"NetBios computer name: {n.netbios_computer}",
                f"DNS domain name: {n.dns_domain}",
                f"DNS computer name: {n.dns_computer}",
                f"DNS tree: {n.dns_tree}",
                f"OS version: {n.os_version}",
            ]
            parts.append("\r\n".join(ntlm_lines))
        elif self.results.ntlm_error is not None:
            parts.append(f"NTLM error: {self.results.ntlm_error}")

        if self.results.spf_requires_domain:
            parts.append("SPF check requires domain name")
        elif (spf_records := self.results.spf_records) is not None:
            spf_lines = []
            for ns, records in spf_records.items():
                for r in records:
                    spf_lines.append(f"[{ns}] {r}")
            if spf_lines:
                parts.append("\r\n".join(spf_lines))

        return "\r\n".join(parts) if parts else ""

    def _collect_flat_vulns(self) -> list[dict]:
        """Collect global vulnerabilities for flat (non-node) JSON output."""
        vulns: list[dict] = []

        if self.results.authentications_requested:
            info = self.results.info
            if info is not None and info.ehlo:
                for display, level in _parse_ehlo_commands(info.ehlo, connection_encrypted=False):
                    if display.upper().startswith("AUTH ") and level == "ERROR":
                        vulns.append({"vuln_code": VULNS.AuthMethods.value})
                        break
            return vulns

        _CMD_VULN_MAP = {
            "ATRN": VULNS.CmdATRN.value,
            "DEBUG": VULNS.CmdDEBUG.value,
            "ETRN": VULNS.CmdETRN.value,
            "EXPN": VULNS.CmdEXPN.value,
            "SAML": VULNS.CmdSAML.value,
            "SEND": VULNS.CmdSEND.value,
            "SOML": VULNS.CmdSOML.value,
            "TURN": VULNS.CmdTURN.value,
            "VERB": VULNS.CmdVERB.value,
            "VRFY": VULNS.CmdVRFY.value,
        }
        if self.results.commands_requested:
            info = self.results.info
            seen_vuln_codes: set[str] = set()
            if info is not None:
                for raw, encrypted in ((info.ehlo, False), (info.ehlo_starttls, True)):
                    if not raw:
                        continue
                    for display, level in _parse_ehlo_commands(raw, connection_encrypted=encrypted):
                        key = display.split()[0].upper() if display else ""
                        if key == "AUTH":
                            continue
                        vc = _CMD_VULN_MAP.get(key)
                        if vc is None and key == "SIZE" and level == "ERROR":
                            vc = VULNS.BigSize.value
                        if vc is None and key == "STARTTLS" and "is not allowed" in display:
                            vc = VULNS.NoStarttls.value
                        if vc and vc not in seen_vuln_codes:
                            seen_vuln_codes.add(vc)
                            vulns.append({"vuln_code": vc})

        if (enc := self.results.encryption) is not None:
            if enc.plaintext_ok:
                vulns.append({"vuln_code": VULNS.CryptOnly.value})

        if (role_r := self.results.role) is not None:
            if role_r.role == "hybrid":
                vulns.append({"vuln_code": VULNS.HybridRole.value})

        if self.results.open_relay:
            vulns.append({"vuln_code": VULNS.OpenRelay.value})

        if (blacklist := self.results.blacklist) is not None:
            if blacklist.listed:
                vulns.append({"vuln_code": VULNS.Blacklist.value})

        if (nf1 := self.results.noop_flood1) is not None:
            # No disconnect, or disconnect only after far too many NOOPs.
            if not nf1.disconnected or (
                nf1.disconnect_after is not None
                and nf1.disconnect_after > NOOP_FLOOD_DISCONNECT_OK_MAX
            ):
                vulns.append({"vuln_code": VULNS.NoopFloodNoLimit.value})
            # Enough samples to judge time-trolling and we did not see it.
            if (
                nf1.baseline_avg_seconds is not None
                and nf1.last_window_avg_seconds is not None
                and nf1.commands_ok >= 20
                and not nf1.slowdown_detected
            ):
                vulns.append({"vuln_code": VULNS.NoopFloodNoTrottle.value})
            if nf1.error_rate_pct > NOOP_FLOOD_ERROR_RATE_OK_MAX_PCT:
                vulns.append({"vuln_code": VULNS.NoopFloodErrors.value})

        if (nf2 := self.results.noop_flood2) is not None:
            if (
                nf2.avg_rt_seconds is not None
                and nf2.avg_rt_seconds > NOOP_FLOOD2_AVG_TIME_OK_MAX_SECONDS
            ):
                vulns.append({"vuln_code": VULNS.NoopFloodDosSlow.value})
            if nf2.error_rate_pct > NOOP_FLOOD_ERROR_RATE_OK_MAX_PCT:
                vulns.append({"vuln_code": VULNS.NoopFloodDosErrors.value})
            # All sockets cut by the server before the time-budget elapsed —
            # the storm itself is enough to take the listener offline.
            if nf2.early_exit_no_connections:
                vulns.append({"vuln_code": VULNS.NoopFloodDosDropAll.value})

        if rl := self.results.rate_limit:
            if rl.connected is not None and rl.connected >= RATE_LIMIT_CONN_VULN_THRESHOLD:
                vulns.append({"vuln_code": VULNS.ManyConns.value})
            # Ban was triggered but lifted too quickly — only when ban-duration was measured.
            if (
                rl.ban_duration_probe_ran
                and rl.ban_duration_seconds is not None
                and not rl.ban_duration_exceeded
                and rl.ban_duration_seconds < RATE_LIMIT_BAN_MIN_SECONDS
            ):
                vulns.append({"vuln_code": VULNS.BanDurationShort.value})
            # Banner-only (pre-EHLO) idle timeout too long.
            if rl.initial_timeout_seconds is not None and (
                rl.initial_timeout_exceeded
                or rl.initial_timeout_seconds > RATE_LIMIT_INITIAL_TIMEOUT_MAX_SECONDS
            ):
                vulns.append({"vuln_code": VULNS.InitialTimeoutLong.value})
            # Post-EHLO idle timeout too long.
            if rl.idle_timeout_seconds is not None and (
                rl.idle_timeout_exceeded
                or rl.idle_timeout_seconds > RATE_LIMIT_IDLE_TIMEOUT_MAX_SECONDS
            ):
                vulns.append({"vuln_code": VULNS.IdleTimeoutLong.value})

        if (ntlm := self.results.ntlm) is not None and ntlm.ntlm is not None:
            vulns.append({"vuln_code": VULNS.NTLM.value})

        if (ae := self.results.auth_enum) is not None and ae.vulnerable:
            ae_entry: dict = {"vuln_code": VULNS.UserEnumAUTH.value}
            if ae.enumerated_users:
                ae_entry["enumerated_users"] = list(ae.enumerated_users)
            vulns.append(ae_entry)

        if (ad := self.results.auth_downgrade) is not None and ad.vulnerable:
            vulns.append({"vuln_code": VULNS.AuthDowngrade.value})

        if (hv := self.results.helo_validation) is not None and (hv.vulnerable or hv.ehlo_bypass):
            vulns.append({"vuln_code": VULNS.HeloNoValidation.value})

        if (ic := self.results.inv_comm) is not None and ic.vulnerable:
            vulns.append({"vuln_code": VULNS.InvComm.value})

        if (ho := self.results.helo_only) is not None and ho.vulnerable:
            vulns.append({"vuln_code": VULNS.HeloOnly.value})

        if (hb := self.results.helo_bypass) is not None and hb.vulnerable:
            vulns.append({"vuln_code": VULNS.HeloBypass.value})

        if (br := self.results.bounce_replay) is not None and (
            br.message_accepted or getattr(br, "message_accepted_return_path", False)
        ):
            vulns.append({"vuln_code": VULNS.BounceReplay.value})

        if (mb := self.results.mail_bomb) is not None and mb.vulnerable:
            vulns.append(
                {
                    "vuln_code": VULNS.Bomb.value,
                    "vuln_request": f"Flood of {mb.sent} messages to {self.args.rcpt_to}",
                    "vuln_response": mb.detail or "",
                }
            )

        if (av := self.results.antivirus) is not None and av.vulnerable:
            vulns.append(
                {
                    "vuln_code": VULNS.Antivirus.value,
                    "vuln_request": f"E-mail with malicious content to {self.args.rcpt_to}",
                    "vuln_response": av.detail or "Risky content accepted at MTA",
                }
            )

        if (sh := self.results.spoof_header) is not None and sh.vulnerable:
            vulns.append(
                {
                    "vuln_code": VULNS.SpoofHeader.value,
                    "vuln_request": f"E-mail with spoofed From/Reply-To/Return-Path headers to {self.args.rcpt_to}",
                    "vuln_response": sh.detail or "Message accepted (250 OK) – server delivers spoofed headers",
                    "vuln_note": sh.vulnerable_note,
                }
            )

        return vulns

    def _rcpt_limit_for_json(self, *, rcpt_vuln_detail: bool = False) -> tuple[dict, list[dict]]:
        """RCPT TO limit (-rl) for JSON: property fragment (node-based scans only) + vulnerabilities.

        Flat standalone ``-rl -j`` keeps only ``description`` (from ``_build_flat_description``) in
        ``properties`` and minimal ``vulnerabilities`` entries (``vuln_code`` only). Structured
        ``rcptLimit`` keys are merged into the software node properties when ``output()`` uses the
        node-based branch.

        When ``rcpt_vuln_detail`` is true (node-based ``output()``), ``ManyRcptReject`` entries
        include ``vuln_request`` / ``vuln_response`` like the software-node JSON.

        ``PTV-SVC-SMTP-MANYRCPT`` is emitted only when ``maxAccepted`` exceeds 500 (strictly).
        """
        props: dict = {}
        vulns: list[dict] = []
        rcptmax_advertised = None
        if (info := getattr(self.results, "info", None)) and getattr(info, "ehlo", None):
            rcptmax_advertised = _parse_rcptmax_from_ehlo(info.ehlo)
        if (rcpt_limit_err := self.results.rcpt_limit_error) is not None:
            if rcptmax_advertised is not None:
                props["rcptLimitAdvertised"] = rcptmax_advertised
            props["rcptLimitError"] = rcpt_limit_err
            return props, vulns
        if (rlim := self.results.rcpt_limit) is None:
            return props, vulns
        if rcptmax_advertised is not None:
            props["rcptLimitAdvertised"] = rcptmax_advertised

        # Pre-check context (role + open-relay verdict + auth) is recorded for *every* outcome so
        # the JSON consumer always knows in which configuration the result was produced.
        precheck_obj: dict = {}
        if getattr(rlim, "role", None):
            precheck_obj["role"] = rlim.role
        ar = getattr(rlim, "auth_required", None)
        if ar is not None:
            precheck_obj["authRequired"] = bool(ar)
        if getattr(rlim, "auth_used", False):
            precheck_obj["authUsed"] = True
        if getattr(rlim, "open_relay", None) is not None:
            precheck_obj["openRelay"] = bool(rlim.open_relay)
        if getattr(rlim, "recipients_source", None):
            precheck_obj["recipientsSource"] = rlim.recipients_source
        if getattr(rlim, "accept_all_via_rcpt", False):
            precheck_obj["acceptAllViaRcpt"] = True
        if getattr(rlim, "limit_send_mode", False):
            precheck_obj["limitSendMode"] = True
        if getattr(rlim, "limit_send_attempted", False):
            precheck_obj["limitSend"] = {
                "mailFrom": getattr(rlim, "limit_send_mail_from", None),
                "dataAccepted": bool(getattr(rlim, "limit_send_ok", False)),
                "dataCode": getattr(rlim, "limit_send_data_code", None),
                "dataReply": getattr(rlim, "limit_send_data_reply", None),
                "acceptedRcptCount": rlim.max_accepted,
            }
        if (bounce_mb := getattr(rlim, "catch_all_bounce_mailbox", None)):
            precheck_obj["catchAllBounceMailbox"] = bounce_mb
        if getattr(rlim, "catch_all_delivery_attempted", False):
            precheck_obj["catchAllBounceProbe"] = {
                "probeRcpt": getattr(rlim, "catch_all_delivery_rcpt", None),
                "mailFrom": getattr(rlim, "catch_all_bounce_mailbox", None),
                "dataAccepted": bool(getattr(rlim, "catch_all_delivery_data_ok", False)),
                "probeUuid": getattr(rlim, "catch_all_probe_uuid", None),
            }

        # Skipped: emit a structured record but no vulnerability code.
        if getattr(rlim, "skipped", False):
            skip_obj: dict = {
                "skipped": True,
                "skipReason": getattr(rlim, "skip_reason", None),
                "skipMessage": getattr(rlim, "skip_message", None),
            }
            if precheck_obj:
                skip_obj["precheck"] = precheck_obj
            props["rcptLimit"] = skip_obj
            return props, vulns

        if getattr(rlim, "session_limit_triggered", False):
            props["rcptLimit"] = {
                "sessionLimitTriggered": True,
                "failedBeforeLimit": getattr(rlim, "failed_before_limit", 0),
                "maxAccepted": rlim.max_accepted,
                "serverResponse": rlim.server_response,
                **({"precheck": precheck_obj} if precheck_obj else {}),
            }
            return props, vulns
        if getattr(rlim, "rejected_addresses", False):
            rcpt_obj: dict = {"rejectedAddresses": True, "serverResponse": rlim.server_response}
            if getattr(rlim, "no_session_limit", False):
                rcpt_obj["manyRcptReject"] = True
                rcpt_obj["failedBeforeLimit"] = getattr(rlim, "failed_before_limit", 0)
                if rcpt_vuln_detail:
                    fb = rcpt_obj["failedBeforeLimit"]
                    vulns.append(
                        {
                            "vuln_code": VULNS.ManyRcptReject.value,
                            "vuln_request": "RCPT TO limit test (policy rejects without session close)",
                            "vuln_response": (
                                f"Could not test per-message limit: server rejects {fb} tested addresses "
                                f"(allowed {fb} failed RCPTs without disconnect)"
                            ),
                        }
                    )
                else:
                    vulns.append({"vuln_code": VULNS.ManyRcptReject.value})
            if precheck_obj:
                rcpt_obj["precheck"] = precheck_obj
            props["rcptLimit"] = rcpt_obj
            return props, vulns
        if rlim.limit_triggered:
            obj: dict = {"maxAccepted": rlim.max_accepted, "limitTriggered": True}
            disc = getattr(rlim, "disconnect_after_limit", None)
            if disc is not None:
                obj["disconnectAfterLimit"] = bool(disc)
                obj["posthitProbeCount"] = int(getattr(rlim, "posthit_probe_count", 0))
            if precheck_obj:
                obj["precheck"] = precheck_obj
            props["rcptLimit"] = obj
            ma = rlim.max_accepted if rlim.max_accepted is not None else 0
            if ma > RCPT_LIMIT_VERDICT_WARN_MAX:
                vulns.append({"vuln_code": VULNS.ManyRcpt.value})
            if disc is False:
                vulns.append({"vuln_code": VULNS.RcptNoCut.value})
            return props, vulns
        if rlim.max_accepted == 0:
            obj = {"maxAccepted": 0, "limitTriggered": False, "couldNotTest": True}
        else:
            obj = {"maxAccepted": rlim.max_accepted, "limitTriggered": False}
            ma = rlim.max_accepted if rlim.max_accepted is not None else 0
            if ma > RCPT_LIMIT_VERDICT_WARN_MAX:
                vulns.append({"vuln_code": VULNS.ManyRcpt.value})
        if precheck_obj:
            obj["precheck"] = precheck_obj
        props["rcptLimit"] = obj
        return props, vulns

    def _rcpt_duplicate_for_json(self) -> tuple[dict, list[dict]]:
        """Duplicate RCPT TO (-rdd): properties + optional PTV when many identical RCPT are accepted."""
        props: dict = {}
        vulns: list[dict] = []
        if (err := self.results.rcpt_duplicate_error) is not None:
            props["rcptDuplicateError"] = err
            return props, vulns
        if (rd := self.results.rcpt_duplicate) is None:
            return props, vulns
        _rdd_analyst_note = (
            "After DATA, sound implementations usually deliver a single mailbox copy even when the same "
            "address appeared in RCPT TO multiple times (no data amplification). Several delivered copies "
            "for one submitted message indicate risky fan-out. Inspect Delivered-To and Received lines: "
            "sometimes only one copy arrives but headers still reflect duplicate envelope recipients "
            "(possible informational leak)."
        )
        props["rcptDuplicate"] = {
            "testId": "PTL-SVC-SMTP-RCPT-DUP",
            "recipient": rd.recipient,
            "duplicateCount": rd.duplicate_count,
            "rcptReplies": [{"smtpCode": c, "reply": rep} for c, rep in rd.rcpt_replies],
            "allRcpt2xx": rd.all_rcpt_2xx,
            "firstFailureIndex": rd.first_failure_index,
            "dataSent": rd.data_sent,
            "dataSmtpCode": rd.data_code,
            "dataReply": rd.data_reply_snippet,
            "mailFromUsed": rd.mail_from_used,
            "probeUuid": rd.probe_uuid,
            **({"analystNote": _rdd_analyst_note} if rd.all_rcpt_2xx else {}),
        }
        if rd.all_rcpt_2xx and rd.duplicate_count >= 3:
            vulns.append(
                {
                    "vuln_code": VULNS.RcptDuplicate.value,
                    "vuln_request": (
                        f"Same recipient accepted {rd.duplicate_count} times as separate RCPT TO "
                        f"in one MAIL transaction ({rd.recipient})"
                    ),
                    "vuln_response": (
                        "SMTP returned 2xx for each duplicate RCPT TO — envelope semantics treat them as "
                        "separate recipients; after DATA, correct handling should still yield one logical "
                        "delivery without amplification. If the recipient receives multiple distinct copies, "
                        "that matches this finding (PTV-SVC-SMTP-RCPTDUP). Verify manually with --send "
                        "and mailbox/logs; also review Delivered-To / Received: a single message may "
                        "still expose repeated routing (informational leak)."
                    ),
                    "vuln_note": _rdd_analyst_note,
                }
            )
        return props, vulns

    def output(self) -> None:
        # Connection error: use unified error format (status=error, empty nodes)
        if (info_error := getattr(self.results, "info_error", None)) is not None:
            if self.use_json:
                self.ptjsonlib.end_error(info_error, self.use_json)
            ptprinthelper.ptprint(info_error, bullet_type="VULN",
                                  condition=not self.use_json, indent=4)
            return

        # ── Flat output: no nodes, global properties + global vulnerabilities ──
        if not self._is_node_based_output():
            description = self._build_flat_description()
            flat_vulns = self._collect_flat_vulns()
            _, _rcpt_vulns = self._rcpt_limit_for_json()
            flat_vulns.extend(_rcpt_vulns)
            _rdd_p, _rdd_v = self._rcpt_duplicate_for_json()
            flat_vulns.extend(_rdd_v)
            props: dict = {"description": description}
            props.update(_rdd_p)
            if (ad := self.results.auth_downgrade) is not None:
                props["authDowngrade"] = {
                    "vulnerable": ad.vulnerable,
                    "weakness": ad.weakness,
                    "indeterminate": ad.indeterminate,
                    "infoDefensive": ad.info_defensive,
                    "methodsBefore": ad.methods_before,
                    "methodsAfter": ad.methods_after,
                    "authMethodUsed": ad.auth_method_used,
                    "detail": ad.detail,
                }
                if ad.server_response is not None:
                    props["authDowngrade"]["serverResponse"] = ad.server_response
                if ad.rset_ok is not None:
                    props["authDowngrade"]["rsetOk"] = ad.rset_ok
            elif (ad_err := self.results.auth_downgrade_error) is not None:
                props["authDowngradeError"] = ad_err
            if (af := self.results.auth_format) is not None:
                props["authFormat"] = {
                    "testId": "PTL-SVC-SMTP-AUTH-FORMAT",
                    "methodTested": af.method_tested,
                    "conclusion": af.conclusion,
                    "conclusionId": af.conclusion_id,
                    "targetDomainUsed": af.target_domain_used,
                    "targetDomainSource": af.target_domain_source,
                    "targetDomainAnalystNote": af.target_domain_analyst_note,
                    "targetDomainEhloHostname": af.target_domain_ehlo_hostname,
                    "targetDomainScanHostname": af.target_domain_scan_hostname,
                    "netbiosDomainUsed": af.netbios_domain_used,
                    "challengeDecoded": af.challenge_decoded,
                    "challengeHint": af.challenge_hint,
                    "rateLimited": af.rate_limited,
                    "indeterminate": af.indeterminate,
                    "probes": [
                        {
                            "id": r.probe_id,
                            "label": r.label,
                            "identity": r.identity,
                            "skipped": r.skipped,
                            "skipReason": r.skip_reason,
                            "codeAfterIdentity": r.code_after_identity,
                            "passwordPhase": r.password_phase,
                            "codeAfterPassword": r.code_after_password,
                            "replyAfterIdentity": r.reply_after_identity,
                            "rateLimited": r.rate_limited,
                        }
                        for r in af.rows
                    ],
                }
            elif (af_err := self.results.auth_format_error) is not None:
                props["authFormatError"] = af_err
            if (ic := self.results.inv_comm) is not None:
                props["invalidCommands"] = {
                    "vulnerable": ic.vulnerable,
                    "weakness": ic.weakness,
                    "indeterminate": ic.indeterminate,
                    "detail": ic.detail,
                    "baselineLatencySec": getattr(ic, "baseline_latency_sec", None),
                    "tarpittingDetected": getattr(ic, "tarpitting_detected", False),
                    "tests": [
                        {
                            "category": t.category,
                            "command": t.command_display,
                            "status": t.status,
                            "reply": t.reply,
                            "sessionOk": t.session_ok,
                            "infoLeak": t.info_leak,
                            "vulnerable": t.vulnerable,
                            "vulnType": getattr(t, "vuln_type", None),
                            "responseTimeSec": getattr(t, "response_time_sec", None),
                            "slowResponse": getattr(t, "slow_response", False),
                        }
                        for t in ic.tests
                    ],
                }
            elif (ic_err := self.results.inv_comm_error) is not None:
                props["invalidCommandsError"] = ic_err
            if (ho := self.results.helo_only) is not None:
                props["heloOnly"] = {
                    "vulnerable": ho.vulnerable,
                    "indeterminate": ho.indeterminate,
                    "heloStatus": ho.helo_status,
                    "ehloStatus": ho.ehlo_status,
                    "extensions": list(ho.extensions),
                    "connectionType": ho.connection_type,
                    "detail": ho.detail,
                }
            elif (ho_err := self.results.helo_only_error) is not None:
                props["heloOnlyError"] = ho_err
            if (hb := self.results.helo_bypass) is not None:
                props["heloBypass"] = {
                    "vulnerable": hb.vulnerable,
                    "indeterminate": hb.indeterminate,
                    "submissionBypassEhlo": list(hb.submission_bypass_ehlo),
                    "relayBypassEhlo": list(hb.relay_bypass_ehlo),
                    "acceptsInvalidFormat": list(hb.accepts_invalid_format),
                    "ehloConsistent": hb.ehlo_consistent,
                    "tarpittingDetected": list(hb.tarpitting_detected),
                    "rcptLatencies": hb.rcpt_latencies,
                    "detail": hb.detail,
                }
            elif (hb_err := self.results.helo_bypass_error) is not None:
                props["heloBypassError"] = hb_err
            if (id_r := self.results.identify) is not None:
                props["serverIdentify"] = {
                    "product": id_r.product,
                    "behavioralHint": getattr(id_r, "behavioral_hint", None),
                    "version": id_r.version,
                    "cpe": id_r.cpe,
                    "os": id_r.os,
                    "confidencePct": id_r.confidence_pct,
                    "confidenceLabel": id_r.confidence_label,
                    "hiddenBanner": id_r.hidden_banner,
                    "scoringMatrix": [
                        {"method": s.method, "points": s.points, "detail": s.detail}
                        for s in id_r.scoring_matrix
                    ],
                    "banner": id_r.banner,
                    "ehloExtensions": id_r.ehlo_extensions,
                    "ehloProprietary": id_r.ehlo_proprietary,
                    "recommendation": id_r.recommendation,
                    "anomalousIdentity": id_r.anomalous_identity,
                    "bannerClaims": id_r.banner_claims,
                    "behaviorMatches": id_r.behavior_matches,
                    "tlsCertSubject": id_r.tls_cert_subject,
                    "tlsCertIssuer": id_r.tls_cert_issuer,
                    "tlsCertSan": id_r.tls_cert_san,
                    "tlsCertSelfSigned": id_r.tls_cert_self_signed,
                    "transportTls": getattr(id_r, "transport_tls", False),
                    "starttlsAdvertised": getattr(id_r, "starttls_advertised", False),
                    "tlsPolicy": getattr(id_r, "tls_policy", None),
                    "tlsCertWarnings": getattr(id_r, "tls_cert_warnings", None) or [],
                    "tlsCipherWarnings": getattr(id_r, "tls_cipher_warnings", None) or [],
                    "tlsDowngradeFindings": getattr(id_r, "tls_downgrade_findings", None) or [],
                    "tlsDowngradeProbed": getattr(id_r, "tls_downgrade_probed", False),
                    "certDomainMatch": getattr(id_r, "cert_domain_match", False),
                    "mxCertOk": getattr(id_r, "mx_cert_ok", None),
                    "mxCertMessage": getattr(id_r, "mx_cert_message", None),
                    "mxQueriedDomain": getattr(id_r, "mx_queried_domain", None),
                    "mxPeerHostname": getattr(id_r, "mx_peer_hostname", None),
                    "osHint": getattr(id_r, "os_hint", None),
                    "dataLeakage": [
                        {
                            "email": x.email,
                            "risk": x.risk,
                            "sources": list(x.sources),
                            "targetDomainMatch": getattr(x, "target_domain_match", False),
                            "kind": getattr(x, "kind", "email"),
                        }
                        for x in (getattr(id_r, "data_leakage_findings", None) or ())
                    ],
                    "discrepancyDetected": getattr(id_r, "discrepancy_detected", False),
                    "discrepancyBannerProduct": getattr(id_r, "discrepancy_banner_product", None),
                    "discrepancyBehaviorProduct": getattr(id_r, "discrepancy_behavior_product", None),
                }
            elif (id_err := self.results.identify_error) is not None:
                props["serverIdentifyError"] = id_err
            if (mb := self.results.mail_bomb) is not None:
                props["mailBomb"] = {
                    "vulnerable": mb.vulnerable,
                    "indeterminate": mb.indeterminate,
                    "partialProtection": mb.partial_protection,
                    "sent": mb.sent,
                    "delivered": mb.delivered,
                    "rateLimited": mb.rate_limited,
                    "blocked": mb.blocked,
                    "connectionLost": mb.connection_lost,
                    "firstRejectionAt": mb.first_rejection_at,
                    "elapsedSec": round(mb.elapsed_sec, 2),
                    "tarpittingDetected": mb.tarpitting_detected,
                    "lastError": mb.last_error,
                    "lastErrorType": mb.last_error_type or None,
                    "avgRttMs": round(mb.avg_rtt_ms, 1) if mb.avg_rtt_ms is not None else None,
                    "smtpTrace": list(mb.smtp_trace),
                    "perMessageDelivered": list(getattr(mb, "per_message_delivered", ()) or ()),
                    "abortedOnSmtp500": getattr(mb, "aborted_on_smtp_500", False),
                    "abortAtMessage": getattr(mb, "abort_at_message", None),
                    "authUsed": mb.auth_used,
                    "detail": mb.detail,
                    "sampleTestId": mb.sample_test_id or None,
                }
            elif (mb_err := self.results.mail_bomb_error) is not None:
                props["mailBombError"] = mb_err
            if (av := self.results.antivirus) is not None:
                props["antivirus"] = {
                    "vulnerable": av.vulnerable,
                    "indeterminate": av.indeterminate,
                    "partialProtection": av.partial_protection,
                    "elapsedSec": round(av.elapsed_sec, 2),
                    "authUsed": av.auth_used,
                    "detail": av.detail,
                    "categories": [
                        {
                            "category": c.category,
                            "sent": c.sent,
                            "accepted": c.accepted,
                            "rejected": c.rejected,
                            "error": c.error,
                            "smtpTrace": list(c.smtp_trace),
                            "messageSummary": list(c.message_summary),
                            "payloadTestIds": list(c.payload_test_ids),
                            "detail": c.detail,
                            "testId": c.test_id or None,
                        }
                        for c in av.categories
                    ],
                }
            elif (av_err := self.results.antivirus_error) is not None:
                props["antivirusError"] = av_err
            if (sh := self.results.spoof_header) is not None:
                props["spoofHeader"] = {
                    "vulnerable": sh.vulnerable,
                    "indeterminate": sh.indeterminate,
                    "elapsedSec": round(sh.elapsed_sec, 2),
                    "detail": sh.detail,
                    "vulnerableNote": sh.vulnerable_note,
                    "variants": [
                        {
                            "variant": v.variant,
                            "testId": v.test_id,
                            "accepted": v.accepted,
                            "rejected": v.rejected,
                            "error": v.error,
                            "smtpStatus": v.smtp_status,
                            "smtpReply": v.smtp_reply,
                            "detail": v.detail,
                            "envelopeHeaderMismatch": v.envelope_header_mismatch,
                            "smtpTrace": list(v.smtp_trace),
                        }
                        for v in sh.variants
                    ],
                }
            elif (sh_err := self.results.spoof_header_error) is not None:
                props["spoofHeaderError"] = sh_err
            if (bc := self.results.bcc_test) is not None:
                props["bccTest"] = {
                    "messageAccepted": bc.message_accepted,
                    "smtpStatus": bc.smtp_status,
                    "smtpReply": bc.smtp_reply,
                    "recipientsTo": list(bc.recipients_to),
                    "recipientsCc": list(bc.recipients_cc),
                    "recipientsBcc": list(bc.recipients_bcc),
                    "elapsedSec": round(bc.elapsed_sec, 2),
                    "detail": bc.detail,
                    "verificationInstructions": bc.verification_instructions,
                    "smtpTrace": list(bc.smtp_trace),
                    "testId": bc.test_id or None,
                }
            elif (bc_err := self.results.bcc_test_error) is not None:
                props["bccTestError"] = bc_err
            if (al := self.results.alias_test) is not None:
                props["aliasTest"] = {
                    "baseAddress": al.base_address,
                    "baseMailSent": al.base_mail_sent,
                    "baseTestId": al.base_test_id or None,
                    "elapsedSec": round(al.elapsed_sec, 2),
                    "detail": al.detail,
                    "verificationInstructions": al.verification_instructions,
                    "variants": [
                        {
                            "variant": v.variant,
                            "address": v.address,
                            "accepted": v.accepted,
                            "rejected": v.rejected,
                            "error": v.error,
                            "smtpStatus": v.smtp_status,
                            "smtpReply": v.smtp_reply,
                            "detail": v.detail,
                            "uucpWarning": v.uucp_warning,
                            "smtpTrace": list(v.smtp_trace),
                            "testId": v.test_id or None,
                        }
                        for v in al.variants
                    ],
                }
            elif (al_err := self.results.alias_test_error) is not None:
                props["aliasTestError"] = al_err
            if (fr := self.results.flood) is not None:
                props["flood"] = {
                    "vulnerable": fr.vulnerable,
                    "indeterminate": fr.indeterminate,
                    "partialProtection": fr.partial_protection,
                    "sizeAdvertised": fr.size_advertised,
                    "sizeLimitBytes": fr.size_limit_bytes,
                    "sizeLimitMb": round(fr.size_limit_bytes / 1048576, 2) if fr.size_limit_bytes else None,
                    "sizeEnforced": fr.size_enforced,
                    "messagesSent": fr.messages_sent,
                    "messagesAccepted": fr.messages_accepted,
                    "messagesRejected": fr.messages_rejected,
                    "queueAttempts": fr.queue_attempts,
                    "floodNotes": list(fr.flood_notes),
                    "firstRejectionAt": fr.first_rejection_at,
                    "tarpittingDetected": fr.tarpitting_detected,
                    "elapsedSec": round(fr.elapsed_sec, 2),
                    "smtpTrace": list(fr.smtp_trace),
                    "authUsed": fr.auth_used,
                    "detail": fr.detail,
                    "testId": fr.test_id or None,
                }
            elif (flood_err := self.results.flood_error) is not None:
                props["floodError"] = flood_err
            _adp_props = self._accepted_domain_probe_props_json()
            if _adp_props:
                props.update(_adp_props)
            self.ptjsonlib.add_properties(props)
            for v in flat_vulns:
                self.ptjsonlib.add_vulnerability(**v)
            self.ptjsonlib.set_status("finished", "")
            self.ptprint(self.ptjsonlib.get_result_json(), json=True)
            return

        # ── Enum-only: userAccount nodes + global vulns, no software node ──
        if self._is_enum_only_output():
            props: dict = {}
            if (catch_all := self.results.catch_all) is not None:
                desc_map = {
                    "not_configured": "CatchAll not_configured",
                    "configured": "CatchAll configured",
                    "indeterminate": "CatchAll indeterminate",
                    "indeterminate_accept_all_rcpt": (
                        "CatchAll indeterminate (accept-all via RCPT)"
                    ),
                }
                props["description"] = desc_map.get(catch_all, f"CatchAll {catch_all}")
            if catch_all == "configured":
                props["enumerationNotes"] = (
                    "Results unreliable: Catch-all configured - all methods report as indeterminate (useless for enumeration)"
                )
            if (enum_err := self.results.enum_error) is not None:
                props["enumerationError"] = enum_err
            if props:
                self.ptjsonlib.add_properties(props)
            if (enum_results := self.results.enum_results) is not None:
                for e in enum_results:
                    if e.vulnerable and e.results is not None:
                        for user in sorted(e.results, key=str):
                            local_part = str(user).split("@")[0] if "@" in str(user) else str(user)
                            user_props = {"name": local_part, "email": str(user)}
                            user_node = self.ptjsonlib.create_node_object(
                                "userAccount",
                                parent_type="userAccounts",
                                parent=None,
                                properties=user_props,
                            )
                            self.ptjsonlib.add_node(user_node)
            _ENUM_VULN_MAP = {
                "EXPN": VULNS.UserEnumEXPN.value,
                "VRFY": VULNS.UserEnumVRFY.value,
                "RCPT": VULNS.UserEnumRCPT.value,
            }
            if enum_results is not None:
                catch_all_val = getattr(self.results, "catch_all", None)
                if self.args.enumerate is None:
                    requested_set = {"EXPN", "VRFY", "RCPT"}
                elif isinstance(self.args.enumerate, list):
                    requested_set = {m.upper() for m in self.args.enumerate if m}
                else:
                    requested_set = {self.args.enumerate.upper()} if self.args.enumerate else {"EXPN", "VRFY", "RCPT"}
                filtered = [e for e in enum_results if e.method.upper() in requested_set]
                for e in filtered:
                    vulnerable = False if catch_all_val == "configured" else e.vulnerable
                    if vulnerable:
                        vc = _ENUM_VULN_MAP.get(e.method.upper())
                        if vc:
                            self.ptjsonlib.add_vulnerability(vuln_code=vc)
            self.ptjsonlib.set_status("finished", "")
            self.ptprint(self.ptjsonlib.get_result_json(), json=True)
            return

        # ── Node-based output: software node + optional userAccount nodes ──
        properties = {
            "software_type": None,
            "name": "smtp",
            "version": None,
            "vendor": None,
            "description": None,
        }
        if getattr(self.args, "smtp_role", None):
            properties["declaredServerRole"] = self.args.smtp_role

        global_vulns: list[dict] = []

        if getattr(self, "run_all_mode", False) and (resolved := getattr(self.results, "resolved_domain", None)) is not None:
            properties.update({"resolvedDomain": resolved})

        # 1. Banner
        if self.results.banner_requested:
            if (info := self.results.info) and info.banner is not None:
                sid = identify_service(info.banner)
                vendor = _vendor_from_cpe(sid.cpe) if sid else None
                version = sid.version if sid else None
                properties.update(
                    {
                        "description": f"Banner: {info.banner}",
                        "version": version,
                        "vendor": vendor,
                    }
                )
                if sid is not None:
                    if sid.version is not None:
                        global_vulns.append({"vuln_code": VULNS.Banner.value})
                    properties.update({"cpe": sid.cpe})

        # 2. EHLO extensions
        if self.results.commands_requested:
            if (info := self.results.info) and info.ehlo is not None:
                ehlo_starttls = getattr(info, "ehlo_starttls", None)
                if ehlo_starttls:
                    properties.update(
                        {"ehloCommand": info.ehlo, "ehloCommandStarttls": ehlo_starttls}
                    )
                else:
                    properties.update({"ehloCommand": info.ehlo})

        # Role identification
        if (role_error := self.results.role_error) is not None:
            properties.update({"roleError": role_error})
        elif (role_r := self.results.role) is not None:
            properties.update({
                "identifiedRole": {
                    "role": role_r.role,
                    "portHint": role_r.port_hint,
                    "authAdvertised": role_r.auth_advertised,
                    "authRequired": role_r.auth_required,
                    "detail": role_r.detail,
                }
            })
            if role_r.role == "hybrid":
                global_vulns.append({
                    "vuln_code": VULNS.HybridRole.value,
                    "vuln_request": f"Role identification on port {self.args.target.port}",
                    "vuln_response": (
                        f"Hybrid (MTA + Submission) -- consider separating roles\n"
                        f"{role_r.detail}"
                    ),
                })

        # Encryption
        if (encryption_error := self.results.encryption_error) is not None:
            properties.update({"encryptionError": encryption_error})
        elif (enc := self.results.encryption) is not None:
            properties.update(
                {
                    "encryption": {
                        "plaintext": enc.plaintext_ok,
                        "starttls": enc.starttls_ok,
                        "tls": enc.tls_ok,
                    }
                }
            )
            if enc.plaintext_ok:
                global_vulns.append({"vuln_code": VULNS.CryptOnly.value})

        # Open relay
        if (open_relay_error := self.results.open_relay_error) is not None:
            properties.update({"openRelayError": open_relay_error})
        elif (open_relay := self.results.open_relay) is not None:
            if open_relay:
                global_vulns.append(
                    {"vuln_code": VULNS.OpenRelay.value, "vuln_request": "Open relay"}
                )

        # Catch All mailbox
        if (catch_all := self.results.catch_all) is not None:
            properties.update({"catchAll": catch_all})

        # RCPT TO limit
        _rcpt_p, _rcpt_v = self._rcpt_limit_for_json(rcpt_vuln_detail=True)
        properties.update(_rcpt_p)
        global_vulns.extend(_rcpt_v)

        _rdd_p, _rdd_v = self._rcpt_duplicate_for_json()
        properties.update(_rdd_p)
        global_vulns.extend(_rdd_v)

        _adp_props = self._accepted_domain_probe_props_json()
        if _adp_props:
            properties.update(_adp_props)

        # Blacklist information
        if (blacklist_error := self.results.blacklist_error) is not None:
            properties.update({"blacklistError": blacklist_error})
        elif self.results.blacklist_private_ip_skipped:
            properties.update({"blacklistSkipped": "private_ip"})
        elif blacklist := self.results.blacklist:
            if blacklist.listed:
                json_lines: list[str] = []
                if (results := blacklist.results) is not None:
                    for r in results:
                        json_lines.append(f'{r.blacklist.strip()}: "{r.reason}" (TTL={r.ttl})')
                    if len(json_lines) > 0:
                        global_vulns.append(
                            {
                                "vuln_code": VULNS.Blacklist.value,
                                "vuln_request": f"blacklists containing target {self.target}",
                                "vuln_response": "\n".join(json_lines),
                            }
                        )

        # SPF records
        if (spf_error := self.results.spf_error) is not None:
            properties.update({"spfError": spf_error})
        elif self.results.spf_requires_domain:
            properties.update({"spfSkipped": "requires_domain"})
        elif (spf_records := self.results.spf_records) is not None:
            json_lines = []
            for ns, records in spf_records.items():
                for r in records:
                    json_lines.append(f"[{ns}] {r}")
            if len(json_lines) > 0:
                properties.update({"spfRecords": "\n".join(json_lines)})

        # User enumeration methods
        _ENUM_VULN_MAP = {
            "EXPN": VULNS.UserEnumEXPN.value,
            "VRFY": VULNS.UserEnumVRFY.value,
            "RCPT": VULNS.UserEnumRCPT.value,
        }
        if (enum_error := self.results.enum_error) is not None:
            properties.update({"enumerationError": enum_error})
        elif (enum_results := self.results.enum_results) is not None:
            catch_all = getattr(self.results, "catch_all", None)
            if self.args.enumerate is None:
                requested_set = {"EXPN", "VRFY", "RCPT"}
            elif isinstance(self.args.enumerate, list):
                requested_set = {m.upper() for m in self.args.enumerate if m}
            else:
                requested_set = {self.args.enumerate.upper()} if self.args.enumerate else {"EXPN", "VRFY", "RCPT"}
            filtered = [e for e in enum_results if e.method.upper() in requested_set]
            if catch_all == "configured":
                properties.update(
                    {
                        "enumerationNotes": "Results unreliable: Catch-all configured - all methods report as indeterminate (useless for enumeration)",
                    }
                )
            for e in filtered:
                vulnerable = False if catch_all == "configured" else e.vulnerable
                if vulnerable:
                    vuln_code = _ENUM_VULN_MAP.get(e.method.upper())
                    if vuln_code:
                        global_vulns.append({"vuln_code": vuln_code})

        # NTLM information
        if (ntlm_error := self.results.ntlm_error) is not None:
            properties.update({"ntlmError": ntlm_error})
        elif ntlm := self.results.ntlm:
            if not ntlm.success:
                properties.update({"ntlmInfoStatus": "failed"})
            elif ntlm.ntlm is not None:
                properties.update({"ntlmInfoStatus": "ok"})
                out_lines = [
                    f"Target name: {ntlm.ntlm.target_name}",
                    f"NetBios domain name: {ntlm.ntlm.netbios_domain}",
                    f"NetBios computer name: {ntlm.ntlm.netbios_computer}",
                    f"DNS domain name: {ntlm.ntlm.dns_domain}",
                    f"DNS computer name: {ntlm.ntlm.dns_computer}",
                    f"DNS tree: {ntlm.ntlm.dns_tree}",
                    f"OS version: {ntlm.ntlm.os_version}",
                ]
                global_vulns.append(
                    {
                        "vuln_code": VULNS.NTLM.value,
                        "vuln_request": "ntlm authentication",
                        "vuln_response": "\n".join(out_lines),
                    }
                )

        # HELO/EHLO hostname validation
        if (helo_err := self.results.helo_validation_error) is not None:
            properties.update({"heloValidationError": helo_err})
        elif (hv := self.results.helo_validation) is not None:
            hv_props: dict = {
                "vulnerable": hv.vulnerable,
                "weakConfig": hv.weak_config,
                "indeterminate": hv.indeterminate,
                "acceptedVectors": hv.accepted_vectors,
                "rejectedVectors": hv.rejected_vectors,
                "detail": hv.detail,
            }
            if hv.ehlo_bypass is not None:
                hv_props["ehloBypass"] = hv.ehlo_bypass
            if hv.ehlo_comparison:
                hv_props["ehloComparison"] = hv.ehlo_comparison
            properties.update({"heloValidation": hv_props})
            if hv.vulnerable or hv.ehlo_bypass:
                global_vulns.append(
                    {
                        "vuln_code": VULNS.HeloNoValidation.value,
                        "vuln_request": "HELO/EHLO hostname validation",
                        "vuln_response": hv.detail or "",
                    }
                )

        # AUTH downgrade
        if (ad_err := self.results.auth_downgrade_error) is not None:
            properties.update({"authDowngradeError": ad_err})
        elif (ad := self.results.auth_downgrade) is not None:
            ad_props: dict = {
                "vulnerable": ad.vulnerable,
                "weakness": ad.weakness,
                "indeterminate": ad.indeterminate,
                "infoDefensive": ad.info_defensive,
                "methodsBefore": ad.methods_before,
                "methodsAfter": ad.methods_after,
                "authMethodUsed": ad.auth_method_used,
                "detail": ad.detail,
            }
            if ad.server_response is not None:
                ad_props["serverResponse"] = ad.server_response
            if ad.rset_ok is not None:
                ad_props["rsetOk"] = ad.rset_ok
            properties.update({"authDowngrade": ad_props})
            if ad.vulnerable:
                global_vulns.append(
                    {
                        "vuln_code": VULNS.AuthDowngrade.value,
                        "vuln_request": f"AUTH {ad.auth_method_used} (bogus token)",
                        "vuln_response": ad.detail or "",
                    }
                )

        # AUTH LOGIN format (PTL-SVC-SMTP-AUTH-FORMAT)
        if (af_err := self.results.auth_format_error) is not None:
            properties.update({"authFormatError": af_err})
        elif (af := self.results.auth_format) is not None:
            properties.update(
                {
                    "authFormat": {
                        "testId": "PTL-SVC-SMTP-AUTH-FORMAT",
                        "methodTested": af.method_tested,
                        "conclusion": af.conclusion,
                        "conclusionId": af.conclusion_id,
                        "targetDomainUsed": af.target_domain_used,
                        "targetDomainSource": af.target_domain_source,
                        "targetDomainAnalystNote": af.target_domain_analyst_note,
                        "targetDomainEhloHostname": af.target_domain_ehlo_hostname,
                        "targetDomainScanHostname": af.target_domain_scan_hostname,
                        "netbiosDomainUsed": af.netbios_domain_used,
                        "challengeDecoded": af.challenge_decoded,
                        "challengeHint": af.challenge_hint,
                        "rateLimited": af.rate_limited,
                        "indeterminate": af.indeterminate,
                        "probes": [
                            {
                                "id": r.probe_id,
                                "label": r.label,
                                "identity": r.identity,
                                "skipped": r.skipped,
                                "skipReason": r.skip_reason,
                                "codeAfterIdentity": r.code_after_identity,
                                "passwordPhase": r.password_phase,
                                "codeAfterPassword": r.code_after_password,
                                "replyAfterIdentity": r.reply_after_identity,
                                "rateLimited": r.rate_limited,
                            }
                            for r in af.rows
                        ],
                    }
                }
            )

        # Invalid commands (PTL-SVC-SMTP-INVCOMM)
        if (ic_err := self.results.inv_comm_error) is not None:
            properties.update({"invalidCommandsError": ic_err})
        elif (ic := self.results.inv_comm) is not None:
            ic_props: dict = {
                "vulnerable": ic.vulnerable,
                "weakness": ic.weakness,
                "indeterminate": ic.indeterminate,
                "detail": ic.detail,
                "baselineLatencySec": getattr(ic, "baseline_latency_sec", None),
                "tarpittingDetected": getattr(ic, "tarpitting_detected", False),
                "tests": [
                    {
                        "category": t.category,
                        "command": t.command_display,
                        "status": t.status,
                        "reply": t.reply,
                        "sessionOk": t.session_ok,
                        "infoLeak": t.info_leak,
                        "vulnerable": t.vulnerable,
                        "vulnType": getattr(t, "vuln_type", None),
                        "responseTimeSec": getattr(t, "response_time_sec", None),
                        "slowResponse": getattr(t, "slow_response", False),
                    }
                    for t in ic.tests
                ],
            }
            properties.update({"invalidCommands": ic_props})
            if ic.vulnerable:
                global_vulns.append(
                    {
                        "vuln_code": VULNS.InvComm.value,
                        "vuln_request": "Invalid/non-standard SMTP commands",
                        "vuln_response": ic.detail or "",
                    }
                )

        # HELO-only (PTL-SVC-SMTP-HELOONLY)
        if (ho_err := self.results.helo_only_error) is not None:
            properties.update({"heloOnlyError": ho_err})
        elif (ho := self.results.helo_only) is not None:
            ho_props: dict = {
                "vulnerable": ho.vulnerable,
                "indeterminate": ho.indeterminate,
                "heloStatus": ho.helo_status,
                "ehloStatus": ho.ehlo_status,
                "extensions": list(ho.extensions),
                "connectionType": ho.connection_type,
                "detail": ho.detail,
            }
            properties.update({"heloOnly": ho_props})
            if ho.vulnerable:
                global_vulns.append(
                    {
                        "vuln_code": VULNS.HeloOnly.value,
                        "vuln_request": "EHLO test.local",
                        "vuln_response": ho.detail or "",
                    }
                )

        # HELO bypass (PTL-SVC-SMTP-HELO)
        if (hb_err := self.results.helo_bypass_error) is not None:
            properties.update({"heloBypassError": hb_err})
        elif (hb := self.results.helo_bypass) is not None:
            hb_props: dict = {
                "vulnerable": hb.vulnerable,
                "indeterminate": hb.indeterminate,
                "submissionBypassEhlo": list(hb.submission_bypass_ehlo),
                "relayBypassEhlo": list(hb.relay_bypass_ehlo),
                "acceptsInvalidFormat": list(hb.accepts_invalid_format),
                "ehloConsistent": hb.ehlo_consistent,
                "tarpittingDetected": list(hb.tarpitting_detected),
                "detail": hb.detail,
            }
            properties.update({"heloBypass": hb_props})
            if hb.vulnerable:
                bypass_ehlo = ", ".join(hb.submission_bypass_ehlo + hb.relay_bypass_ehlo)
                global_vulns.append(
                    {
                        "vuln_code": VULNS.HeloBypass.value,
                        "vuln_request": f"EHLO {bypass_ehlo}\nMAIL FROM:<tester@example.com>\nRCPT TO:<external-test@gmail.com>",
                        "vuln_response": hb.detail or "",
                    }
                )

        # Bounce replay (PTL-SVC-SMTP-REPLAY)
        if (br_err := self.results.bounce_replay_error) is not None:
            properties.update({"bounceReplayError": br_err})
        elif (br := self.results.bounce_replay) is not None:
            br_description = (
                "\r\n".join(self._bounce_replay_trace_line_clean(l) for l in br.smtp_trace)
                if br.smtp_trace else None
            )
            br_props: dict = {
                "vulnerable": br.vulnerable,
                "indeterminate": br.indeterminate,
                "messageAccepted": br.message_accepted,
                "messageAcceptedReturnPath": getattr(br, "message_accepted_return_path", False),
                "rcptRejectedInSession": br.rcpt_rejected_in_session,
                "bounceAddr": br.bounce_addr,
                "recipientUsed": br.recipient_used,
                "testId": br.test_id,
                "testIdReturnPath": getattr(br, "test_id_return_path", "") or None,
                "smtpTrace": list(br.smtp_trace),
                "tarpittingOrTimeout": br.tarpitting_or_timeout,
                "authUsed": getattr(br, "auth_used", False),
                "detail": br.detail,
                "description": br_description,
            }
            properties.update({"bounceReplay": br_props})
            if br.message_accepted or getattr(br, "message_accepted_return_path", False):
                global_vulns.append(
                    {
                        "vuln_code": VULNS.BounceReplay.value,
                        "vuln_request": f"MAIL FROM:<{br.bounce_addr}>\nRCPT TO:<{br.recipient_used}>",
                        "vuln_response": br.detail or "",
                    }
                )

        # Mail bomb (PTL-SVC-SMTP-BOMB)
        if (mb_err := self.results.mail_bomb_error) is not None:
            properties.update({"mailBombError": mb_err})
        elif (mb := self.results.mail_bomb) is not None:
            mb_props: dict = {
                "vulnerable": mb.vulnerable,
                "indeterminate": mb.indeterminate,
                "partialProtection": mb.partial_protection,
                "sent": mb.sent,
                "delivered": mb.delivered,
                "rateLimited": mb.rate_limited,
                "blocked": mb.blocked,
                "connectionLost": mb.connection_lost,
                "firstRejectionAt": mb.first_rejection_at,
                "elapsedSec": round(mb.elapsed_sec, 2),
                "tarpittingDetected": mb.tarpitting_detected,
                "lastError": mb.last_error,
                "lastErrorType": mb.last_error_type or None,
                "avgRttMs": round(mb.avg_rtt_ms, 1) if mb.avg_rtt_ms is not None else None,
                "smtpTrace": list(mb.smtp_trace),
                "perMessageDelivered": list(getattr(mb, "per_message_delivered", ()) or ()),
                "abortedOnSmtp500": getattr(mb, "aborted_on_smtp_500", False),
                "abortAtMessage": getattr(mb, "abort_at_message", None),
                "authUsed": mb.auth_used,
                "detail": mb.detail,
                "sampleTestId": mb.sample_test_id or None,
            }
            properties.update({"mailBomb": mb_props})
            if mb.vulnerable:
                global_vulns.append(
                    {
                        "vuln_code": VULNS.Bomb.value,
                        "vuln_request": f"Flood of {mb.sent} messages to {self.args.rcpt_to}",
                        "vuln_response": mb.detail or "",
                    }
                )

        # Antivirus (PTL-SVC-SMTP-ANTIVIRUS)
        if (av_err := self.results.antivirus_error) is not None:
            properties.update({"antivirusError": av_err})
        elif (av := self.results.antivirus) is not None:
            properties.update({
                "antivirus": {
                    "vulnerable": av.vulnerable,
                    "indeterminate": av.indeterminate,
                    "partialProtection": av.partial_protection,
                    "elapsedSec": round(av.elapsed_sec, 2),
                    "authUsed": av.auth_used,
                    "detail": av.detail,
                    "categories": [
                        {
                            "category": c.category,
                            "sent": c.sent,
                            "accepted": c.accepted,
                            "rejected": c.rejected,
                            "error": c.error,
                            "smtpTrace": list(c.smtp_trace),
                            "messageSummary": list(c.message_summary),
                            "payloadTestIds": list(c.payload_test_ids),
                            "detail": c.detail,
                            "testId": c.test_id or None,
                        }
                        for c in av.categories
                    ],
                }
            })
            if av.vulnerable:
                global_vulns.append(
                    {
                        "vuln_code": VULNS.Antivirus.value,
                        "vuln_request": f"E-mail with malicious content to {self.args.rcpt_to}",
                        "vuln_response": av.detail or "Risky content accepted at MTA",
                    }
                )

        # SSRF (PTL-SVC-SMTP-SSRF)
        if (ssrf_err := self.results.ssrf_error) is not None:
            properties.update({"ssrfError": ssrf_err})
        elif (sr := self.results.ssrf) is not None:
            properties.update({
                "ssrf": {
                    "manualVerificationRequired": sr.manual_verification_required,
                    "canaryUrl": sr.canary_url,
                    "elapsedSec": round(sr.elapsed_sec, 2),
                    "authUsed": sr.auth_used,
                    "detail": sr.detail,
                    "verificationInstructions": sr.verification_instructions,
                    "variants": [
                        {
                            "variant": v.variant,
                            "sent": v.sent,
                            "accepted": v.accepted,
                            "rejected": v.rejected,
                            "error": v.error,
                            "smtpTrace": list(v.smtp_trace),
                            "detail": v.detail,
                            "testId": v.test_id or None,
                        }
                        for v in sr.variants
                    ],
                }
            })

        # FLOOD (PTL-SVC-SMTP-FLOOD)
        if (flood_err := self.results.flood_error) is not None:
            properties.update({"floodError": flood_err})
        elif (fr := self.results.flood) is not None:
            properties.update({
                "flood": {
                    "vulnerable": fr.vulnerable,
                    "indeterminate": fr.indeterminate,
                    "partialProtection": fr.partial_protection,
                    "sizeAdvertised": fr.size_advertised,
                    "sizeLimitBytes": fr.size_limit_bytes,
                    "sizeLimitMb": round(fr.size_limit_bytes / 1048576, 2) if fr.size_limit_bytes else None,
                    "sizeEnforced": fr.size_enforced,
                    "messagesSent": fr.messages_sent,
                    "messagesAccepted": fr.messages_accepted,
                    "messagesRejected": fr.messages_rejected,
                    "queueAttempts": fr.queue_attempts,
                    "floodNotes": list(fr.flood_notes),
                    "firstRejectionAt": fr.first_rejection_at,
                    "tarpittingDetected": fr.tarpitting_detected,
                    "elapsedSec": round(fr.elapsed_sec, 2),
                    "smtpTrace": list(fr.smtp_trace),
                    "authUsed": fr.auth_used,
                    "detail": fr.detail,
                    "testId": fr.test_id or None,
                }
            })
            if fr.vulnerable:
                global_vulns.append(
                    {
                        "vuln_code": VULNS.Flood.value,
                        "vuln_request": f"Queue flood ({fr.queue_attempts} attempts, {fr.messages_accepted} delivered) + SIZE test",
                        "vuln_response": fr.detail or "Server accepts excessive messages or SIZE not enforced",
                    }
                )

        # ZIPXXE (PTL-SVC-SMTP-ZIPXXE)
        if (zipxxe_err := self.results.zipxxe_error) is not None:
            properties.update({"zipxxeError": zipxxe_err})
        elif (zr := self.results.zipxxe) is not None:
            properties.update({
                "zipxxe": {
                    "manualVerificationRequired": zr.manual_verification_required,
                    "canaryUrl": zr.canary_url or None,
                    "elapsedSec": round(zr.elapsed_sec, 2),
                    "authUsed": zr.auth_used,
                    "detail": zr.detail,
                    "allRejectedAtRcpt": zr.all_rejected_at_rcpt,
                    "verificationInstructions": zr.verification_instructions,
                    "variants": [
                        {
                            "variant": v.variant,
                            "sent": v.sent,
                            "accepted": v.accepted,
                            "rejected": v.rejected,
                            "error": v.error,
                            "smtpTrace": list(v.smtp_trace),
                            "detail": v.detail,
                            "testId": v.test_id or None,
                        }
                        for v in zr.variants
                    ],
                }
            })

        # SPOOFHDR
        if (sh_err := self.results.spoof_header_error) is not None:
            properties.update({"spoofHeaderError": sh_err})
        elif (sh := self.results.spoof_header) is not None:
            properties.update({
                "spoofHeader": {
                    "vulnerable": sh.vulnerable,
                    "indeterminate": sh.indeterminate,
                    "elapsedSec": round(sh.elapsed_sec, 2),
                    "detail": sh.detail,
                    "vulnerableNote": sh.vulnerable_note,
                    "variants": [
                        {
                            "variant": v.variant,
                            "testId": v.test_id,
                            "accepted": v.accepted,
                            "rejected": v.rejected,
                            "error": v.error,
                            "smtpStatus": v.smtp_status,
                            "smtpReply": v.smtp_reply,
                            "detail": v.detail,
                            "envelopeHeaderMismatch": v.envelope_header_mismatch,
                            "smtpTrace": list(v.smtp_trace),
                        }
                        for v in sh.variants
                    ],
                }
            })
            if sh.vulnerable:
                global_vulns.append(
                    {
                        "vuln_code": VULNS.SpoofHeader.value,
                        "vuln_request": f"E-mail with spoofed From/Reply-To/Return-Path headers to {self.args.rcpt_to}",
                        "vuln_response": sh.detail or "Message accepted (250 OK) – server delivers spoofed headers",
                        "vuln_note": sh.vulnerable_note,
                    }
                )

        # BCC (PTL-SVC-SMTP-BCC) – manual verification, no auto vuln
        if (bc_err := self.results.bcc_test_error) is not None:
            properties.update({"bccTestError": bc_err})
        elif (bc := self.results.bcc_test) is not None:
            properties.update({
                "bccTest": {
                    "messageAccepted": bc.message_accepted,
                    "smtpStatus": bc.smtp_status,
                    "smtpReply": bc.smtp_reply,
                    "recipientsTo": list(bc.recipients_to),
                    "recipientsCc": list(bc.recipients_cc),
                    "recipientsBcc": list(bc.recipients_bcc),
                    "elapsedSec": round(bc.elapsed_sec, 2),
                    "detail": bc.detail,
                    "verificationInstructions": bc.verification_instructions,
                    "smtpTrace": list(bc.smtp_trace),
                    "testId": bc.test_id or None,
                }
            })

        # Alias (PTL-SVC-SMTP-ALIAS) – manual verification, no auto vuln
        if (al_err := self.results.alias_test_error) is not None:
            properties.update({"aliasTestError": al_err})
        elif (al := self.results.alias_test) is not None:
            properties.update({
                "aliasTest": {
                    "baseAddress": al.base_address,
                    "elapsedSec": round(al.elapsed_sec, 2),
                    "detail": al.detail,
                    "verificationInstructions": al.verification_instructions,
                    "variants": [
                        {
                            "variant": v.variant,
                            "address": v.address,
                            "accepted": v.accepted,
                            "rejected": v.rejected,
                            "error": v.error,
                            "smtpStatus": v.smtp_status,
                            "smtpReply": v.smtp_reply,
                            "detail": v.detail,
                            "uucpWarning": v.uucp_warning,
                            "smtpTrace": list(v.smtp_trace),
                            "testId": v.test_id or None,
                        }
                        for v in al.variants
                    ],
                }
            })

        # Rate limiting
        if (rl_err := self.results.rate_limit_error) is not None:
            properties.update({"rateLimitError": rl_err})
        elif rl := self.results.rate_limit:
            properties.update({
                "connected": rl.connected,
                "maxAttempts": rl.max_attempts,
                "banned": rl.banned,
                "banDurationProbeRan": rl.ban_duration_probe_ran,
                "banDurationSeconds": rl.ban_duration_seconds,
                "banDurationExceeded": rl.ban_duration_exceeded,
                "initialTimeoutSeconds": rl.initial_timeout_seconds,
                "initialTimeoutExceeded": rl.initial_timeout_exceeded,
                "idleTimeoutSeconds": rl.idle_timeout_seconds,
                "idleTimeoutExceeded": rl.idle_timeout_exceeded,
            })

        # NOOP flood, single connection (-ts NOOP1)
        if (nf1_err := self.results.noop_flood1_error) is not None:
            properties.update({"noopFlood1Error": nf1_err})
        elif (nf1 := self.results.noop_flood1) is not None:
            properties.update({
                "noopFlood1": {
                    "commandsSent": nf1.commands_sent,
                    "commandsOk": nf1.commands_ok,
                    "commandsError": nf1.commands_error,
                    "disconnected": nf1.disconnected,
                    "disconnectAfter": nf1.disconnect_after,
                    "hitCommandCap": nf1.hit_command_cap,
                    "hitTimeCap": nf1.hit_time_cap,
                    "minRtSeconds": nf1.min_rt_seconds,
                    "maxRtSeconds": nf1.max_rt_seconds,
                    "avgRtSeconds": nf1.avg_rt_seconds,
                    "baselineAvgSeconds": nf1.baseline_avg_seconds,
                    "lastWindowAvgSeconds": nf1.last_window_avg_seconds,
                    "slowdownDetected": nf1.slowdown_detected,
                    "errorRatePct": nf1.error_rate_pct,
                }
            })

        # NOOP flood 2 (-nf2)
        if (nf2_err := self.results.noop_flood2_error) is not None:
            properties.update({"noopFlood2Error": nf2_err})
        elif (nf2 := self.results.noop_flood2) is not None:
            properties.update({
                "noopFlood2": {
                    "requestedConnections": nf2.requested_connections,
                    "establishedConnections": nf2.established_connections,
                    "runDurationSeconds": nf2.run_duration_seconds,
                    "commandsSent": nf2.commands_sent,
                    "commandsOk": nf2.commands_ok,
                    "commandsError": nf2.commands_error,
                    "minRtSeconds": nf2.min_rt_seconds,
                    "maxRtSeconds": nf2.max_rt_seconds,
                    "avgRtSeconds": nf2.avg_rt_seconds,
                    "errorRatePct": nf2.error_rate_pct,
                    "activeConnectionsEnd": nf2.active_connections_end,
                    "disconnectedDuringTest": nf2.disconnected_during_test,
                    "earlyExitNoConnections": nf2.early_exit_no_connections,
                    "establishErrors": nf2.establish_errors,
                    "establishDisconnected": nf2.establish_disconnected,
                    "establishTimeouts": nf2.establish_timeouts,
                    "reapedBeforeStorm": nf2.reaped_before_storm,
                    "stormPoolConnections": nf2.storm_pool_connections,
                    "terminatedConnections": [
                        {"index": idx, "reason": reason, "detail": detail}
                        for idx, reason, detail in nf2.terminated_connections
                    ],
                }
            })

        # Login bruteforce
        if (creds := self.results.creds) is not None:
            if len(creds) > 0:
                json_lines: list[str] = []
                for cred in creds:
                    json_lines.append(f"user: {cred.user}, password: {cred.passw}")

                if self.args.user is not None:
                    if isinstance(self.args.user, list):
                        user_str = f"usernames: {', '.join(self.args.user)}"
                    else:
                        user_str = f"username: {self.args.user}"
                else:
                    user_str = f"usernames: {self.args.users}"

                if self.args.password is not None:
                    passw_str = f"password: {self.args.password}"
                else:
                    passw_str = f"passwords: {self.args.passwords}"

                global_vulns.append(
                    {
                        "vuln_code": VULNS.WeakCreds.value,
                        "vuln_request": f"{user_str}\n{passw_str}",
                        "vuln_response": "\n".join(json_lines),
                    }
                )

        # Create main software node (vulnerabilities are always global)
        smtp_node = self.ptjsonlib.create_node_object(
            "software",
            None,
            None,
            properties,
        )
        self.ptjsonlib.add_node(smtp_node)

        # Create userAccount child nodes for enumerated users
        if (enum_results := self.results.enum_results) is not None:
            for e in enum_results:
                if e.vulnerable and e.results is not None:
                    for user in sorted(e.results, key=str):
                        local_part = str(user).split("@")[0] if "@" in str(user) else str(user)
                        user_props = {"name": local_part, "email": str(user)}
                        user_node = self.ptjsonlib.create_node_object(
                            "userAccount",
                            parent_type="userAccounts",
                            parent=None,
                            properties=user_props,
                        )
                        self.ptjsonlib.add_node(user_node)

        # All vulnerabilities go to global results.vulnerabilities[]
        for v in global_vulns:
            self.ptjsonlib.add_vulnerability(**v)

        self.ptjsonlib.set_status("finished", "")
        self.ptprint(self.ptjsonlib.get_result_json(), json=True)
