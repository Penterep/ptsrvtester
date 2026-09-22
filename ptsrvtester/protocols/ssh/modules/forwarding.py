"""FORWARD — SSH port forwarding & tunneling capabilities (post-auth).

Logs in with the supplied credentials and actively probes what the server lets an
authenticated client tunnel (see :mod:`..utils.forwarding_core` for the verdict
logic). Each capability maps to a concrete SSH request:

  * **Local forwarding / SOCKS** — ``open_channel("direct-tcpip", …)`` to a couple
    of loopback destinations. A ``ChannelException`` code 1 is *administratively
    prohibited* (denied); code 2 is *connect failed* (forwarding permitted, the
    destination was merely unreachable); success is permitted. Dynamic/SOCKS
    forwarding (``ssh -D``) rides on the same ``direct-tcpip`` channel, so its
    availability equals local forwarding. Comparing destinations also reveals a
    ``PermitOpen`` allow-list (some allowed, some prohibited).
  * **Remote forwarding** — ``request_port_forward("127.0.0.1", 0)``; the server
    returns a bound port (permitted) or raises (denied). Cancelled immediately.
  * **GatewayPorts** — a wildcard-bind ``request_port_forward("", 0)``; only
    weakly observable (see the core note), so reported informationally.
  * **Agent forwarding** — ``auth-agent-req@openssh.com`` sent with ``want_reply``
    set (paramiko's own helper never asks for a reply) and a timed wait for the
    server's SUCCESS/FAILURE.
  * **X11 forwarding** — ``request_x11()`` (raises when denied).
  * **PTY** — ``get_pty()`` (raises when denied).

Needs valid credentials (``-u`` + ``-p``/``-P``/``--privkeys``); never runs in the
default / ALL sweep (``__RUN_IN_ALL__ = False``).
"""
import paramiko
from paramiko.common import cMSG_CHANNEL_REQUEST
from paramiko.message import Message

# Importing ssh_helpers applies paramiko's legacy-host-key + logging setup as a
# side effect (so old servers still negotiate and paramiko does not spam stderr).
from ptsrvtester.protocols.ssh.utils import ssh_helpers  # noqa: F401
from ptsrvtester.protocols.ssh.utils.helpers import text_or_file
from ptsrvtester.protocols.ssh.utils.results import SSHCreds, VULNS
from ptsrvtester.protocols.ssh.utils.forwarding_core import (
    LocalProbe,
    State,
    assess_forwarding,
)

__MODULELABEL__ = "Port forwarding & tunneling"
__MODULECODE__ = "FORWARD"
__ORDER__ = 36
__RUN_IN_ALL__ = False

_CONNECT_TIMEOUT = 10.0
_PROBE_TIMEOUT = 8.0


def _fwd_creds(a, account: str) -> list[SSHCreds]:
    """Secrets to authenticate as ``account``: private keys if given, else password(s)."""
    if getattr(a, "privkeys", None):
        return [SSHCreds(account, "", pk) for pk in ssh_helpers.parse_privkeys(a.privkeys)]
    passwords = text_or_file(getattr(a, "password", None), getattr(a, "passwords", None))
    return [SSHCreds(account, p, None) for p in passwords]


def _connect(ip: str, port: int, cred: SSHCreds):
    """Authenticate and return an OPEN SSHClient (or None)."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.MissingHostKeyPolicy)
    try:
        if cred.privkey is not None:
            client.connect(
                ip, port, username=cred.user, key_filename=cred.privkey.keypath,
                passphrase=cred.privkey.passphrase, look_for_keys=False,
                allow_agent=False, banner_timeout=_CONNECT_TIMEOUT, timeout=_CONNECT_TIMEOUT,
            )
        else:
            client.connect(
                ip, port, username=cred.user, password=cred.passw, look_for_keys=False,
                allow_agent=False, banner_timeout=_CONNECT_TIMEOUT, timeout=_CONNECT_TIMEOUT,
            )
        return client
    except Exception:
        try:
            client.close()
        except Exception:
            pass
        return None


# --- individual probes --------------------------------------------------------

def _probe_local(transport, host: str, port: int) -> LocalProbe:
    dest = f"{host}:{port}"
    try:
        chan = transport.open_channel(
            "direct-tcpip", (host, port), ("127.0.0.1", 0), timeout=_PROBE_TIMEOUT
        )
        try:
            chan.close()
        except Exception:
            pass
        return LocalProbe(dest, State.ALLOWED, "direct-tcpip channel opened")
    except paramiko.ChannelException as e:
        code = getattr(e, "code", None)
        if code == 1:
            return LocalProbe(dest, State.DENIED, "administratively prohibited")
        if code == 2:
            return LocalProbe(dest, State.ALLOWED, "forwarding permitted (destination unreachable)")
        return LocalProbe(dest, State.ERROR, f"channel error {code}: {getattr(e, 'text', e)}")
    except Exception as e:
        return LocalProbe(dest, State.ERROR, f"{type(e).__name__}: {e}")


def _probe_remote(transport, bind_addr: str) -> tuple[State, str]:
    try:
        bound = transport.request_port_forward(bind_addr, 0)
        try:
            transport.cancel_port_forward(bind_addr, bound)
        except Exception:
            pass
        return State.ALLOWED, f"server bound '{bind_addr or '*'}' port {bound}"
    except paramiko.SSHException as e:
        return State.DENIED, str(e) or "TCP forwarding request denied"
    except Exception as e:
        return State.ERROR, f"{type(e).__name__}: {e}"


def _probe_x11(transport) -> tuple[State, str]:
    try:
        chan = transport.open_session(timeout=_PROBE_TIMEOUT)
    except Exception as e:
        return State.ERROR, f"open_session: {type(e).__name__}: {e}"
    try:
        chan.request_x11(handler=lambda *a, **k: None)
        return State.ALLOWED, "x11-req accepted"
    except paramiko.SSHException as e:
        return State.DENIED, str(e) or "x11-req rejected"
    except Exception as e:
        return State.ERROR, f"{type(e).__name__}: {e}"
    finally:
        try:
            chan.close()
        except Exception:
            pass


def _probe_pty(transport) -> tuple[State, str]:
    try:
        chan = transport.open_session(timeout=_PROBE_TIMEOUT)
    except Exception as e:
        return State.ERROR, f"open_session: {type(e).__name__}: {e}"
    try:
        chan.get_pty()
        return State.ALLOWED, "pty-req accepted"
    except paramiko.SSHException as e:
        return State.DENIED, str(e) or "pty-req rejected"
    except Exception as e:
        return State.ERROR, f"{type(e).__name__}: {e}"
    finally:
        try:
            chan.close()
        except Exception:
            pass


def _probe_agent(transport) -> tuple[State, str]:
    """Send ``auth-agent-req@openssh.com`` with want_reply and wait for the reply.

    paramiko's ``Channel.request_forward_agent`` sends want_reply=0 (and always
    returns True), so it cannot detect the policy. We replicate the request with
    want_reply=1 and wait on the channel's reply event (SUCCESS -> allowed,
    FAILURE closes the channel -> denied, no reply -> unknown).
    """
    try:
        chan = transport.open_session(timeout=_PROBE_TIMEOUT)
    except Exception as e:
        return State.ERROR, f"open_session: {type(e).__name__}: {e}"
    try:
        m = Message()
        m.add_byte(cMSG_CHANNEL_REQUEST)
        m.add_int(chan.remote_chanid)
        m.add_string("auth-agent-req@openssh.com")
        m.add_boolean(True)  # want_reply — the crucial difference from paramiko's helper
        chan.event.clear()
        chan.event_ready = False
        transport._send_user_message(m)
        if not chan.event.wait(_PROBE_TIMEOUT):
            return State.UNKNOWN, "server did not reply to auth-agent-req"
        if getattr(chan, "event_ready", False) and not chan.closed:
            return State.ALLOWED, "server accepted agent forwarding request"
        return State.DENIED, "server rejected agent forwarding request"
    except Exception as e:
        return State.ERROR, f"{type(e).__name__}: {e}"
    finally:
        try:
            chan.close()
        except Exception:
            pass


def run(ctx):
    a = ctx.args
    ip, port = ctx.target

    account = a.user if (isinstance(a.user, str) and a.user) else (
        a.user[0] if isinstance(a.user, list) and a.user else None)
    if not account:
        ctx.out("FORWARD requires -u/--user (account to test)", "WARNING", indent=4)
        return

    creds = _fwd_creds(a, account)
    if not creds:
        ctx.out("FORWARD requires a secret to log in: -p/--password, -P/--passwords or --privkeys",
                "WARNING", indent=4)
        return

    ctx.out(f"Testing forwarding capabilities for '{account}' on {ip}:{port} "
            f"({len(creds)} secret(s))", "INFO", colortext=True, indent=4)

    client = None
    for c in creds:
        client = _connect(ip, port, c)
        if client is not None:
            break

    if client is None:
        _render(ctx, assess_forwarding(account=account, authenticated=False))
        return

    transport = client.get_transport()
    if transport is None:
        try:
            client.close()
        except Exception:
            pass
        _render(ctx, assess_forwarding(
            account=account, authenticated=False,
            auth_note="authenticated but the SSH transport was not available",
        ))
        return

    try:
        # Local forwarding: loopback to sshd's own port (usually reachable) and a
        # closed loopback port; comparing the two separates prohibited from
        # connect-failed and reveals a PermitOpen allow-list.
        local_probes = [
            _probe_local(transport, "127.0.0.1", port),
            _probe_local(transport, "127.0.0.1", 1),
        ]
        remote_state, remote_detail = _probe_remote(transport, "127.0.0.1")
        if remote_state == State.ALLOWED:
            gateway_state, _gw_detail = _probe_remote(transport, "")
        else:
            gateway_state = State.SKIPPED
        agent_state, _ = _probe_agent(transport)
        x11_state, _ = _probe_x11(transport)
        pty_state, _ = _probe_pty(transport)
    finally:
        try:
            client.close()
        except Exception:
            pass

    result = assess_forwarding(
        account=account, authenticated=True, local_probes=local_probes,
        remote=remote_state, gateway=gateway_state, agent=agent_state,
        x11=x11_state, pty=pty_state,
    )
    _render(ctx, result)


# --- rendering ----------------------------------------------------------------

def _cat(state: State, *, allowed="VULN", denied="OK") -> str:
    return {
        State.ALLOWED: allowed,
        State.DENIED: denied,
    }.get(state, "WARNING")


def _render(ctx, r):
    if not r.authenticated:
        ctx.out(f"Forwarding: NOT TESTED — could not authenticate as '{r.account}'",
                "WARNING", indent=4)
        for n in r.notes:
            ctx.out(n, "TEXT", indent=8)
        with ctx.results_lock:
            ctx.properties["forwardAccount"] = r.account
            ctx.properties["forwardVerdict"] = "no-auth"
        return

    # TCP forwarding (local / dynamic-SOCKS / remote) + PermitOpen + GatewayPorts
    ctx.out("TCP port forwarding", "INFO", colortext=True, indent=4)
    ctx.out(f"Local forwarding (-L): {_word(r.local)}", _cat(r.local), indent=8)
    ctx.out(f"Dynamic / SOCKS proxy (-D): {_word(r.dynamic)} (uses local forwarding)",
            _cat(r.dynamic), indent=8)
    ctx.out(f"Remote forwarding (-R): {_word(r.remote)}", _cat(r.remote), indent=8)
    for p in r.local_probes:
        ctx.debug(f"local probe {p.dest}: {p.state.value} — {p.detail}")
    if r.permitopen_restricted:
        ctx.out("PermitOpen restriction detected (allow-list filtering destinations)",
                "WARNING", indent=8)
    if r.gateway == State.ALLOWED:
        ctx.out("GatewayPorts: wildcard remote bind accepted (verify externally — may be "
                "loopback-only under GatewayPorts=no)", "WARNING", indent=8)
    elif r.gateway == State.DENIED:
        ctx.out("GatewayPorts: wildcard remote bind refused", "OK", indent=8)

    # Agent forwarding
    ctx.out("Agent forwarding", "INFO", colortext=True, indent=4)
    ctx.out(_word(r.agent, allowed="PERMITTED — server may reach the client's ssh-agent "
                                   "(agent-hijack risk on a compromised host)",
                  denied="denied", unknown="could not determine (server did not reply)"),
            _cat(r.agent), indent=8)

    # X11 forwarding
    ctx.out("X11 forwarding", "INFO", colortext=True, indent=4)
    ctx.out(_word(r.x11, allowed="PERMITTED — server may open X11 connections back "
                                 "(keystroke/screen-capture risk)",
                  denied="denied"),
            _cat(r.x11), indent=8)

    # PTY / interactive shell
    ctx.out("PTY / interactive shell", "INFO", colortext=True, indent=4)
    ctx.out(_word(r.pty, allowed="pseudo-terminal granted (interactive shell possible)",
                  denied="pseudo-terminal refused"),
            _cat(r.pty, allowed="WARNING"), indent=8)

    for n in r.notes:
        ctx.out(n, "TEXT", indent=8)

    with ctx.results_lock:
        ctx.properties["forwardAccount"] = r.account
        ctx.properties["forwardLocal"] = r.local.value
        ctx.properties["forwardRemote"] = r.remote.value
        ctx.properties["forwardDynamicSocks"] = r.dynamic.value
        ctx.properties["forwardGateway"] = r.gateway.value
        ctx.properties["forwardPermitOpenRestricted"] = r.permitopen_restricted
        ctx.properties["forwardAgent"] = r.agent.value
        ctx.properties["forwardX11"] = r.x11.value
        ctx.properties["forwardPty"] = r.pty.value

        _push_vulns(ctx, r)


def _word(state: State, *, allowed="ALLOWED", denied="denied", unknown=None) -> str:
    if state == State.ALLOWED:
        return allowed
    if state == State.DENIED:
        return denied
    if state == State.SKIPPED:
        return "not tested (remote forwarding is disabled)"
    if state == State.ERROR:
        return "could not be determined (probe error)"
    return unknown or "could not be determined"


def _push_vulns(ctx, r):
    if r.tcp_forwarding_finding:
        kinds = ", ".join(r.enabled_tcp_kinds())
        extra = ""
        if r.gateway == State.ALLOWED:
            extra = "\nGatewayPorts: wildcard remote bind accepted (verify external exposure)"
        if r.permitopen_restricted:
            extra += "\nPermitOpen allow-list is in effect (not a blanket allow)"
        ctx.deferred_vulns.append({
            "vuln_code": VULNS.PortForwarding.value,
            "vuln_request": f"account: {r.account}\ndirect-tcpip / tcpip-forward requests",
            "vuln_response": f"TCP forwarding enabled: {kinds} — usable for pivoting / lateral "
                             f"movement{extra}",
        })
    if r.agent_finding:
        ctx.deferred_vulns.append({
            "vuln_code": VULNS.AgentForwarding.value,
            "vuln_request": f"account: {r.account}\nauth-agent-req@openssh.com (want_reply)",
            "vuln_response": "agent forwarding permitted — a compromised server can reach and use "
                             "the client's ssh-agent keys",
        })
    if r.x11_finding:
        ctx.deferred_vulns.append({
            "vuln_code": VULNS.X11Forwarding.value,
            "vuln_request": f"account: {r.account}\nx11-req",
            "vuln_response": "X11 forwarding permitted — a malicious server can open X11 "
                             "connections back to the client (keystroke/screen capture)",
        })
