from ptsrvtester.protocols.dhcp.utils.registry import (random_xid, random_mac,
                                                       sendp, prepare_discover_packet, DHCP, sniff)


__MODULELABEL__ = "DHCP server information enumeration"
__MODULECODE__ = "server_info"
__ORDER__ = 100


def _get_server_info(ctx):
    """Retrieve DHCP server information"""
    ctx.out("Retrieving DHCP server information...", "INFO", indent=4)

    src_mac = random_mac()
    transaction_id = random_xid()
    offer_filter = f"udp and src port 67 and (ether dst ff:ff:ff:ff:ff:ff or ether dst {src_mac})"

    try:
        sendp(prepare_discover_packet(src_mac, transaction_id), ctx.interface, verbose=False)

        def is_offer_packet(packet):
            if packet.haslayer(DHCP):
                options = packet[DHCP].options
                ctx.out("\n[+] DHCP Server Information", "OK", indent=4)
                for o in range(1, len(options)):
                    if options[o] == "end":
                        break
                    option_str = str(options[o]).replace("(", "").replace(")", "").replace(",", ":\t").replace("'",
                                                                                                               "")
                    ctx.out(f"    {option_str}", "TEXT", indent=4)
                return True
            return False

        res = sniff(iface=ctx.interface, filter=offer_filter, promisc=True,
                    timeout=ctx.timeout, stop_filter=is_offer_packet)

        if len(res) == 0:
            ctx.out("[-] No DHCP server information accessible", "WARNING", indent=4)
    except Exception as e:
        ctx.out(f"[-] Error retrieving DHCP information: {str(e)}", "ERROR", indent=4)


def run(ctx):
    _get_server_info(ctx)