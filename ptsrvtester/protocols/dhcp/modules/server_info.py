from ptsrvtester.protocols.dhcp.utils.registry import (random_xid, random_mac,
                                                       sendp, prepare_discover_packet, DHCP, sniff, BOOTP)


__MODULELABEL__ = "DHCP server information enumeration"
__MODULECODE__ = "server_info"
__ORDER__ = 100


def _check_lease(lease):
    return int(lease) >= 2592000

def _is_relay(offered_ip: str|None, server_ip: str, subnet_mask: str|None):
    if offered_ip is None or subnet_mask is None:
        return False

    n_octets = len(list(filter(lambda a: a != '0', subnet_mask.split('.'))))

    return offered_ip.split('.')[:n_octets] != server_ip.split('.')[:n_octets]


def _get_subnet_mask(options: list) -> str|None:
    for o in options:
        if isinstance(o, tuple):
            key, value = o
            if key == "subnet_mask":
                return value

    return None


def _get_server_info(ctx):
    """Retrieve DHCP server information"""

    src_mac = ctx.mac or random_mac()
    transaction_id = ctx.xid or random_xid()
    offer_filter = f"udp and src port 67 and (ether dst ff:ff:ff:ff:ff:ff or ether dst {src_mac})"

    try:
        sendp(prepare_discover_packet(src_mac, transaction_id), ctx.interface, verbose=False)

        def is_offer_packet(packet):
            if packet.haslayer(DHCP):
                offered_ip = packet[BOOTP].yiaddr if packet.haslayer(BOOTP) else None
                options = packet[DHCP].options
                ctx.out("DHCP Server Information", "VULN", indent=4)

                for o in range(1, len(options)):
                    b_type = "INFO"
                    if options[o] == "end":
                        break
                    option = options[o]
                    if isinstance(option, tuple):
                        key, *values = option
                        value_str = ", ".join(str(v) for v in values)
                    else:
                        key, value_str = str(option), ""

                    if key == "lease_time" and _check_lease(value_str):
                        b_type = "WARN"

                    ctx.out(f"{key + ':':<24}{value_str}", b_type, indent=8)

                    if key == "server_id":
                        if _is_relay(offered_ip, value_str, _get_subnet_mask(options)):
                            ctx.out(f"DHCP relay detected", "INFO", indent=12)

                return True

            return False


        res = sniff(iface=ctx.interface, filter=offer_filter, promisc=True,
                    timeout=ctx.timeout, stop_filter=is_offer_packet)

        if len(res) == 0:
            ctx.out("No DHCP server information accessible", "OK", indent=4)
    except Exception as e:
        ctx.out(f"Error retrieving DHCP information: {str(e)}", "ERROR", indent=4)


def run(ctx):
    _get_server_info(ctx)