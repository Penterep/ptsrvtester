import time

from ptsrvtester.protocols.dhcp.utils.registry import (
    random_xid,
    random_mac,
    get_option,
    prepare_request_packet,
    sendp,
    DHCP,
    print_dhcp_options,
    DHCPTypes
)

from scapy.sendrecv import AsyncSniffer

__MODULELABEL__ = "DHCP REQUEST sender"
__MODULECODE__ = "request"
__ORDER__ = 100

def _request(ctx):
    """Run DHCP REQUEST sender"""
    src_mac = ctx.mac or random_mac()
    transaction_id = ctx.xid or random_xid()
    ack_filter = f"udp and src port 67 and (ether dst ff:ff:ff:ff:ff:ff or ether dst {src_mac})"

    try:
        def is_ack_packet(packet):
            if packet.haslayer(DHCP):
                for opt in packet[DHCP].options:
                    if isinstance(opt, tuple) and opt[0] == "message-type":
                        msg_type = opt[1]

                        if msg_type == DHCPTypes.ACK: # DHCPACK
                            ctx.out(f"Successfully requested {ctx.requested_ip} and received a DHCP ACK message", "VULN", indent=4)
                            ctx.out(f"Received DHCP options:", "INFO", indent=4)
                            print_dhcp_options(ctx, packet[DHCP].options, 4)
                            return True
                        elif msg_type == DHCPTypes.NAK: # DCHPNACK
                            msg = get_option(packet[DHCP].options, "error_message")

                            if isinstance(msg, bytes):
                                msg = msg.decode("utf-8")

                            ctx.out(f"Could not reserve {ctx.requested_ip}: {msg}", "OK", indent=4)
                            return False

                        else:
                            ctx.out(f"Got unexpected DHCP message type: {packet[DHCP]} {hex(msg_type)}", "WARNING", indent=4)

            return False

        sniffer = AsyncSniffer(
            iface=ctx.interface,
            filter=ack_filter,
            promisc=True,
            stop_filter=is_ack_packet,
            timeout=ctx.timeout
        )  # Use async sniffer to prevent race conditions

        sniffer.start()
        time.sleep(0.05)

        sendp(prepare_request_packet(src_mac, transaction_id, ctx.requested_ip), iface=ctx.interface,
              verbose=False)

        sniffer.join()
        res = sniffer.results

        if res is None or len(res) == 0:
            ctx.out("The DHCP server returned no response", "OK", indent=4)

    except Exception as e:
        ctx.out(f"Failed sending DHCP REQUEST to server: {e}", "ERROR", indent=4)


def run(ctx):
    _request(ctx)