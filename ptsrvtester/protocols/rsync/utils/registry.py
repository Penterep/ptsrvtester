import socket


def receive(sock: socket.socket) -> bytes:
    data = b""

    while True:
        try:
            chunk = sock.recv(8192)
        except socket.timeout:
            break
        if not chunk:
            break
        data += chunk

        if b"@RSYNCD: EXIT" in data:
            break
        if b"@ERROR" in data:
            break

    return data

def split_module_list(modules: str) -> list:
    return modules.split(",")