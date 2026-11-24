import pymysql


__MODULELABEL__ = "MySQL TLS/SSL detection module"
__MODULECODE__ = "encrypt"
__ORDER__ = 10


def connect(t, tls_ctx=None, **extra):
    return pymysql.connect(host=t.ip, port=t.port, user=t.username,
                           password=t.password, ssl=tls_ctx, connect_timeout=10, **extra)


def check_plaintext_refused(ctx):
    try:
        connect(ctx, ssl_disabled=True).close()
        ctx.out(f"The server accepted an unencrypted connection", "VULN", indent=4)
        ctx.ptjsonlib.add_vulnerability("PTV-SRV-MYSQL-UNENCRYPTED-COMMS")
        return
    except pymysql.err.OperationalError as e:
        if e.args[0] == 3159:   # ER_SECURE_TRANSPORT_REQUIRED
            ctx.out(f"The server refused an unencrypted connection", "OK", indent=4)
            return
        ctx.out(f"Could not establish a connection to server", "OK", indent=4)


def run(ctx):
    check_plaintext_refused(ctx)