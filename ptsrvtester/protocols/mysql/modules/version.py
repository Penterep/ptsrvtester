from ptsrvtester.protocols.mysql.utils.registry import create_mysql_connection


__MODULELABEL__ = "MySQL version detection module"
__MODULECODE__ = "version"
__ORDER__ = 10


def _mysql_grab_version(ctx):
    connection = create_mysql_connection(ctx)

    if connection is None:
        return

    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT VERSION();")
            row = cursor.fetchone()
        version_string = row[0] if row else None
        if version_string:
            ctx.out(f"Detected MySQL server version: {version_string}", "INFO", indent=4)
        else:
            ctx.out("No version string was returned", "INFO", indent=4)
    finally:
        connection.close()


def run(ctx):
    _mysql_grab_version(ctx)