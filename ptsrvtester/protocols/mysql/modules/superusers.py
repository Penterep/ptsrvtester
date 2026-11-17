from ptsrvtester.protocols.mysql.utils.registry import create_mysql_connection


__MODULELABEL__ = "MySQL superuser enumeration module"
__MODULECODE__ = "superusers"
__ORDER__ = 10


def _mysql_grab_superusers(ctx):
    connection = create_mysql_connection(ctx)

    if connection is None:
        return

    try:
        with connection.cursor() as cursor:
            cursor.execute('select user from mysql.user where Super_priv="Y";')
            query_response = cursor.fetchall()
            superusers = [user[0] for user in query_response if query_response]

        if superusers:
            ctx.out(f"Found users with the SUPER privilege:", "INFO", indent=4)
            [ctx.out(f"{user}", "INFO", indent=8) for user in superusers]
        else:
            ctx.out("No users with the SUPER privilege found", "INFO", indent=4)
    finally:
        connection.close()

def run(ctx):
    _mysql_grab_superusers(ctx)