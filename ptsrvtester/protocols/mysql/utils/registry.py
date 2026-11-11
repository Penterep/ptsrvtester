import pymysql
from pymysql.connections import Connection


def create_mysql_connection(ctx) -> Connection | None:
    try:
        if ctx.password is None:
            connection = pymysql.connect(
                host=ctx.ip,
                port=ctx.port,
                user=ctx.username
            )
        else:
            connection = pymysql.connect(
                host=ctx.ip,
                port=ctx.port,
                user=ctx.username,
                password=ctx.password
            )
    except Exception as e:
        ctx.ptjsonlib.end_error(
            f"Could not connect to the MySQL server: {e}",
            ctx.json,
        )
        return None

    return connection