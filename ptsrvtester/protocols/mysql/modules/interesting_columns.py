from ptsrvtester.protocols.mysql.utils.registry import create_mysql_connection


__MODULELABEL__ = "MySQL interesting columns location module"
__MODULECODE__ = "INTERESTING_COLUMNS"
__ORDER__ = 10


QUERY_INTERESTING="""
SELECT table_schema, table_name, column_name FROM information_schema.COLUMNS 
WHERE column_name LIKE '%password%' 
   OR column_name LIKE '%pass%'
   OR column_name LIKE '%pwd%'
   OR column_name LIKE '%secret%'
   OR column_name LIKE '%token%';
"""


def _get_databases(ctx, cursor) -> list[str]:
    qry = "SHOW databases;"
    ctx.debug(f"Executed query: {qry}")
    cursor.execute(qry)
    query_response = cursor.fetchall()
    ctx.debug(f"Affected row count: {cursor.rowcount}")

    if query_response:
        return [db[0] for db in query_response if db[0] not in ["sys", "mysql", "information_schema", "performance_schema"]]

    return []

def _get_tables(ctx, cursor, database) -> dict:
    qry = f"SHOW tables in {database}"
    ctx.debug(f"Executed query: {qry}")
    cursor.execute(qry)
    query_response = cursor.fetchall()
    ctx.debug(f"Affected row count: {cursor.rowcount}")

    tables = {}

    if query_response:
        for table in query_response:
            tables.update({table[0]: None})
        return tables

    return {}

def _get_columns(ctx, cursor, db, table) -> list[str]:
    query_manual = f"""
    SHOW columns in {db}.{table} WHERE Field LIKE '%password%' 
    or Field LIKE '%pass%'
    or Field LIKE '%pwd%'
    or Field LIKE '%secret%'
    or Field LIKE '%token%'
    """
    ctx.debug(f"Executed query: {query_manual}")
    cursor.execute(query_manual)
    query_response = cursor.fetchall()
    ctx.debug(f"Affected row count: {cursor.rowcount}")

    if query_response:
        return [column[0] for column in query_response]


    return []

def _probe(ctx, cursor):
    if not (databases := _get_databases(ctx, cursor)):
        ctx.out(f"Could not any non-default fetch databases", "OK", indent=4)

    found = False
    db_tables_dict = {}

    for db in databases:
        db_tables_dict.update({db: _get_tables(ctx, cursor, db)})

    for db, tables in db_tables_dict.items():
        for table_name in tables.keys():
            interesting_columns = _get_columns(ctx, cursor, db, table_name)
            if interesting_columns:
                db_tables_dict[db][table_name] = interesting_columns
                found = True

    if found:
        for db, tables in db_tables_dict.items():
            for table_name, cols in tables.items():
                if cols:
                    ctx.out(f"Interesting columns in '{db}.{table_name}':", "VULN", indent=8)
                    for col in cols:
                        ctx.out(f"{col}", "VULN", indent=12)
    else:
        ctx.out(f"Manual search turned up no interesting columns", "OK", indent=4)


def _mysql_get_interesting_columns(ctx):
    connection = create_mysql_connection(ctx)

    if connection is None:
        return

    try:
        with connection.cursor() as cursor:
            ctx.debug(f"Executed query: {QUERY_INTERESTING}")
            cursor.execute(QUERY_INTERESTING)
            ctx.debug(f"Affected row count: {cursor.rowcount}")
            query_response = cursor.fetchall()

        if query_response:
            ctx.out(f"Found interesting columns:", "VULN", indent=4)
            for database, table_name, column_name in query_response:
                ctx.out(f"Column '{column_name}' in table '{database}.{table_name}'", "VULN", indent=8)
        else:
            ctx.out("Did not manage to locate any interesting columns", "OK", indent=4)
            ctx.out(f"Probing the MySQL manually", "INFO", indent=4)
            _probe(ctx, connection.cursor())
    except Exception as e:
        ctx.out(f"Could not query information_schema.COLUMNS: {e}", "OK", indent=4)
        ctx.out(f"Probing the MySQL manually", "INFO", indent=4)
        _probe(ctx, connection.cursor())

    finally:
        connection.close()

def run(ctx):
    _mysql_get_interesting_columns(ctx)