"""Independent SQL oracle. Execute in disposable in-memory SQLite databases.

Accesses come from SQLite's authorizer, never from the resolver's table name.
https://www.sqlite.org/c3ref/set_authorizer.html
"""
import json
import sqlite3
import sys

results = []
for query in json.load(sys.stdin):
    db = sqlite3.connect(':memory:', cached_statements=0)
    db.executescript("""
      ATTACH DATABASE ':memory:' AS analytics;
      ATTACH DATABASE ':memory:' AS crm;
      CREATE TABLE analytics.metrics(day INTEGER, visits INTEGER);
      INSERT INTO analytics.metrics VALUES (1,42);
      CREATE TABLE crm.customers(id INTEGER, email TEXT);
      INSERT INTO crm.customers VALUES (1,'alice@example.com');
    """)
    reads, writes = set(), []
    def authorize(action, table, column, database, source):
        if action == sqlite3.SQLITE_READ:
            reads.add(f'{database}.{table}')
        if action not in (sqlite3.SQLITE_READ, sqlite3.SQLITE_SELECT):
            writes.append(action)
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK
    db.set_authorizer(authorize)
    try:
        cursor = db.execute(query)
        rows = cursor.fetchall()
        results.append({'reads': sorted(reads), 'writes': writes, 'rows': rows,
                        'columns': [c[0] for c in cursor.description], 'error': None})
    except sqlite3.Error as error:
        results.append({'reads': sorted(reads), 'writes': writes, 'error': str(error)})
    finally:
        db.close()
print(json.dumps({'sqlite': sqlite3.sqlite_version, 'results': results}))
