"""Read restored data and execute a rollback-only legitimate transaction."""
import json
import sqlite3
import threading
import urllib.request
from pathlib import Path

path = Path('/restore/source/checkpoint.db')
result = {'status': 'failed'}
try:
    # Copy only inside this container's tmpfs to exercise a real transaction.
    import shutil
    scratch = Path('/tmp/check.db')
    shutil.copyfile(path, scratch)
    with sqlite3.connect(scratch) as db:
        assert db.execute('pragma integrity_check').fetchone()[0] == 'ok'
        accounts = list(db.execute('select id,balance from accounts order by id'))
        assert len(accounts) == 2 and sum(row[1] for row in accounts) == 1000
        assert all(row[1] >= 0 for row in accounts)
        assert dict(db.execute('select name,value from trust')) == {'build': 'clean-fixture-v1'}
    import app
    app.DB = scratch
    service = app.ThreadingHTTPServer(('127.0.0.1', 0), app.Handler)
    threading.Thread(target=service.serve_forever, daemon=True).start()
    try:
        with urllib.request.urlopen(f'http://127.0.0.1:{service.server_port}/transaction', timeout=3) as response:
            assert response.status == 200 and json.load(response)['transaction'] == 'committed'
        with sqlite3.connect(scratch) as db:
            assert db.execute('select sum(balance) from accounts').fetchone()[0] == 1000
    finally:
        service.shutdown()
        service.server_close()
    result = {'status': 'verified', 'integrity_ok': True, 'business_invariants_ok': True,
              'clean_build_marker_ok': True, 'transaction_ok': True, 'application_http_ok': True, 'accounts': accounts}
except (OSError, sqlite3.DatabaseError, AssertionError):
    result = {'status': 'failed', 'error': 'RESTORED_APPLICATION_INVARIANT_FAILED'}
print(json.dumps(result))
