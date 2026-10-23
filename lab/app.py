"""Synthetic transaction oracle. No shell, exploit or real customer data."""
import json
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

DB = Path('/state/app.db')


def connect():
    db = sqlite3.connect(DB, timeout=5)
    db.execute('pragma journal_mode=DELETE')
    return db


def initialize():
    with connect() as db:
        db.execute('create table if not exists counts(name text primary key, value integer not null)')
        for name in ('reached', 'harm', 'legitimate', 'background', 'long_started', 'long_finished'):
            db.execute('insert or ignore into counts values (?,0)', (name,))
        db.execute('create table if not exists accounts(id integer primary key, balance integer not null check(balance >= 0))')
        db.execute('insert or ignore into accounts values (1,600),(2,400)')
        db.execute('create table if not exists trust(name text primary key, value text not null)')
        db.execute("insert or ignore into trust values ('build','clean-fixture-v1')")


def increment(name):
    with connect() as db:
        db.execute('update counts set value=value+1 where name=?', (name,))


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def send(self, obj, status=200):
        data = json.dumps(obj, sort_keys=True).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parts = urlsplit(self.path)
        if parts.path == '/_lab/state':
            with connect() as db:
                counts = dict(db.execute('select name,value from counts'))
                accounts = list(db.execute('select id,balance from accounts order by id'))
                trust = dict(db.execute('select name,value from trust'))
            self.send({'counts': counts, 'accounts': accounts, 'trust': trust, 'synthetic': True})
            return
        if parts.path == '/_lab/checkpoint':
            destination = Path('/state/checkpoint.db')
            with connect() as source, sqlite3.connect(destination) as backup:
                source.backup(backup)
            self.send({'checkpoint': 'application-consistent-sqlite-backup'})
            return
        if parts.path == '/_lab/contaminate':
            with connect() as db:
                db.execute("update trust set value='planted-contamination' where name='build'")
            self.send({'synthetic_contamination': True})
            return
        if parts.path == '/_lab/clean-fixture':
            with connect() as db:
                db.execute("update trust set value='clean-fixture-v1' where name='build'")
            self.send({'synthetic_clean_marker_restored': True})
            return
        if parts.path in {'/_lab/data-loss', '/_lab/reset-data', '/_lab/inconsistent'}:
            with connect() as db:
                db.execute('delete from accounts')
                if parts.path != '/_lab/data-loss':
                    db.execute('insert into accounts values (1,600),(2,400)')
                if parts.path == '/_lab/inconsistent':
                    db.execute('update accounts set balance=599 where id=1')
            self.send({'synthetic_data_stimulus': parts.path.rsplit('/', 1)[-1]})
            return
        increment('reached')
        if parts.path == '/fixture-operation':
            # This intentionally planted counter is not a vulnerable application/exploit.
            increment('harm')
            self.send({'synthetic_operation_reached': True})
        elif parts.path == '/transaction':
            with connect() as db:
                debited = db.execute('update accounts set balance=balance-1 where id=1 and balance>0').rowcount
                if debited:
                    db.execute('update accounts set balance=balance+1 where id=2')
                db.execute("update counts set value=value+1 where name='legitimate'")
            self.send({'transaction': 'committed' if debited else 'insufficient_funds'}, 200 if debited else 409)
        elif parts.path == '/long':
            increment('long_started')
            seconds = min(4, max(0, int(parse_qs(parts.query).get('seconds', ['2'])[0])))
            time.sleep(seconds)
            increment('long_finished')
            self.send({'long_finished': True})
        elif parts.path == '/start-background':
            def finish():
                time.sleep(2)
                increment('background')
            threading.Thread(target=finish, daemon=True).start()
            self.send({'background_started': True})
        else:
            self.send({'healthy': True})


if __name__ == '__main__':
    initialize()
    ThreadingHTTPServer(('0.0.0.0', 8000), Handler).serve_forever()
