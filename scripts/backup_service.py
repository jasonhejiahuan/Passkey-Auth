#!/usr/bin/python3
from pathlib import Path
from datetime import datetime, timezone
import os, sqlite3
os.umask(0o077)
source = Path('/var/lib/jason-passkey-auth/auth-v2.sqlite3')
folder = Path('/var/backups/jason-passkey-auth')
if not source.is_file():
    raise SystemExit('Authentication database is not ready')
name = 'auth-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '.sqlite3'
temporary = folder / (name + '.partial')
try:
    with sqlite3.connect(f'file:{source}?mode=ro', uri=True) as incoming, sqlite3.connect(temporary) as outgoing:
        incoming.backup(outgoing)
        if outgoing.execute('PRAGMA quick_check').fetchone()[0] != 'ok':
            raise RuntimeError('Backup integrity check failed')
    temporary.replace(folder / name)
    for old in sorted(folder.glob('auth-*.sqlite3'))[:-14]:
        old.unlink()
finally:
    temporary.unlink(missing_ok=True)
