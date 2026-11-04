"""Durable per-input batch state. Only verified artifacts may be reused."""
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import uuid


def digest(path):
    h = hashlib.sha256()
    try:
        if not stat.S_ISREG(os.stat(path).st_mode):
            return None
        with open(path, 'rb') as stream:
            while True:
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


class Checkpoint:
    def __init__(self, directory, config, inputs, resume):
        self.directory = directory
        path = directory / 'checkpoint.sqlite3'
        if resume and (not path.is_file() or path.is_symlink()):
            raise ValueError('checkpoint missing or invalid')
        self.db = sqlite3.connect(path)
        self.db.execute('PRAGMA synchronous=FULL')
        if resume:
            try:
                if self.db.execute('PRAGMA quick_check').fetchone() != ('ok',):
                    raise ValueError('checkpoint integrity check failed')
                stored = dict(self.db.execute('SELECT key, value FROM meta'))
                if set(stored) != {'schema', 'config', 'inputs'} or stored['schema'] != '1':
                    raise ValueError('unsupported checkpoint metadata')
                if json.loads(stored['config']) != config or json.loads(stored['inputs']) != inputs:
                    raise ValueError('checkpoint parameters or input list differ')
                rows = self.db.execute('SELECT idx, input_hash, engine_hash, result, output_hash, stderr_hash FROM jobs').fetchall()
                if len(rows) > len(inputs) or any(not isinstance(row[0], int) or row[0] < 0 or row[0] >= len(inputs) for row in rows):
                    raise ValueError('invalid checkpoint job index')
                for index, input_hash, engine_hash, data, output_hash, stderr_hash in rows:
                    value = json.loads(data)
                    hashes = (input_hash, engine_hash, output_hash, stderr_hash)
                    if any(item is not None and (not isinstance(item, str) or len(item) != 64 or any(c not in '0123456789abcdef' for c in item)) for item in hashes):
                        raise ValueError('invalid checkpoint hash')
                    if not isinstance(value, dict) or value.get('input') != inputs[index] or value.get('status') not in ('ok', 'failed', 'timeout', 'cancelled', 'output_limit'):
                        raise ValueError('invalid checkpoint job result')
                    for key in ('output', 'stderr'):
                        name = value.get(key)
                        if name is not None and (not isinstance(name, str) or not name or Path(name).name != name):
                            raise ValueError('invalid checkpoint artifact name')
            except (sqlite3.Error, ValueError, TypeError, json.JSONDecodeError) as error:
                self.db.close()
                raise ValueError('invalid checkpoint: ' + str(error)) from error
            self.rows = {row[0]: row[1:] for row in rows}
        else:
            self.db.execute('CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)')
            self.db.execute('CREATE TABLE jobs (idx INTEGER PRIMARY KEY, input_hash TEXT, engine_hash TEXT NOT NULL, result TEXT NOT NULL, output_hash TEXT, stderr_hash TEXT)')
            self.db.executemany('INSERT INTO meta VALUES (?, ?)', [('schema','1'), ('config',json.dumps(config, sort_keys=True)), ('inputs',json.dumps(inputs))])
            self.db.commit()
            self.rows = {}

    def reusable(self, index, source, engine_hash):
        row = self.rows.get(index)
        if not row:
            return None
        input_hash, old_engine, data, output_hash, stderr_hash = row
        current = digest(source)
        if not current or current != input_hash or old_engine != engine_hash:
            return None
        try:
            result = json.loads(data)
            if not isinstance(result, dict) or result.get('input') != source or result.get('status') != 'ok':
                return None
            for key, expected in [('output', output_hash), ('stderr', stderr_hash)]:
                name = result.get(key)
                if not isinstance(name, str) or Path(name).name != name or not expected:
                    return None
                artifact = self.directory / name
                if artifact.is_symlink() or digest(artifact) != expected:
                    return None
            return result
        except (TypeError, ValueError):
            return None

    def save(self, index, source_hash, engine_hash, result):
        def artifact_hash(key):
            name = result.get(key)
            return digest(self.directory / name) if isinstance(name, str) and Path(name).name == name else None
        row = (index, source_hash, engine_hash, json.dumps(result, sort_keys=True), artifact_hash('output'), artifact_hash('stderr'))
        self.db.execute('INSERT OR REPLACE INTO jobs VALUES (?, ?, ?, ?, ?, ?)', row)
        self.db.commit()

    def close(self):
        self.db.close()


def attempt_id():
    return uuid.uuid4().hex
