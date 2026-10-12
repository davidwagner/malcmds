"""Real subprocess hangs must fail promptly without leaving parsing workers."""

import sys
import time
from pathlib import Path

import pytest
from test_ingest_batches import invoke


@pytest.mark.skipif(sys.platform != 'linux', reason='Inspect worker state through /proc')
@pytest.mark.parametrize('parent_exits', [False, True])
def test_ingest_timeout_kills_workers_and_reports_output(tmp_path, parent_exits):
    """Bound both a stuck driver and pipes held open by its surviving worker."""
    source = '''
import os
import subprocess
import time

def records(root, options):
    worker = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])
    (root / 'worker.pid').write_text(str(worker.pid))
    print('driver stdout', flush=True)
    print('driver stderr', file=sys.stderr, flush=True)
    if PARENT_EXITS:
        os._exit(0)
    time.sleep(60)
    return []
'''.replace('PARENT_EXITS', repr(parent_exits))
    started = time.monotonic()
    with pytest.raises(AssertionError, match='Ingestion timed out after 4 seconds') as failure:
        invoke(tmp_path, tmp_path / 'hang.duckdb', source, timeout=4)
    assert time.monotonic() - started < 10, 'Inherited worker pipes prevented timeout cleanup'
    message = str(failure.value)
    assert 'driver stdout' in message and 'driver stderr' in message
    if not parent_exits:
        assert 'Timeout' in message and 'in records' in message, 'Missing hung driver traceback'
    pid = int((tmp_path / 'worker.pid').read_text())
    status = Path(f'/proc/{pid}/stat')
    deadline = time.monotonic() + 2
    while status.exists():
        try:
            state = status.read_text().rsplit(')', 1)[1].split()[0]
        except FileNotFoundError:
            break
        if state == 'Z':  # Dead; waiting for the system's child reaper.
            break
        assert time.monotonic() < deadline, f'Timed-out worker {pid} is still running'
        time.sleep(0.01)
