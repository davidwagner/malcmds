"""Bounded process parsing with ordered, disk-backed results."""

import multiprocessing
import pickle
import sys
import tempfile
from collections import deque
from itertools import islice
from pathlib import Path


def _spool(reader, arguments, destination):
    with destination.open('wb') as stream:
        for record in reader(*arguments):
            pickle.dump(record, stream, protocol=pickle.HIGHEST_PROTOCOL)


def ordered_records(reader, tasks, workers, scratch, prefix):
    """Parse argument tuples concurrently, yielding records in submission order.

    Keep at most one unconsumed spool per worker. Only this invocation's trusted
    worker output is unpickled. Join workers before removing their files, even
    if parsing fails or the consumer closes the iterator early.
    """
    tasks = iter(tasks)
    initial = list(islice(tasks, workers))
    workers = len(initial)
    if workers <= 1:
        for arguments in initial:
            yield from reader(*arguments)
        for arguments in tasks:
            yield from reader(*arguments)
        return
    scratch.mkdir(parents=True, exist_ok=True)
    print(f'{prefix}: {workers} parsing workers', file=sys.stderr, flush=True)
    with tempfile.TemporaryDirectory(dir=scratch, prefix=f'{prefix}-workers-') as temporary:
        pool = multiprocessing.get_context('spawn').Pool(workers)
        pending = deque()
        try:
            for index, arguments in enumerate(initial):
                destination = Path(temporary) / f'{index}.pickle'
                pending.append((destination, pool.apply_async(_spool, (reader, arguments, destination))))
            index = workers
            while pending:
                destination, job = pending.popleft()
                job.get()
                with destination.open('rb') as stream:
                    while stream.peek(1):
                        yield pickle.load(stream)
                destination.unlink()
                arguments = next(tasks, None)
                if arguments is not None:
                    destination = Path(temporary) / f'{index}.pickle'
                    pending.append((destination, pool.apply_async(_spool, (reader, arguments, destination))))
                    index += 1
            pool.close()
            pool.join()
        finally:
            pool.terminate()
            pool.join()
