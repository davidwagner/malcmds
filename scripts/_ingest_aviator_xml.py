"""Serial byte filtering for AVIATOR's mostly command-free XML exports."""

import codecs
import ctypes
import hashlib
import io
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile
from functools import lru_cache
from pathlib import Path

from _ingest_windows import EVENT_START, event_commands, parse_log, xml_events
from isal import isal_zlib

CHUNK_SIZE = 128 * 1024
CAPACITY = 4096


def export_encoding(stream, *, validate=True):
    """Select AVIATOR's declared codec or validated UTF-8/Windows export codec."""
    prefix = stream.read(4096)
    stream.seek(0)
    if prefix.startswith((b"\xff\xfe", b"\xfe\xff")):
        return "utf-16"
    if prefix.startswith(codecs.BOM_UTF8):
        return "utf-8-sig"
    declaration = re.match(br'''\s*<\?xml\b[^>]*encoding=["']([^"']+)["']''', prefix)
    if declaration:
        encoding = codecs.lookup(declaration[1].decode("ascii")).name
        if encoding not in {"utf-8", "utf-16", "utf-16-le", "utf-16-be", "cp1252", "iso8859-1", "ascii"}:
            raise ValueError(f"Unsupported AVIATOR XML encoding: {encoding}")
        return encoding
    if not validate:
        return "auto"
    decoder = codecs.getincrementaldecoder("utf-8")()
    try:
        while chunk := stream.read(1024 * 1024):
            decoder.decode(chunk)
        decoder.decode(b"", final=True)
    except UnicodeDecodeError:
        # Publisher Windows exports contain E4 (ä) and F1 (ñ); preserve the
        # exported text, including mojibake already present in raw EVTX.
        return "cp1252"
    finally:
        stream.seek(0)
    return "utf-8"

class ExportReader(io.BufferedReader):
    """Use ISA-L inside ZipExtFile, retaining its ZIP framing and CRC checks.

    ZipFile has no decompressor factory argument. These private attributes are
    covered by integration tests for seeking, ZIP64, codecs and corrupt CRCs.
    """

    def __init__(self, raw):
        super().__init__(raw, buffer_size=CHUNK_SIZE)
        self._accelerate()
        raw._update_crc = self._update_crc

    def _accelerate(self):
        # Seeking backwards can create a fresh stdlib decoder. Replace it only
        # at the beginning of the compressed stream, before it has consumed data.
        if (self.raw._compress_type == zipfile.ZIP_DEFLATED
                and self.raw._compress_left == self.raw._orig_compress_size):
            self.raw._decompressor = isal_zlib.decompressobj(-15)

    def seek(self, offset, whence=0):
        """Rewind encoding probes and re-enable ISA-L after a decoder reset."""
        position = super().seek(offset, whence)
        self._accelerate()
        return position

    def _update_crc(self, data):
        raw = self.raw
        # ZipExtFile sets _expected_crc from the central directory for every
        # actual ZIP member. None is only used by manually constructed readers.
        if raw._expected_crc is None:
            return
        raw._running_crc = isal_zlib.crc32(data, raw._running_crc)
        if raw._eof and raw._running_crc != raw._expected_crc:
            raise zipfile.BadZipFile(f"Bad CRC-32 for file {raw.name!r}")


@lru_cache(maxsize=1)
def _scanner():
    source = Path(__file__).with_name('_aviator_scan.c')
    cache = source.parent.parent / 'tmp' / 'ingest' / 'aviator-native'
    digest = hashlib.sha256(source.read_bytes()).hexdigest()[:20]
    library = cache / f'{digest}.so'
    if not library.exists():
        compiler = shutil.which('cc')
        if compiler is None:
            # Preserve portability: bounded runs and hosts without a C compiler
            # use the established parser. A compiler enables the fast path.
            return None
        cache.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=cache) as temporary:
            output = Path(temporary) / 'scan.so'
            subprocess.run([compiler, '-O3', '-std=c99', '-shared', '-fPIC',
                            str(source), '-o', str(output)], check=True, capture_output=True)
            output.replace(library)
    native = ctypes.CDLL(str(library))
    scan = native.aviator_scan
    pointer = ctypes.POINTER(ctypes.c_size_t)
    scan.argtypes = [ctypes.c_char_p, ctypes.c_size_t, pointer, ctypes.c_size_t,
                     pointer, pointer]
    scan.restype = ctypes.c_size_t
    return scan


class ExportCodec:
    """Resolve undeclared UTF-8/CP1252 without decompressing the export twice."""

    def __init__(self, encoding):
        self.encoding = encoding
        self.decoder = codecs.getincrementaldecoder('utf-8')()
        self.undefined = None

    def check(self, chunk, *, final=False):
        """Validate all bytes, including records discarded by the command filter."""
        if self.encoding in {'auto', 'cp1252'} and self.undefined is None:
            self.undefined = next((byte for byte in
                                   (b'\x81', b'\x8d', b'\x8f', b'\x90', b'\x9d')
                                   if byte in chunk), None)
        if self.encoding != 'cp1252':
            try:
                self.decoder.decode(chunk, final=final)
            except UnicodeDecodeError:
                if self.encoding != 'auto':
                    raise
                self.encoding = 'cp1252'
        if self.encoding == 'cp1252' and self.undefined is not None:
            self.undefined.decode('cp1252')
        if final and self.encoding == 'auto':
            self.encoding = 'utf-8'


def _candidate_bytes(stream, codec, scan):
    spans = (ctypes.c_size_t * (CAPACITY * 3))()
    consumed, count = ctypes.c_size_t(), ctypes.c_size_t()
    number = 0
    tail = b''
    parts = []
    while chunk := stream.read(CHUNK_SIZE):
        codec.check(chunk)
        block = tail + chunk
        if parts:
            if b'</Event>' not in block:
                parts.append(block[:-7])
                tail = block[-7:]
                continue
            block = b''.join(parts) + block
            parts.clear()
        while block:
            found = scan(block, len(block), spans, CAPACITY,
                         ctypes.byref(consumed), ctypes.byref(count))
            for index in range(found):
                start, size, ordinal = spans[index * 3:index * 3 + 3]
                yield number + ordinal, block[start:start + size]
            previous = number
            number += count.value
            if number // 100000 > previous // 100000:
                print(f'aviator: {number:,} XML events scanned', file=sys.stderr, flush=True)
            block = block[consumed.value:]
            if found < CAPACITY:
                break
        # Keep large events in pieces and search new bytes only, avoiding
        # quadratic concatenation and rescanning of an unfinished event.
        if len(block) > 7:
            parts.append(block[:-7])
            tail = block[-7:]
        else:
            tail = block
    codec.check(b'', final=True)
    # The original framer checks any unfinished event and ignores trailing text.
    yield number + 1, b''.join(parts) + tail


def _pending_candidates(pending, encoding):
    pending.seek(0)
    while header := pending.read(16):
        number, size = struct.unpack('<QQ', header)
        yield number, pending.read(size), encoding
    pending.seek(0)
    pending.truncate()


def _encoded_candidates(stream, encoding, scan):
    codec = ExportCodec(encoding)
    scratch = Path(__file__).parent.parent / 'tmp' / 'ingest'
    scratch.mkdir(parents=True, exist_ok=True)
    # ASCII is identical in both codecs. Once an ambiguous candidate occurs,
    # defer it and subsequent candidates until the codec is known, preserving
    # order. Only candidate XML is spooled, with bounded resident memory.
    with tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024, dir=scratch) as pending:
        deferred = False
        for number, raw in _candidate_bytes(stream, codec, scan):
            if codec.encoding == 'auto' and (deferred or not raw.isascii()):
                pending.write(struct.pack('<QQ', number, len(raw)))
                pending.write(raw)
                deferred = True
                continue
            if deferred:
                yield from _pending_candidates(pending, codec.encoding)
                deferred = False
            yield number, raw, 'ascii' if codec.encoding == 'auto' else codec.encoding


def filtered_events(stream, encoding, scan):
    """Yield command candidates with the reference parser's fields and ordinals."""
    rejected = 0
    for number, raw, codec in _encoded_candidates(stream, encoding, scan):
        text = raw.decode(codec).replace('\r\n', '\n').replace('\r', '\n')
        events = list(xml_events(io.StringIO(text), commands_only=True))
        if not events:
            rejected += 1
        else:
            yield number - rejected, events[0][1]


def parse_export(stream, source, dataset, budget, label, group, *, encoding, accelerated=True):
    """Filter unbounded UTF-8/CP1252 XML; retain other formats and record bounds."""
    if accelerated and encoding in {'auto', 'utf-8', 'cp1252'} and budget.remaining is None:
        # Latin-1 preserves ASCII framing without guessing the eventual codec.
        prefix = stream.peek(4096)[:4096].decode('latin1')
        if EVENT_START.search(prefix) and (scan := _scanner()) is not None:
            print(f'{dataset}: reading {source}', file=sys.stderr, flush=True)
            for number, fields in filtered_events(stream, encoding, scan):
                if fields:
                    yield from event_commands(fields, dataset, source, number, label, group)
            return
    if encoding == 'auto':
        encoding = export_encoding(stream)
    yield from parse_log(stream, source, dataset, budget, label, group, encoding=encoding)
