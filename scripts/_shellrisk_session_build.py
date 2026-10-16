"""Reproduce ShellRisk's pinned extraction and retain trajectory positions.

Only the three hash-checked adapter modules are imported as Python code. Raw
trajectory commands are data and are never executed. The extraction loops below
follow those adapters, including counting multiline submissions in emitted IDs.
"""

import hashlib
import importlib.util
import json
import shutil
import sys
import urllib.request
from pathlib import Path

import pyarrow.parquet as pq

from _shellrisk_sessions import file_digest, published_rows, session_identity

CONFIG_PATH = Path(__file__).with_name("shellrisk-sources.json")


def _check(path, pin):
    if (not path.is_file() or path.stat().st_size != pin["size"]
            or file_digest(path) != pin["sha256"]):
        raise ValueError(f"ShellRisk pinned file size/hash mismatch: {path}")


def _fetch(path, pin, url):
    if path.exists():
        _check(path, pin)
        return path
    path.parent.mkdir(parents=True, exist_ok=True)
    scratch = path.parent / "tmp"
    scratch.mkdir(exist_ok=True)
    part = scratch / (path.name + ".part")
    try:
        with urllib.request.urlopen(url, timeout=120) as response, part.open("wb") as output:
            shutil.copyfileobj(response, output)
        _check(part, pin)
        part.replace(path)
    finally:
        part.unlink(missing_ok=True)
    return path


def _load_adapter(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _adapters(root, config):
    for pin in config["adapter_files"]:
        _fetch(root / "upstream" / pin["path"], pin,
               "https://raw.githubusercontent.com/kontext-security/shellrisk-bench/"
               f"{config['adapter_revision']}/{pin['path']}")
    directory = root / "upstream" / "adapters"
    common = _load_adapter(directory / "_common.py", "_shellrisk_pinned_common")
    previous = sys.modules.get("_common")
    sys.modules["_common"] = common
    try:
        modules = {source: _load_adapter(directory / f"{source}.py", f"_shellrisk_pinned_{source}")
                   for source in config["upstream_sources"]}
    finally:
        if previous is None:
            del sys.modules["_common"]
        else:
            sys.modules["_common"] = previous
    return common, modules


def _rows(root, source, config):
    for pin in config["files"]:
        # Older read-only investigations cached shards without their data/ prefix.
        legacy = root / source / Path(pin["path"]).name
        path = legacy if legacy.exists() else root / source / pin["path"]
        _fetch(path, pin, f"https://huggingface.co/datasets/{config['dataset']}/resolve/"
               f"{config['revision']}/{pin['path']}")
        index = 0
        for batch in pq.ParquetFile(path).iter_batches(batch_size=128):
            for row in batch.to_pylist():
                yield pin["path"], index, row
                index += 1


def _swesmith(rows, adapter, settings):
    seen = set()
    shapes = {}
    heredocs = 0
    index = 0
    for filename, row_number, row in rows:
        for message_index, message in enumerate(row.get("messages", [])):
            if message.get("role") != "assistant":
                continue
            # Count empty fences as positions even though extraction skips them.
            for block_index, block in enumerate(adapter.FENCE.findall(message.get("content", ""))):
                command = block.strip()
                if not command:
                    continue
                digest = hashlib.md5(command.encode("utf-8")).hexdigest()
                if digest in seen:
                    continue
                if "<<" in command:
                    if heredocs >= settings["heredoc_cap"]:
                        continue
                    heredocs += 1
                elif settings["cap_per_shape"]:
                    shape = adapter.command_shape(command)
                    if shapes.get(shape, 0) >= settings["cap_per_shape"]:
                        continue
                    shapes[shape] = shapes.get(shape, 0) + 1
                seen.add(digest)
                yield index, command, dict(raw_file=filename, raw_row=row_number,
                    task_id=row.get("instance_id", ""), agent=None, trial_id=None,
                    message_index=message_index, bash_block_index=block_index,
                    step_index=None, tool_index=None)
                index += 1


def _terminalbench(rows, adapter, settings):
    seen = set()
    index = 0
    for filename, row_number, row in rows:
        raw = row.get("steps")
        if not raw or raw == "null":
            continue
        try:
            steps = json.loads(raw)
        except (ValueError, TypeError):
            continue
        for step_index, step in enumerate(steps):
            for tool_index, tool in enumerate(step.get("tools") or []):
                if not isinstance(tool, dict) or tool.get("fn") != settings["shell_fn"]:
                    continue
                raw_command = tool.get("cmd")
                if not isinstance(raw_command, str) or not adapter.usable_command(raw_command):
                    continue
                command = raw_command.strip()
                digest = hashlib.md5(command.encode("utf-8")).hexdigest()
                if digest in seen:
                    continue
                seen.add(digest)
                yield index, command, dict(raw_file=filename, raw_row=row_number,
                    task_id=row.get("task_name"), agent=row.get("agent"), trial_id=row.get("trial_id"),
                    message_index=None, bash_block_index=None,
                    step_index=step_index, tool_index=tool_index)
                index += 1


def build_session_map(published_root, upstream_root, output_dir):
    """Replay pinned files and write a complete, deterministic session mapping.

    Missing upstream files are downloaded at pinned revisions. Existing files
    must match their pinned size and SHA-256. Published files must already exist.
    Returns the manifest; a mismatch aborts before replacing the mapping.
    """
    published_root, upstream_root, output_dir = map(Path, (published_root, upstream_root, output_dir))
    config = json.loads(CONFIG_PATH.read_text())
    for pin in config["published_files"]:
        _check(published_root / pin["path"], pin)
    published = {}
    for row in published_rows(published_root):
        if row["source"] not in config["upstream_sources"]:
            continue
        key = row["source"], row["upstream_id"]
        if key in published:
            raise ValueError(f"Duplicate ShellRisk published key: {key}")
        published[key] = row
    common, adapters = _adapters(upstream_root, config)
    selected = {}
    coverage = {}
    for source, extract in (("swesmith", _swesmith), ("terminalbench", _terminalbench)):
        rows = _rows(upstream_root, source, config["upstream_sources"][source])
        coverage[source] = 0
        for index, raw_command, position in extract(rows, adapters[source], config["extraction_settings"][source]):
            upstream_id = f"{source}-{index:06d}"
            key = source, upstream_id
            if key not in published:
                continue
            row = published[key]
            layer, actions = common.route_by_newline(raw_command)
            command = common.normalize_command(actions[0]["content"]).strip()
            command_id = "sha256:" + hashlib.sha256(command.encode("utf-8")).hexdigest()
            if layer != "command" or command != row["command"] or command_id != row["id"]:
                raise ValueError(f"ShellRisk replay mismatch for {source}/{upstream_id}")
            selected[key] = dict(source=source, upstream_id=upstream_id,
                command_id=command_id, command=command, **position,
                session_id=session_identity(source, position["raw_file"], position["raw_row"]))
            coverage[source] += 1
        print(f"{source}: matched {coverage[source]} published commands", flush=True)
    missing = published.keys() - selected.keys()
    if missing:
        raise ValueError(f"ShellRisk replay missing {len(missing)} commands: {sorted(missing)[:5]}")
    output_dir.mkdir(parents=True, exist_ok=True)
    scratch = output_dir / "tmp"
    scratch.mkdir(exist_ok=True)
    mapping = scratch / "sessions.jsonl"
    with mapping.open("w", encoding="utf-8") as output:
        for key in sorted(selected):
            output.write(json.dumps(selected[key], ensure_ascii=False, sort_keys=True) + "\n")
    manifest = dict(format_version=1, published_revision=config["published_revision"],
        published_files=config["published_files"], upstream_sources=config["upstream_sources"],
        adapter_revision=config["adapter_revision"], adapter_files=config["adapter_files"],
        extraction_settings=config["extraction_settings"], mapping_sha256=file_digest(mapping),
        coverage=coverage)
    manifest_path = scratch / "sessions.manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    mapping.replace(output_dir / mapping.name)
    manifest_path.replace(output_dir / manifest_path.name)
    return manifest
