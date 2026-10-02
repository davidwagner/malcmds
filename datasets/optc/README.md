# DARPA Operationally Transparent Cyber (OpTC)

Windows 10 endpoint telemetry from a controlled enterprise evaluation in September 2019. Five Directions endpoint sensors sent host events through Kafka; a translation service produced extended Cyber Analytics Repository (eCAR) records. Benign activity continued while a red team attacked the environment. The released collection covers 500 hosts and is approximately a terabyte compressed across all streams. Commands are **process-creation command lines**, not an interactive shell-history transcript. Windows-hosted Unix compatibility tools can also appear.

Run `./fetch` with Python 3.10+, curl, and Python's `venv` support. It automatically installs pinned `gdown==6.4.1` into `.fetch-venv/`, then recursively downloads the public Google Drive **ecar** folder to `ecar/`. This gdown version uses embedded folder listings without the historical 50-item limit; discovery errors fail the script. Completed output files are skipped, partial transfers are resumed, and files stay compressed. Only partial files created by gdown are resumed; a manually supplied truncated file at its final filename must be moved aside because gdown treats existing final files as completed. Google Drive quotas or permission changes can still cause a nonzero failure; rerun after service recovery. `FETCH_LIST=1 ./fetch` prints the endpoint-folder URL and document URLs without installing dependencies or transferring data.

Files:

- `ecar/benign/`: benign collection, subdivided by date and host ranges.
- `ecar/evaluation/`: concurrent benign and red-team activity, subdivided similarly. An example is `23Sep19-red/AIA-1-25/AIA-1-25.ecar-last.json.gz`.
- `ecar/short/`: events with missing data; retain the partition name when preparing examples.
- `source/OpTCRedTeamGroundTruth.pdf`: red-team attack narrative, timing, machines and actions.
- `source/ecar.md`, `source/errata.md`, `source/README.md`: schema and collection caveats, pinned to GitHub commit `5b108604f11f767aa11ea79ff827595f3fad15fd`.

The network-only `bro/` and flow-correlation `ecar-bro/` trees are excluded. Process, file, flow and other endpoint events are mixed within the compressed eCAR files; the service does not offer a separate command-only stream.

Relevant JSON schema, as documented by the publisher:

| Field | Use |
| --- | --- |
| `object`, `action` | Select `PROCESS` and `CREATE`. |
| `properties.command_line` | Full command-line string. |
| `properties.image_path`, `properties.parent_image_path` | Executable paths; check the publisher's errata before using them for joins. |
| `id` | Event UUID. |
| `objectID`, `actorID` | Object and actor UUIDs; process relationships are preferable to PID-only joins. |
| `hostname`, `pid`, `ppid`, `tid` | Host, process, parent process and thread identifiers. Missing values include `-1`, PID `0`, and all-zero UUIDs. |
| `principal`, `properties.user`, `properties.sid` | User identity. SID identifies an account, not a login session. |
| `timestamp` / `timestamp_ms` | The schema prose names epoch-millisecond `timestamp_ms`; its example uses `timestamp`. Preserve the source field and inspect actual type before normalizing release files. |

No explicit login-session identifier is promised by the published schema. A process tree groups related executions but is not equivalent to a login session.

Labels are **external red-team ground truth**, not a binary field on each command. The benign partition supplies a collection-level benign designation. The PDF documents attack actions and timing; constructing process/command labels requires matching those actions to host, time, identity and process relationships. Do not label every event in `evaluation/` malicious or every unmatched event proven benign. The release does not supply a comprehensive command-level labeling algorithm. Errata discuss duplicate process objects and inconsistent file-path representations; these affect deduplication and joins.

Sources: [official release](https://github.com/FiveDirections/OpTC-data), [eCAR schema](https://github.com/FiveDirections/OpTC-data/blob/master/ecar.md), [errata](https://github.com/FiveDirections/OpTC-data/blob/master/errata.md), [endpoint folder](https://drive.google.com/drive/folders/1NwaCWRyr_coyPbF2SvScbani5O9MXp7_). DARPA released the data into the public domain. Folder hierarchy, one leaf-file download resolution, and the schema example were checked on 2026-10-02; the terabyte-scale collection was not downloaded for verification.
