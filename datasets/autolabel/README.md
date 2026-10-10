# AutoLabel

Source: the three fixed Zenodo releases [15528780](https://zenodo.org/records/15528780), [15532579](https://zenodo.org/records/15532579), and [15568798](https://zenodo.org/records/15568798). `release.json` pins all 29 scenario archives and publisher MD5 checksums (136,119,439,360 bytes).

Run `./fetch`, then `./ingest --db /path/to/commands.duckdb`. Fetch runs three downloads concurrently and resumes partial downloads. Ingest streams every nested run and all `sysdig/*.log` files without unpacking the complete dataset. Only execve/execveat attempts produce commands. The exporter already combines syscall entry and exit observations; no `evt.dir` field is required. Repeated observations are combined by archive, run, container and event number. Distinct attempts remain separate.

Successful exec uses the new process image and full process command line. Failed exec prefers the attempted filename and available arguments. When the exporter omits them, the remaining caller process fields are retained as a best-effort observation; they cannot establish the missing attempted target. Clone/fork/exit records recover related process lifetimes within a container and run. Missing ancestry starts a separate process lifetime; no login connection is invented. These observations have `shell_input=NULL` and `other_tokens=[]`. Three publisher instrumentation marker strings are removed if still present; other command text is retained.

The exporter writes each graph node's final label to its Sysdig records after propagating the supplied attack annotations, so these labels already cover related launches. The publisher's `malicious=true` and `false` map to malicious and benign. In particular, the malicious `/usr/bin/id` invocation with no arguments stays malicious. Ordinary desktop/browser launches and normal browser helper invocations receive benign labels when their invocation supports that reading.

## Shell command argument reconstruction

Sysdig stores `proc.cmdline` as a flat string without the original argument boundaries. For successful executions of `sh`, `bash`, or `dash`, an unquoted shell name followed immediately by the standalone option `-c` and a nonempty payload is reconstructed as one command argument. For example, `sh -c uname -a` with executable `/usr/bin/bash` becomes `args=["-c", "uname -a"]`. Quotes, escapes, operators, and spacing within the payload are retained literally, including the quoted inner command in `sh -c /bin/bash -c 'sleep 5' || exit 1`. The displayed shell name may differ from the executable's basename. [Issue #90](https://github.com/davidwagner/malcmds/issues/90) supplies the supporting release observations.

This is a heuristic, not byte-for-byte recovery of the original argv. For example, `sh -c echo hello` could originally have had either `echo hello` as its command argument or `echo` as its command argument and `hello` as shell `$0`. We choose the former. Leading whitespace belonging to the command argument cannot be distinguished from argument separators. NUL-separated argv retains its explicit boundaries. Other interpreters, combined options such as `-lc`, options before `-c`, quoted shell names, absent payloads, and failed executions keep their previous parsing, which remains approximate for flat strings. The reconstruction preserves execution identities and labels and does not create extra command rows or populate `shell_input`.

Existing databases marked complete are skipped on rerun. To rebuild corrected AutoLabel data after updating, use a database path that does not exist:

```sh
cd datasets/autolabel
./ingest --db /absolute/path/to/new-autolabel.duckdb
```

## What Suspicious means

AutoLabel propagates attack attribution through its process/network graph. Its analyzer marks certain long-lived network connections `Suspicious` when propagation reaches a connection shared by several participants that is absent from the explicitly supplied attack-connection list. This prevents confident propagation through a connection that may also carry ordinary traffic. It is weaker evidence than a direct malicious label, and is not a benign label.

For any exported exec observation whose `malicious` field is the string `Suspicious`, we use `malicious-group` and the scenario/run identifier as `group_id`. This says the execution belongs to attack-associated activity, while the released evidence does not identify that individual invocation as an attack. An ordinary browser-helper invocation can still be benign. Missing or unrecognized labels remain unknown; they are not silently converted to benign. Only malicious-group rows have a group identifier.
