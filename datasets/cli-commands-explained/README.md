# cli-commands-explained

Source: https://huggingface.co/datasets/b-mc2/cli-commands-explained

Pinned revision: `f7bf751e0d5c43ce26dd51a56d5eed5c51503196`. Run `./fetch`, then `./ingest --db ../../cmds.duckdb`.
The shared downloader verifies byte counts and SHA-256 hashes and saves the source
card, including publisher license information, as `SOURCE_README.md`.

Read `code` from cli_commands_explained.json. Label inputs and all derived invocations unknown.

Angle-bracket placeholders are filled with synthetic values from `templates.json`
before command parsing. For example, `ln -s <source-location> <symlink-location>`
becomes a command with concrete paths. The pools cover every placeholder spelling
identified by inspecting all 16,089 inputs in `cmds.duckdb`: 1,207 distinct
angle-bracket candidates across 1,834 inputs. The checked-in regression fixture
contains those inputs. The table also records candidates preserved as literal
syntax, including HTML/XML tags, regular expressions, redirections, and keyboard
notation. Exact row overrides distinguish ambiguous names such as `<module>` in
Perl and `modprobe`, and `<image>` in Docker, `dd`, and XML.

The ingest `--seed` option (default `0`), original row ID, and placeholder name
determine each selection. Repeated names within an input receive the same value;
sampling and rerunning ingestion keep the same selections. Each source row still
produces one input. Argument values are escaped for their surrounding shell quotes;
explicit fragment pools supply options or globs. Source files are unchanged.
Square-bracket optional-argument notation and existing shell variables are retained.

Pipelines, redirections, quoting and newlines are otherwise preserved as Linux
shell input. The existing Bash parser extracts program
invocations without executing source text. Source row numbers and field names
identify occurrences before filtering or sampling. Descriptions and other source
fields are discarded. Each input gets its own fallback session; derived
invocations share that session. All group IDs are NULL.

The pinned release has eight empty `code` values; these supply no shell input
and are skipped. Stable row IDs include their original positions.

Two source rows contain fenced TOML configuration. Ingestion omits the configuration and retains the shell command following the fence when present.
