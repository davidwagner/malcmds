"""Exercise template filling through the real tabular ingest CLI and DuckDB."""
import json
import re
from pathlib import Path

import duckdb
from test_ingest_tabular import ingest

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / 'tests/fixtures/cli_commands_templates.json'
CONFIG = ROOT / 'datasets/cli-commands-explained/templates.json'


def source(tmp_path, examples):
    """Keep the publisher's row positions so contextual rules are exercised."""
    root = tmp_path / 'cli-commands-explained'
    root.mkdir()
    rows = [{'code': ''} for _ in range(max(int(key.split(':')[1]) for key in examples) + 1)]
    for key, text in examples.items():
        rows[int(key.split(':')[1])]['code'] = text
    (root / 'cli_commands_explained.json').write_text(json.dumps(rows))
    return root


def read_inputs(db):
    """Read the actual complete inputs by their original occurrence IDs."""
    with duckdb.connect(str(db), read_only=True) as con:
        return dict(con.execute('SELECT record_id, shell_input FROM SHELL_INPUTS').fetchall())


def test_templates_before_command_parsing(tmp_path):
    """Resolve templates before extracting arguments and retain literal syntax."""
    examples = {
        'cli_commands_explained.json:20000:code':
            'ip link show <interface>\ncat <file> | wc -l\nln -s <source-location> <symlink-location>',
        'cli_commands_explained.json:20001:code':
            'ssh <user>@<host> "cat <file>" > <outfile>\n'
            'printf \'%s\\n\' "<file>" \'<file>\' <file>',
        'cli_commands_explained.json:15308:code': 'perl -e <program_text>',
        'cli_commands_explained.json:15311:code': 'perl -M<module> -E <program_text>',
        'cli_commands_explained.json:14816:code': 'modprobe <module>',
        'cli_commands_explained.json:20002:code':
            'cat <(sort input.txt) > output.txt\n'
            'perl -e \'print <STDIN>\'\n'
            'sed \'s/<[^>]*>//g\' input.html\n'
            'docker inspect --format="{{.State.Pid}}" app\n'
            'cat < input.txt > output.txt',
    }
    root = source(tmp_path, examples)
    db = tmp_path / 'commands.duckdb'
    result = ingest(root, db)
    assert result.returncode == 0, result.stderr
    actual = read_inputs(db)
    assert len(actual) == len(examples)
    assert actual['cli_commands_explained.json:20002:code'] == examples['cli_commands_explained.json:20002:code']
    for key in examples.keys() - {'cli_commands_explained.json:20002:code'}:
        assert not re.search(r'<[^<>]+>', actual[key]), actual[key]
    with duckdb.connect(str(db)) as con:
        assert con.execute("SELECT count(*) FROM SHELL_INPUTS WHERE dataset_label != 'unknown' OR group_id IS NOT NULL").fetchone() == (0,)
        assert con.execute("SELECT count(*) FROM PROCESS_LAUNCHES WHERE dataset_label != 'unknown' OR group_id IS NOT NULL").fetchone() == (0,)
        parsed = con.execute("SELECT pgm,args FROM PROCESS_LAUNCHES WHERE record_id LIKE '%:20000:code:%' ORDER BY record_id").fetchall()
        assert [pgm for pgm, _ in parsed] == ['ip', 'cat', 'wc', 'ln']
        assert parsed[0][1][:2] == ['link', 'show']
        assert len(parsed[1][1]) == 1
        assert parsed[3][1][0] == '-s'
        assert len(parsed[3][1]) == 3
        repeated = con.execute("SELECT args FROM PROCESS_LAUNCHES WHERE record_id LIKE '%:20001:code:%' AND pgm='printf'").fetchone()[0]
        assert repeated[1] == repeated[2] == repeated[3]
        perl = con.execute("SELECT args FROM PROCESS_LAUNCHES WHERE record_id LIKE '%:15308:code:%'").fetchone()[0]
        assert len(perl) == 2 and perl[0] == '-e' and perl[1].startswith('print ')
        assert con.execute("SELECT count(*) FROM PROCESS_LAUNCHES p JOIN SHELL_INPUTS s ON p.record_id LIKE s.record_id || ':%' WHERE p.session_id != s.session_id").fetchone() == (0,)


def test_complete_template_inventory(tmp_path):
    """Ingest every inspected candidate and check repeatability and sampling."""
    examples = json.loads(FIXTURE.read_text())
    config = json.loads(CONFIG.read_text())
    root = source(tmp_path, examples)
    db = tmp_path / 'commands.duckdb'
    result = ingest(root, db)
    assert result.returncode == 0, result.stderr
    actual = read_inputs(db)
    assert actual.keys() == examples.keys()
    encountered = set()
    changed = 0
    for key, text in examples.items():
        rules = config['placeholders'] | config['overrides'].get(key, {})
        active = {token: pool for token, pool in rules.items() if pool is not None and token in text}
        if active:
            changed += 1
            assert actual[key] != text, key
            for token in active:
                # An email envelope stays in angle brackets as required by its format.
                assert token not in actual[key], (key, token, actual[key])
        else:
            assert actual[key] == text, key
        encountered.update(re.findall(r'<[^<>\n]+>', text))
    assert changed > 1000
    assert encountered <= config['placeholders'].keys() | set(config['preserved_candidates'])
    # Reingestion and sampling use the same choices for an occurrence; another seed varies them.
    with duckdb.connect(str(db)) as con:
        con.execute('UPDATE INGESTED SET ingested=false')
    again = ingest(root, db)
    assert again.returncode == 0, again.stderr
    assert read_inputs(db) == actual
    limited_db = tmp_path / 'limited.duckdb'
    limited = ingest(root, limited_db, '--max-records', '1000')
    assert limited.returncode == 0, limited.stderr
    assert read_inputs(limited_db) == {k:v for k,v in actual.items() if int(k.split(':')[1]) < 1000}
    other_db = tmp_path / 'other.duckdb'
    other = ingest(root, other_db, '--seed', '73')
    assert other.returncode == 0, other.stderr
    assert read_inputs(other_db) != actual


def test_context_specific_values(tmp_path):
    """Use values of the type required by ambiguous real publisher examples."""
    fixture = json.loads(FIXTURE.read_text())
    indices = [652, 12556, 12866, 14816, 15311, 10490, 14446, 5392,
               13776, 15449, 15326, 15377, 12045, 4314]
    examples = {f'cli_commands_explained.json:{i}:code':
                fixture[f'cli_commands_explained.json:{i}:code'] for i in indices}
    root = source(tmp_path, examples)
    db = tmp_path / 'commands.duckdb'
    result = ingest(root, db)
    assert result.returncode == 0, result.stderr
    actual = {int(k.split(':')[1]): v for k, v in read_inputs(db).items()}
    assert re.search(r'query=\$\{@:-\d{5}}', actual[12556])
    assert re.search(r'user@[a-z0-9.]+\.example\.com:', actual[652])
    assert re.search(r'grep -c [abx]$', actual[12866])
    assert actual[14816] in {'modprobe loop', 'modprobe vfat', 'modprobe nf_conntrack'}
    assert re.search(r'perl -M(?:JSON::PP|File::Spec|Data::Dumper)', actual[15311])
    assert re.search(r'dd if=\w+\.img ', actual[10490])
    assert re.search(r'(?:ubuntu:22\.04|debian:12|alpine:3\.19)$', actual[14446])
    for row in [5392, 13776, 4314]:
        assert actual[row] == fixture[f'cli_commands_explained.json:{row}:code']
    assert actual[15449].startswith('pyenv install 3.')
    assert actual[15326].startswith('perlbrew install perl-5.')
    assert actual[15377].startswith('plenv install 5.')
    assert re.search(r'SHOW COLUMNS FROM (users|orders|events)', actual[12045])


def test_other_datasets_retain_angle_brackets(tmp_path):
    """Limit synthetic substitution to CLI Commands Explained."""
    root = tmp_path / 'mecha'
    root.mkdir()
    text = 'cat <file> | grep "<pattern>"'
    (root / 'linuxcommands.json').write_text(json.dumps([{'output': text}]))
    db = tmp_path / 'commands.duckdb'
    result = ingest(root, db)
    assert result.returncode == 0, result.stderr
    assert list(read_inputs(db).values()) == [text]
