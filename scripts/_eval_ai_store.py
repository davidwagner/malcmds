"""DuckDB storage, unique stratified sampling, and evaluation summaries."""

import json
from pathlib import Path

import duckdb

LABELS = ('malicious', 'benign', 'unknown')


def initialize(output: Path, source: Path, config: dict, resume: bool):
    """Open one evaluation per output file; resume only its exact configuration."""
    if output.resolve() == source.resolve():
        raise ValueError('Output must differ from the source database')
    if output.exists() and not resume:
        raise ValueError('Output already exists; use --resume or a new output path')
    if resume and not output.exists():
        raise ValueError('--resume requires an existing evaluation database')
    db = duckdb.connect(str(output))
    try:
        encoded = json.dumps(config, sort_keys=True)
        if resume:
            saved = db.execute('SELECT config::VARCHAR FROM evaluation_run').fetchone()
            if not saved or json.loads(saved[0]) != config:
                raise ValueError('Resume configuration differs from the saved run')
            return db
        db.execute('BEGIN')
        db.execute('''CREATE TABLE evaluation_run (
            config JSON, started_at TIMESTAMPTZ DEFAULT current_timestamp,
            finished_at TIMESTAMPTZ, status VARCHAR DEFAULT 'sampled',
            classification_seconds DOUBLE DEFAULT 0, total_seconds DOUBLE DEFAULT 0,
            error VARCHAR);
            CREATE SEQUENCE request_ids;
            CREATE TABLE requests (
                request_id BIGINT DEFAULT nextval('request_ids'), sample_id BIGINT,
                classifier VARCHAR, stage VARCHAR, attempt INTEGER,
                started_at TIMESTAMPTZ, seconds DOUBLE, http_status INTEGER,
                response JSON, rate_limit_headers JSON, error VARCHAR,
                cost_usd DOUBLE, cost_kind VARCHAR);
            CREATE TABLE results (
                sample_id BIGINT, classifier VARCHAR, model VARCHAR,
                prediction VARCHAR, raw_prediction VARCHAR,
                p_malicious DOUBLE, p_benign DOUBLE, p_unknown DOUBLE,
                score_kind VARCHAR, status VARCHAR, error VARCHAR,
                PRIMARY KEY (sample_id, classifier));
            CREATE TABLE classifier_timing (
                classifier VARCHAR, seconds DOUBLE, started_at TIMESTAMPTZ,
                finished_at TIMESTAMPTZ DEFAULT current_timestamp);
        ''')
        db.execute('INSERT INTO evaluation_run(config) VALUES (?)', [encoded])
        # Sample one observation type so a shell line and its derived processes
        # never compete in the same sample. Preserve array/NULL identities.
        table = config['table']
        if table == 'SHELL_INPUTS':
            observation_sql = '''SELECT dataset, dataset_label, record_id, shell_input,
                NULL::VARCHAR AS pgm_base, NULL::VARCHAR[] AS args FROM source.SHELL_INPUTS'''
        else:
            observation_sql = '''SELECT dataset, dataset_label, record_id, NULL::VARCHAR AS shell_input,
                pgm_base, args FROM source.PROCESS_LAUNCHES'''
        source_sql = str(source).replace("'", "''")
        db.execute(f"ATTACH '{source_sql}' AS source (READ_ONLY)")
        db.execute(f'''CREATE TABLE samples AS
            WITH observations AS ({observation_sql}), unique_commands AS (
                SELECT dataset, dataset_label::VARCHAR AS dataset_label, shell_input, pgm_base, args,
                       min(record_id::VARCHAR) AS record_id
                FROM observations GROUP BY ALL
            ), ranked AS (
                SELECT *, row_number() OVER (
                    PARTITION BY dataset, dataset_label
                    ORDER BY md5(? || to_json(struct_pack(
                        shell_input := shell_input, pgm_base := pgm_base, args := args))),
                        shell_input, pgm_base, args
                ) AS sample_rank FROM unique_commands
            )
            SELECT row_number() OVER (ORDER BY dataset, dataset_label, sample_rank) AS sample_id,
                   * EXCLUDE(sample_rank)
            FROM ranked WHERE sample_rank <= ?
        ''', [str(config['seed']), config['per_group']])
        db.execute('COMMIT')
        db.execute('DETACH source')
        return db
    except BaseException:
        db.close()
        # Rollback leaves an empty file. Keep an existing resume DB untouched.
        if not resume:
            output.unlink(missing_ok=True)
        raise


def command_text(sample: tuple) -> str:
    """Keep shell input verbatim, or encode program and argv without losing quoting."""
    _, shell_input, pgm_base, args = sample
    if shell_input is not None:
        return shell_input
    return json.dumps({'pgm_base': pgm_base, 'args': args}, ensure_ascii=False)


def analyze(db):
    """Materialize joint fractions and disagreement; unknowns stay in denominators.

    Failed classifications have NULL predictions and are excluded, with coverage
    exposed in classifier_costs. Malicious-group is kept as its own source label.
    Overall fractions weight each sampled command equally, not each dataset.
    """
    db.execute('BEGIN')
    try:
        db.execute('''CREATE OR REPLACE TEMP TABLE comparisons AS
            SELECT r.classifier, s.dataset, 'dataset_label' AS reference,
                   s.dataset_label AS reference_label, r.prediction
            FROM results r JOIN samples s USING(sample_id)
            WHERE r.prediction IS NOT NULL
            UNION ALL
            SELECT r.classifier, s.dataset, 'sol' AS reference,
                   sol.prediction AS reference_label, r.prediction
            FROM results r JOIN samples s USING(sample_id)
            JOIN results sol ON sol.sample_id = r.sample_id AND sol.classifier = 'sol'
            WHERE r.prediction IS NOT NULL AND sol.prediction IS NOT NULL;
            CREATE OR REPLACE TABLE disagreements AS
            SELECT classifier, reference,
                   CASE WHEN grouping(dataset) = 1 THEN 'overall' ELSE 'dataset' END AS scope,
                   dataset, count(*) AS sample_count,
                   count(*) FILTER (WHERE
                       (reference_label = 'benign' AND prediction = 'malicious') OR
                       (reference_label = 'malicious' AND prediction = 'benign')) AS disagreement_count,
                   disagreement_count::DOUBLE / sample_count AS disagreement_rate
            FROM comparisons GROUP BY GROUPING SETS
                ((classifier, reference), (classifier, reference, dataset));
            CREATE OR REPLACE TABLE confusion_matrices AS
            WITH counts AS (
                SELECT classifier, reference,
                       CASE WHEN grouping(dataset) = 1 THEN 'overall' ELSE 'dataset' END AS scope,
                       dataset, reference_label, prediction, count(*) AS sample_count
                FROM comparisons GROUP BY GROUPING SETS
                    ((classifier, reference, reference_label, prediction),
                     (classifier, reference, dataset, reference_label, prediction))
            ), reference_labels AS (
                SELECT 'dataset_label' AS reference, dataset_label AS reference_label FROM samples GROUP BY dataset_label
                UNION SELECT 'sol', unnest(['malicious', 'benign', 'unknown'])
            ), grid AS (
                SELECT d.classifier, d.reference, d.scope, d.dataset, l.reference_label,
                       unnest(['malicious', 'benign', 'unknown']) AS prediction,
                       d.sample_count AS total_samples
                FROM disagreements d JOIN reference_labels l USING(reference)
            )
            SELECT g.*, coalesce(c.sample_count, 0) AS sample_count,
                   coalesce(c.sample_count, 0)::DOUBLE / g.total_samples AS fraction
            FROM grid g LEFT JOIN counts c ON
                g.classifier = c.classifier AND g.reference = c.reference AND g.scope = c.scope
                AND g.dataset IS NOT DISTINCT FROM c.dataset
                AND g.reference_label IS NOT DISTINCT FROM c.reference_label
                AND g.prediction = c.prediction;
            CREATE OR REPLACE TABLE classifier_costs AS
            WITH classifiers AS (
                SELECT unnest(json_extract_string(config, '$.classifiers[*]')) AS classifier
                FROM evaluation_run
            ), costs AS (
                SELECT classifier, count(*) AS request_count, sum(cost_usd) AS known_cost_usd,
                       count(*) FILTER (WHERE cost_usd IS NULL) AS unpriced_requests,
                       bool_or(cost_kind = 'estimated') AS includes_estimates
                FROM requests GROUP BY classifier
            ), evaluated AS (
                SELECT classifier, count(*) FILTER (WHERE prediction IS NOT NULL) AS evaluated_samples,
                       count(*) FILTER (WHERE status = 'ok' AND p_malicious IS NOT NULL
                           AND p_benign IS NOT NULL AND p_unknown IS NOT NULL) AS scored_samples,
                       count(*) FILTER (WHERE prediction IS NULL) AS failed_samples
                FROM results GROUP BY classifier
            ), timing AS (
                SELECT classifier, sum(seconds) AS classification_seconds
                FROM classifier_timing GROUP BY classifier
            )
            SELECT n.classifier, (SELECT count(*) FROM samples) AS total_samples,
                   coalesce(e.evaluated_samples, 0) AS evaluated_samples,
                   coalesce(e.scored_samples, 0) AS scored_samples,
                   coalesce(e.failed_samples, 0) AS failed_samples,
                   (SELECT count(*) FROM samples) - coalesce(e.evaluated_samples, 0) AS unevaluated_samples,
                   coalesce(c.request_count, 0) AS request_count,
                   coalesce(c.known_cost_usd, 0) AS known_cost_usd,
                   coalesce(c.unpriced_requests, 0) AS unpriced_requests,
                   CASE WHEN coalesce(c.unpriced_requests, 0) = 0
                       THEN coalesce(c.known_cost_usd, 0) END AS total_cost_usd,
                   total_cost_usd / nullif(evaluated_samples, 0) AS estimated_cost_per_sample_usd,
                   coalesce(c.includes_estimates, false) AS includes_estimates,
                   coalesce(t.classification_seconds, 0) AS classification_seconds
            FROM classifiers n LEFT JOIN costs c USING(classifier)
            LEFT JOIN evaluated e USING(classifier) LEFT JOIN timing t USING(classifier);
        ''')
        db.execute('COMMIT')
    except BaseException:
        db.execute('ROLLBACK')
        raise
