
================================================================================
  PIPELINE V3 / V4.8  |  README
================================================================================

  pipeline_v3.py is a production-grade Python ETL pipeline with built-in
  data governance, privacy compliance, and enterprise audit capabilities.

  You point it at a data source, tell it where to send the data, and it
  handles everything in between: cleaning, validating, masking sensitive
  fields, auditing every action, and loading into your destination.

  What makes it different from tools like Airbyte, dbt, AWS Glue, or
  Fivetran is that everything lives in one Python stack with no external
  services required. Most tools make you stitch together 3 or 4 separate
  products (an orchestrator, a validator, a catalog connector, a compliance
  layer). This does all of it -- including a tamper-evident SHA-256 audit
  ledger, GDPR Art. 17 erasure across all 15 platforms in one call, full
  PII discovery reporting with GDPR/CCPA compliance checklists, reversible
  loads with rollback, and a natural language pipeline builder -- all in a
  single file with no external orchestration services required.


================================================================================
  QUICK START
================================================================================

  Run the interactive wizard:

      python pipeline_v3.py

  The wizard asks 4 questions -- source type, destination, connection
  details, and pipeline options -- and runs the full governance stack.
  Works in any terminal, VS Code, and Windows Command Prompt.

  What gets created automatically:

      customers LOGS/               <-- named after your source file/table
        audit_ledger_<ts>.jsonl     tamper-evident SHA-256 audit chain
        pipeline_<ts>.log           full run log
        run_report_<ts>.html        HTML run report (open in any browser)
        pii_report_<ts>.json        PII discovery (machine-readable)
        pii_report_<ts>.html        PII compliance report (GDPR/CCPA)
        diff_report_<ts>.json       row-level data diff vs. prior run
        quality_history.jsonl       quality score trend (all runs)
        cost_history.jsonl          cost estimates (all runs)
        snapshots/                  rollback snapshots (if enabled)


================================================================================
  THE PIPELINE  |  5 Stages
================================================================================

  1. EXTRACT ─────────────────────────────────────────────────────────────────

     Reads data from 14 file formats, 3 real-time streaming sources,
     and 15 database platforms.

     File formats:

       TEXT / TABULAR
         .csv            CSV, comma-separated
         .tsv            TSV, tab-separated
         .fwf            Fixed-width (mainframe and legacy exports)
         .xlsx  .xls     Excel workbooks

       JSON VARIANTS
         .json           JSON array of objects
         .jsonl          Newline-delimited JSON (NDJSON, streaming logs)
         .ndjson         Alias for .jsonl

       MARKUP / CONFIG
         .xml            XML (auto-flattens nested elements)
         .yaml  .yml     YAML (config files and structured data)

       COLUMNAR BINARY
         .parquet        Apache Parquet (columnar, fast, widely used)
         .feather        Apache Feather (in-memory columnar, ultra-fast)
         .arrow          Apache Arrow (alias for .feather)
         .orc            ORC (Hive and Spark default columnar format)
         .avro           Avro (row-based with embedded schema, Kafka standard)

       STATISTICAL / RESEARCH
         .sas7bdat       SAS dataset
         .dta            Stata dataset

     Compression wrappers (auto-detected -- any format above can be wrapped):

         .gz             GNU gzip     (data.csv.gz, data.parquet.gz, ...)
         .bz2            bzip2        (data.csv.bz2, ...)
         .zip            ZIP archive  (first member extracted)
         .zst            Zstandard    (modern, high-ratio fast compression)
         .lz4            LZ4          (extremely fast decompression)
         .tgz            tar + gzip   (first file member extracted)

     Streaming sources (pipeline_streaming.py):

         Kafka           Any topic. Micro-batch delivery with configurable
                         batch size and flush interval. SASL/SSL auth.

         AWS Kinesis     Any Data Stream. Iterates all shards automatically.
                         Falls back to IAM role if no keys provided.

         Google Pub/Sub  Any subscription. Messages acknowledged only after
                         successful batch processing. ADC or key auth.

     Computes a SHA-256 fingerprint of every source file so you can prove
     the data was not tampered with before entering the pipeline.

     Native chunked streaming (memory-efficient for large files):
         CSV and TSV     pd.read_csv chunksize parameter
         JSONL           pd.read_json chunksize parameter
         Parquet         pyarrow row-group streaming


  2. CLASSIFY ────────────────────────────────────────────────────────────────

     Automatically scans every column and assigns a classification level:

       PUBLIC  ->  INTERNAL  ->  CONFIDENTIAL  ->  RESTRICTED

     Identifies PII fields such as names, emails, phone numbers,
     dates of birth, and SSNs.


  3. VALIDATE ────────────────────────────────────────────────────────────────

     Runs a Great Expectations suite against the data before anything loads.

     Catches:
       - Null violations
       - Type mismatches
       - Out-of-range values
       - Referential integrity problems

     Rows that fail go to a Dead Letter Queue rather than aborting the run.


  4. TRANSFORM ───────────────────────────────────────────────────────────────

     - Masks / pseudonymises PII fields
     - Handles nulls and deduplicates rows
     - Standardises column names and coerces types
     - Flattens nested JSON / XML structures
     - Applies configurable business rules
     - Enriches rows with derived columns
     - Automatic schema evolution: detects new columns and issues
       ALTER TABLE statements so the destination stays in sync
       without manual intervention


  5. LOAD ────────────────────────────────────────────────────────────────────

     Writes clean data to the destination.
     Supports:  append  |  replace  |  MERGE upsert


================================================================================
  DESTINATIONS  |  17 Supported Platforms
================================================================================

  TIER 1  --  Mainstream Cloud Warehouses
  -------------------------------------------------------------------------------
   #   Platform              Load Method
  -------------------------------------------------------------------------------
   1   SQLite                Standard SQL INSERT
   2   PostgreSQL            SQL INSERT via SQLAlchemy
   3   MySQL                 SQL INSERT via SQLAlchemy
   4   SQL Server            SQL INSERT via SQLAlchemy
   5   MongoDB               Bulk document insert
   6   Snowflake             PUT + COPY INTO staging
   7   Amazon Redshift       S3  ->  COPY INTO
   8   Google BigQuery       Storage Write API (no file staging)
   9   Azure Synapse         Azure Blob  ->  COPY INTO

  TIER 2  --  Specialized Analytical Engines
  -------------------------------------------------------------------------------
  10   Databricks / Delta    executemany + Delta MERGE
  11   ClickHouse            Native binary insert_df

  TIER 3  --  Enterprise / Industry Platforms
  -------------------------------------------------------------------------------
  12   Oracle ADW            executemany with batcherrors quarantine
  13   IBM Db2 Warehouse     ibm_db executemany
  14   Firebolt              VALUES literal INSERT / MERGE
  15   Yellowbrick           COPY FROM STDIN stream
  16   SAP HANA              hdbcli executemany + MERGE INTO
  17   SAP Datasphere        OData v4 REST API (PATCH batches)


================================================================================
  GOVERNANCE  |  Compliance and Audit Features
================================================================================

  TAMPER-EVIDENT AUDIT LEDGER
    Every action is written to a SHA-256 hash chain. Each entry contains
    the hash of the previous one -- any retroactive modification to the
    audit log is mathematically detectable. This is rare in ETL tooling
    and provides a court-admissible evidence trail.

  GDPR / CCPA COMPLIANCE
    Detects cross-border data transfers and logs a Chapter V event with
    the applicable safeguard (Standard Contractual Clauses, INTRA-EU
    exemption, etc.). Automatically infers the destination country from
    cloud metadata -- e.g. parses the AWS region from a Redshift hostname.

  GDPR ARTICLE 17  --  RIGHT TO ERASURE
    The ErasureHandler can delete or nullify all records for a given data
    subject across all 15 platforms in a single call, then records a
    cryptographically hashed erasure event in the audit trail.

  PII MASKING
    Sensitive fields are masked, pseudonymised, or tokenised before
    reaching the destination. Original values never appear in logs.

  DATA CATALOG INTEGRATION
    Publishes metadata to Collibra, Alation, Informatica Axon, or Atlan
    after each run, keeping your enterprise catalog current automatically.

  DELTA TIME-TRAVEL AUDIT  (Databricks)
    Records the Delta table version after every load so any historical
    state can be reproduced:
        SELECT * FROM table VERSION AS OF <n>


================================================================================
  FEATURE HISTORY  |  v4.0 through v4.8
================================================================================

  v4.0  --  DATA DIFF REPORTS  (DataDiffReporter)
  ---------------------------------------------------------------------
  After each run, compare the new data against the previous snapshot
  to see exactly what changed: which rows were added, which were deleted,
  and which had specific column values modified. Reports include a
  per-column change count so you can spot unexpected drift at a glance.

  v4.0  --  DATA QUALITY SCORE  (DataQualityScorer)
  ---------------------------------------------------------------------
  Computes a 0-100 composite quality score broken down across 5 dimensions:

      Completeness  (30%)  -- non-null cells as fraction of total
      Uniqueness    (20%)  -- fraction of rows that are not duplicates
      Validity      (25%)  -- fraction of expectations that passed
      Consistency   (15%)  -- fraction of numeric values within 3 sigma
      Timeliness    (10%)  -- fraction of dates within the past N days

  Grades follow the standard A/B/C/D/F scale. History saved to
  quality_history.jsonl in the log folder for trend tracking.

  v4.0  --  SYNTHETIC DATA GENERATION  (SyntheticDataGenerator)
  ---------------------------------------------------------------------
  Generate realistic fake datasets that mirror the schema and statistics
  of real data without exposing any actual PII. Column names are used
  to infer semantics: a column called "email" gets real-looking email
  addresses, "phone" gets phone numbers, and so on. Supports any Faker
  locale (en_US, de_DE, ja_JP, etc.). Save as CSV, JSON, or Parquet.

  v4.0  --  AUTOMATIC SCHEMA EVOLUTION  (SchemaEvolver)
  ---------------------------------------------------------------------
  When the source data gains new columns, SchemaEvolver detects the drift
  and issues ALTER TABLE ... ADD COLUMN statements automatically. No manual
  migrations required. Supports: SQLite, PostgreSQL, MySQL, SQL Server,
  Snowflake, Redshift.

  v4.0  --  HTML RUN REPORTS  (HTMLReportGenerator)
  ---------------------------------------------------------------------
  After each pipeline run, generates a self-contained HTML file that
  can be opened in any browser with no web server. Includes run summary,
  data quality score, data diff, top changed columns, and the last 20
  audit trail entries.

  v4.0  --  STREAMING SOURCES  (pipeline_streaming.py)
  ---------------------------------------------------------------------
  KafkaExtractor, KinesisExtractor, and PubSubExtractor feed real-time
  data into the standard pipeline stages. See pipeline_streaming.py.

  v4.0  --  NATIVE SCHEDULER  (pipeline_scheduler.py)
  ---------------------------------------------------------------------
  Built-in cron-style scheduler. No Airflow or external orchestrator needed.

      sched = PipelineScheduler()
      sched.add_job("daily_sales", my_pipeline, "daily at 06:00", cfg={...})
      sched.start()

  v4.0  --  REST API  (pipeline_api.py)
  ---------------------------------------------------------------------
  Flask HTTP API to trigger and monitor pipeline runs remotely.

      POST  /run                      Trigger a run (returns run_id)
      GET   /run/<run_id>             Poll status
      GET   /runs/<run_id>/log        Fetch the full audit log
      GET   /scheduler/status         List scheduled jobs
      GET   /health                   Liveness probe

  v4.4  --  COST ESTIMATOR  (CostEstimator)
  ---------------------------------------------------------------------
  Estimates the compute and storage cost of every run before it happens
  (or reconstructs cost from the audit ledger after the fact). Embedded
  pricing for Snowflake, BigQuery, Redshift, and generic per-row pricing.
  Logs to cost_history.jsonl in the project log folder.

  v4.5  --  REVERSIBLE LOADER  (ReversibleLoader)
  ---------------------------------------------------------------------
  Makes every load fully undoable. Before writing, it snapshots the
  current table state. If a load produces bad data, one call rolls back:

      rev = ReversibleLoader(gov, loader=my_loader, db_type="snowflake")
      run_id = rev.load(df, cfg, "orders")
      rev.rollback(table="orders", run_id=run_id, cfg=cfg)

  Three snapshot strategies: parquet, shadow table, or both.
  Snapshots are SHA-256 checksummed. Stored in the log folder snapshots/
  subfolder automatically.

  v4.6  --  NATURAL LANGUAGE PIPELINE BUILDER  (NLPipelineBuilder)
  ---------------------------------------------------------------------
  Describe what you want in plain English. Get a working config back:

      builder = NLPipelineBuilder(gov)
      result  = builder.build("load sales.csv into Snowflake, mask emails,
                               run daily at 7am, GDPR mode")

  Generates a validated config dict, a YAML file, or a complete runnable
  Python script. Uses the Claude API. generate_config_offline() works
  without an API key for CI/testing. Interactive REPL available.

  v4.7  --  PII DISCOVERY REPORTER  (PIIDiscoveryReporter)
  ---------------------------------------------------------------------
  Automated PII discovery and audit reporting. Scans every DataFrame,
  tracks row-level exposure, records what action was taken on each field,
  and generates:

      JSON report  -- Machine-readable. Row keys SHA-256 hashed.
                      Safe value samples redacted.
      HTML report  -- Human-readable. Color-coded risk badges.
                      9-check GDPR/CCPA compliance checklist.

  Compliance checks:
      GDPR-01  Special-category protection      (Art. 9)
      GDPR-02  Critical PII pseudonymisation    (Art. 25, 32)
      GDPR-03  Data minimisation                (Art. 5(1)(c))
      GDPR-04  Credential protection            (Art. 32)
      GDPR-05  Audit trail integrity            (Art. 30)
      GDPR-06  PII field documentation          (Art. 30(1)(d))
      GDPR-07  Processing action recorded       (Art. 30(1)(b))
      CCPA-01  Personal information inventory   (ss.1798.100)
      CCPA-02  Sensitive PI handling            (ss.1798.121)

  Supports 23 PII categories with GDPR article and CCPA section
  cross-references for each field found.

  v4.8  --  TABLE COPIER  (TableCopier)
  ---------------------------------------------------------------------
  Copy any database table to a new table -- on the same platform or a
  different one -- with the full governance stack applied automatically:

      copier = TableCopier(
          gov,
          src_db_type = "postgresql",
          dst_db_type = "snowflake",
          transforms  = [
              {"op": "mask",   "columns": ["email", "phone"]},
              {"op": "hash",   "columns": ["ssn"]},
              {"op": "drop",   "columns": ["password"]},
          ],
      )
      result = copier.copy(
          src_cfg   = {"host": "...", "db_name": "crm", ...},
          dst_cfg   = {"account": "...", "database": "DW", ...},
          src_table = "customers",
          dst_table = "customers_clean",
      )

  Every copy automatically runs: PII scan -> transforms -> quality score
  -> diff vs. existing -> reversible load with rollback snapshot ->
  HTML run report + PII compliance reports + audit ledger entry.

  dry_run=True reads, scans, and generates all reports without writing.
  For platforms not covered by the built-in engine (BigQuery, Redshift,
  etc.) supply a read_fn=(cfg, table) -> DataFrame callable.

  v4.8  --  UNIFIED LOG FOLDER
  ---------------------------------------------------------------------
  All logs, reports, and snapshots for a run are written to a single
  folder named after the source file or table:

      customers.csv   ->  customers LOGS/
      orders          ->  orders LOGS/
      events.json     ->  events LOGS/

  Inside that folder:

      audit_ledger_<ts>.jsonl     tamper-evident event chain
      pipeline_<ts>.log           full run log
      run_report_<ts>.html        HTML run report
      pii_report_<ts>.json        PII discovery (JSON)
      pii_report_<ts>.html        PII compliance (HTML)
      diff_report_<ts>.json       row-level data diff
      quality_history.jsonl       cumulative quality scores (all runs)
      cost_history.jsonl          cumulative cost estimates (all runs)
      snapshots/                  reversible load snapshots

  The folder name is derived automatically from GovernanceLogger:

      gov = GovernanceLogger(source_name="customers.csv")
      # creates  ./customers LOGS/  automatically

  Pass log_dir= to override with an explicit path.

  v4.8  --  WIZARD OVERHAUL  (4-step interactive CLI)
  ---------------------------------------------------------------------
  The interactive wizard (python pipeline_v3.py) was redesigned to ask
  source and destination upfront, then show only the prompts relevant
  to that specific combination:

      STEP 1  Where is your data FROM?   (file / database / stream)
      STEP 2  Where does it GO?          (15 destinations, or same-DB copy)
      STEP 3  Connection details         -- only what your combo needs
      STEP 4  Pipeline options           -- trimmed to what matters

  If you choose SQLite you never see S3 buckets or warehouse names.
  If source and destination are the same platform, credentials are
  offered for reuse. Choosing "same database" in step 2 skips the
  destination credentials entirely -- just asks for the new table name.

  Also fixed: the wizard now works correctly inside VS Code on Windows.
  The debugpy terminal does not handle newlines inside input() prompt
  strings. All prompts now use a safe _input() wrapper that separates
  newlines into print() calls before passing a clean prompt to input().

  v4.8  --  BUG FIXES
  ---------------------------------------------------------------------
  Three runtime bugs discovered by automated scanning and corrected:

  ReversibleLoader.purge_old_snapshots()
    Previously crashed if called with a days= argument. Added days=None
    as an optional override so you can call purge_old_snapshots(days=0)
    to force-clean without changing the object's retention_days default.

  SyntheticDataGenerator  (categorical columns)
    Crashed with a ValueError when generating data for categorical
    columns. Faker's random_element() requires an OrderedDict for
    weighted sampling but received a plain dict. Replaced with Python's
    stdlib random.choices() which handles weighted lists without any
    type restriction.

  SchemaEvolver.evolve()
    The engine was only settable in __init__, so targeting a different
    database required reconstructing the whole object. Added an optional
    engine= kwarg to evolve() that uses the override for that call and
    then restores the original, keeping the instance state clean.

  Previously fixed (session prior):
    GovernanceLogger.pipeline_complete()  -- alias for pipeline_end() added
    CostEstimator.estimate_from_ledger()  -- db_type now defaults to "generic"
    TableCopier.copy()                    -- accepts per-call transforms= kwarg
    DLQReplayer._load_group()             -- SQLLoader now receives db_type


  v4.9  --  SAP HANA LOADER  (HanaLoader)
  ---------------------------------------------------------------------
  Writes DataFrames directly to SAP HANA Cloud or on-premise HANA 2.0+
  via the official hdbcli Python driver.  This is the recommended
  integration path for SAP Analytics Cloud (SAC) — SAC can connect to
  HANA tables as a Live Data Connection with no intermediate publish step.

  Supports:
    - Chunked executemany INSERT (5,000 rows per batch by default)
    - MERGE INTO upsert via a staging table when natural_keys provided
    - Schema auto-create (CREATE SCHEMA IF NOT EXISTS)
    - Table auto-create (CREATE TABLE IF NOT EXISTS) with type mapping
    - TLS/SSL (default on for HANA Cloud, off for on-premise)
    - GDPR Art. 17 erasure via hdbcli DELETE / UPDATE NULL
    - Full governance ledger integration

  Wizard: choose destination 16 — SAP HANA
  Requires: pip install hdbcli

  v4.9  --  SAP DATASPHERE LOADER  (DatasphereLoader)
  ---------------------------------------------------------------------
  Uploads DataFrames to SAP Datasphere (formerly SAP Data Warehouse
  Cloud) via the OData v4 REST API.  Data loaded here is immediately
  available to SAP Analytics Cloud stories and dashboards as Analytical
  Datasets or Dimension views — no publish or replication step required.

  Authentication uses OAuth 2.0 client-credentials flow (recommended
  for service accounts).  A pre-fetched bearer token can be supplied
  for testing via cfg["token"].

  Supports:
    - Batch PATCH requests (configurable batch_size, default 1,000 rows)
    - Replace mode (truncates via Datasphere action, then re-uploads)
    - Append mode (upserts on the table's defined primary key)
    - GDPR Art. 17 erasure via OData DELETE on the record endpoint
    - Full governance ledger integration

  Wizard: choose destination 17 — SAP Datasphere
  Requires: requests (already a core dependency — no extra install)

  SAC integration path:
    1. Load data into HANA (HanaLoader) or Datasphere (DatasphereLoader)
    2. In Datasphere, model the table as an Analytical Dataset / view
    3. In SAC, add a Live Data Connection pointing at Datasphere or HANA
    4. SAC stories pick up the data with no further ETL required

================================================================================
  OPERATIONS  |  Built-in Reliability Features
================================================================================

   Checkpointing       ->  Resumes interrupted runs from the last good chunk
   Retry logic         ->  Exponential back-off on all loaders (3 attempts)
   Incremental loads   ->  Watermark-based; only processes new or changed rows
   Parallel processing ->  Multi-threaded chunks for large files
   SLA monitoring      ->  Alerts when a run exceeds its time budget
   Notifications       ->  Slack / email / webhook on success or failure
   Config wizard       ->  4-step interactive CLI, platform-aware prompts
   Dead Letter Queue   ->  Bad rows quarantined with full diagnostic context
   Schema validation   ->  Enforces data contracts before every load
   Native chunked streaming -> CSV, TSV, JSONL, Parquet stream without
                          loading the entire file into memory first


================================================================================
  PROJECT FILES
================================================================================

   pipeline_v3.py          Main pipeline -- extract, classify, validate,
                           transform, load, governance, compliance, 15
                           warehouse loaders, TableCopier, wizard, and
                           all supporting classes. ~14,200 lines.

   pipeline_streaming.py   Real-time streaming extractors for Kafka,
                           AWS Kinesis, and Google Pub/Sub.

   pipeline_scheduler.py   Built-in cron-style job scheduler with run
                           history and per-job hooks.

   pipeline_api.py         Flask REST API to trigger and monitor runs
                           over HTTP.

   catalog_connectors.py   Metadata publishing to Collibra, Alation,
                           Informatica Axon, and Atlan.

   metadata_extensions.py  Column lineage, schema drift detection, DSAR
                           index, anomaly detection, OpenLineage emission.

   pipeline_additions.py   CDC tracker, data product registry, cost
                           estimator, sensitivity scorer, tag taxonomy.

   requirements_v2.txt     All Python dependencies with version pins.
                           42 packages covering all features and platforms.

   readme.txt              This file.


================================================================================
  FORMATS  |  What Goes In and What Comes Out
================================================================================

  IN  --  Source files the pipeline can read
  -------------------------------------------------------------------------------

  Text / Tabular
    .csv              Comma-separated values
    .tsv              Tab-separated values
    .fwf              Fixed-width format (mainframe and legacy exports)
    .xlsx  .xls       Excel workbooks (any sheet)

  JSON variants
    .json             JSON array of objects or single object
    .jsonl  .ndjson   Newline-delimited JSON (one object per line)

  Markup / Config
    .xml              XML (nested elements are auto-flattened to columns)
    .yaml  .yml       YAML (list of objects or single object)

  Columnar binary
    .parquet          Apache Parquet
    .feather  .arrow  Apache Feather / Arrow IPC
    .orc              ORC (Hive / Spark)
    .avro             Avro (with embedded schema)

  Statistical / research
    .sas7bdat         SAS dataset
    .dta              Stata dataset

  Compression wrappers (any format above can be wrapped):
    .gz               GNU gzip        data.csv.gz, data.parquet.gz, ...
    .bz2              bzip2           data.csv.bz2, ...
    .zip              ZIP archive     first member extracted
    .zst              Zstandard       data.csv.zst
    .lz4              LZ4             data.csv.lz4
    .tgz              tar + gzip      first member extracted

  Real-time streams (pipeline_streaming.py):
    Kafka             Any topic, micro-batch, SASL/SSL auth
    AWS Kinesis       Any Data Stream, all shards, IAM or key auth
    Google Pub/Sub    Any subscription, ack on success, ADC or key auth

  Database sources (read via SQLAlchemy or native connector):
    SQLite, PostgreSQL, MySQL, SQL Server, MongoDB
    Snowflake, Redshift, BigQuery, Synapse
    Databricks, ClickHouse, Oracle, Db2, Firebolt, Yellowbrick


  OUT  --  What the pipeline produces
  -------------------------------------------------------------------------------

  Destination databases (all 17 platforms accept APPEND, REPLACE, MERGE upsert):
    SQLite            PostgreSQL       MySQL            SQL Server
    MongoDB           Snowflake        Redshift         BigQuery
    Synapse           Databricks       ClickHouse       Oracle
    Db2               Firebolt         Yellowbrick      SAP HANA
    SAP Datasphere

  Log folder  (auto-named "<source> LOGS/" in the working directory):
    audit_ledger_<ts>.jsonl       tamper-evident SHA-256 event chain
    pipeline_<ts>.log             full run log
    run_report_<ts>.html          HTML run report (quality, diff, audit)
    pii_report_<ts>.json          PII discovery (machine-readable)
    pii_report_<ts>.html          PII compliance report (GDPR/CCPA)
    diff_report_<ts>.json         row-level data diff vs. prior run
    quality_history.jsonl         cumulative quality score trend
    cost_history.jsonl            cumulative cost estimates
    lineage_<ts>.html             interactive D3.js data lineage graph
    dlq_<ts>.csv                  dead-letter queue (failed rows)
    snapshots/                    reversible load snapshots (.parquet)

  Synthetic data (SyntheticDataGenerator.save()):
    .csv              Comma-separated (default)
    .jsonl            Newline-delimited JSON
    .parquet          Apache Parquet

  Pipeline configs (NLPipelineBuilder):
    .yaml             Pipeline config for version control
    .py               Complete runnable Python script
    .json             Config as JSON


================================================================================
  SUMMARY
================================================================================

  An enterprise data pipeline that ingests data from 14 file formats and
  3 real-time streaming sources (with 6 compression wrappers), governs it
  to GDPR/CCPA standards, and loads it into any of 17 databases or data
  warehouses.

  Run it with:  python pipeline_v3.py

  Everything lands in one folder named after your source file. No
  configuration required. No external orchestration services required.

================================================================================
