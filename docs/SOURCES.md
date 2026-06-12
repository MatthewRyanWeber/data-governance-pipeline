# Source Formats and Streaming Inputs

Reference for everything the EXTRACT stage reads.  Ported from the
original terminal manual when readme.txt was retired (2026-06-12).

```
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
```
