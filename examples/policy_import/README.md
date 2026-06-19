# Import governance policy from a catalog

Demonstrates `PolicyImporter`: take a catalog's policy export and turn it into
the governance files `governance_preflight.py` enforces on every run — so an org
that already keeps policy in a catalog gets it enforced here without re-typing.

`catalog_export.json` is a normalized export for two synthetic datasets
(`customers`, `orders`). It is fully synthetic — column names only, no real data.

## Run it

Write the policy into the pipeline's real config dir (what the preflight reads):

```bash
python -c "from pipeline.catalog import PolicyImporter, JsonExportAdapter; \
print(PolicyImporter(config_dir='config').import_from( \
JsonExportAdapter('examples/policy_import/catalog_export.json')))"
```

Or try it against a throwaway dir first (writes nowhere permanent):

```bash
python -c "from pipeline.catalog import PolicyImporter, JsonExportAdapter; \
print(PolicyImporter(config_dir='/tmp/dgp_config').import_from( \
JsonExportAdapter('examples/policy_import/catalog_export.json')))"
```

Preview without writing anything (`dry_run=True`):

```bash
python -c "from pipeline.catalog import PolicyImporter, JsonExportAdapter; \
PolicyImporter(config_dir='config', dry_run=True).import_from( \
JsonExportAdapter('examples/policy_import/catalog_export.json'))"
```

## What it produces

Four files under the config dir, each keyed by `source_label`:

| File | From the export | The preflight then… |
|------|-----------------|---------------------|
| `schema_registry.json` | `columns` + `dtypes` | flags schema drift |
| `column_purpose.json` | `column_purposes` + `pii_columns` (as `PII`) | shows purposes / PII |
| `purpose_registry.json` | `allowed_columns` + `purpose` | drops out-of-purpose columns |
| `anomaly_baseline.json` | `expected_row_count` + `null_rates` | flags quality anomalies |

The import **merges, never clobbers**: re-running, or importing a different
source, updates only that source's entry and leaves the rest intact.

## Other catalogs

`JsonExportAdapter` works for any catalog that can export (or be scripted into)
the normalized shape above. `AtlanCatalogAdapter(base_url, api_key)` is a sketch
for pulling the same shape straight from an Atlan tenant.
