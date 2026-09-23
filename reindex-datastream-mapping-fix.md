# Reindexing a Data Stream Backing Index to Fix a Mapping

Use this when a field's mapping needs to change on an **existing** backing index (mapping type changes aren't allowed in place — only new fields/sub-fields can be added via `_mapping`).

Replace `<DATA_STREAM>` and `<INDEX>` below with your actual values, e.g.:
`<DATA_STREAM>` = `logs-medianova.traffic-default`
`<INDEX>` = `.ds-logs-medianova.traffic-default-2026.09.23-000215`

## 0. Check doc count (decide sync vs async)
```json
GET <INDEX>/_count
```
- Under ~1M docs → reindex synchronously, no task polling needed.
- Millions of docs → use async + `conflicts: "proceed"` (step 2b).

## 1. Confirm it's not the current write index
```json
GET _data_stream/<DATA_STREAM>
```
Last entry in `"indices"` = write index. If your target index is the write index, roll over first:
```json
POST <DATA_STREAM>/_rollover
```

## 2. Create the destination index
```json
PUT <INDEX>-fixed
{
  "settings": { ... copy from current index template ... },
  "mappings": { ... corrected mapping ... }
}
```

## 2a. Reindex — small index (sync)
```json
POST _reindex
{
  "source": { "index": "<INDEX>" },
  "dest": { "index": "<INDEX>-fixed", "op_type": "create" }
}
```

## 2b. Reindex — large index (async, idempotent)
```json
POST _reindex?wait_for_completion=false&slices=auto
{
  "conflicts": "proceed",
  "source": { "index": "<INDEX>" },
  "dest": { "index": "<INDEX>-fixed", "op_type": "create" }
}
```
Poll until `"completed": true`:
```json
GET _tasks/<node>:<task_id>
```
Lost the task ID? Find it again:
```json
GET _tasks?actions=*reindex&detailed=true
```

## 3. Verify doc count matches source
```json
GET <INDEX>-fixed/_count
```

## 4. Swap into the data stream (atomic)
```json
POST _data_stream/_modify
{
  "actions": [
    { "remove_backing_index": { "data_stream": "<DATA_STREAM>", "index": "<INDEX>" } },
    { "add_backing_index": { "data_stream": "<DATA_STREAM>", "index": "<INDEX>-fixed" } }
  ]
}
```

## 5. Delete the old index (reclaims disk)
```json
DELETE <INDEX>
```

## Notes
- `remove_backing_index` only detaches/un-hides — it does **not** delete. Step 5 is required to free space.
- A write index can never be removed via `remove_backing_index` — always check step 1 first.
- `version_conflict_engine_exception` on reindex usually means a prior attempt already partially/fully populated `-fixed`. Check the count (step 3) before re-running — if it already matches the source, skip straight to step 4.
