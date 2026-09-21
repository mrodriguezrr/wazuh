# Elasticsearch Cluster Status — Command Reference

Companion to `elasticsearch_shard_rebalancing_commands.md`. Use this for general health checks, not just during an active rebalancing operation.

---

## 1. Overall cluster health — start here

```json
GET _cluster/health
```
Top-level status (`green`/`yellow`/`red`), unassigned shard count, node counts. Fastest single check for "is anything wrong right now."

```json
GET _cluster/health?level=indices
```
Same, broken down per-index — use this to find exactly which index is causing a `yellow`/`red` status.

---

## 2. Node-level resource status

```json
GET _cat/nodes?v&h=name,node.role,master,ram.percent,heap.percent,cpu,load_1m,load_5m,load_15m,disk.used_percent
```
Same view as `_cat/nodes` from the terminal, with disk percent included.

```json
GET _nodes/stats/breaker
```
Circuit breaker status per node — this caught real memory pressure earlier in this project. Check whenever things feel slow, not just during an incident.

---

## 3. Disk and shard allocation

```json
GET _cat/allocation?v&s=disk.percent:desc
```
Per-node disk usage as Elasticsearch sees it.

```json
GET _cat/shards?v&h=index,shard,prirep,state,node&s=state
```
Every shard's current state — sort by `state` to spot anything `UNASSIGNED` or `INITIALIZING`.

```json
GET *?filter_path=*.settings.index.blocks.read_only_allow_delete
```
Lists any index currently forced **read-only** because a node crossed the 95% flood-stage disk watermark. If this returns results, that index is blocking writes until disk space is freed and the block is manually cleared.

**Clearing a read-only block once disk space is freed:**
```json
PUT <index-name>/_settings
{
  "index.blocks.read_only_allow_delete": null
}
```

---

## 4. Pending work / background tasks

```json
GET _cluster/pending_tasks
```
Anything queued waiting on the master node — a growing queue signals master-node overload.

```json
GET _cat/recovery?active_only=true&v
```
Any shard relocation or recovery currently in progress.

---

## 5. Allocation settings — confirm rebalancing isn't stuck paused

```json
GET _cluster/settings?filter_path=**.allocation.enable
```
Should show `all` under normal conditions. If `transient` still shows `primaries` (or `none`) from a past manual pause, shards needing reassignment may sit `UNASSIGNED` indefinitely until this is reset:
```json
PUT _cluster/settings
{
  "transient": {
    "cluster.routing.allocation.enable": "all"
  }
}
```

---

## 6. Snapshots — confirm backups exist and are running

```json
GET _snapshot
```
Lists configured snapshot repositories. Empty response = no backup destination configured at all.

```json
GET _slm/policy
```
Snapshot Lifecycle Management policies — confirms snapshots are actually scheduled, not just possible.

```json
GET _snapshot/_all/_all?filter_path=**.snapshot,**.state,**.end_time
```
Actual run history, once a repository exists — confirms snapshots are succeeding, not just configured.

---

## 7. Index-level health check

```json
GET _cat/indices?v&health=yellow,red&s=index
```
Filters straight to unhealthy indices instead of scrolling through the full list.

---

## 8. Kibana / OS-level checks (run directly on the server, not Dev Tools)

```bash
curl -k https://localhost:9200
```
Confirms Elasticsearch itself is responding, independent of Kibana.

```bash
sudo systemctl status kibana
sudo journalctl -u kibana --since "10 minutes ago" --no-pager | tail -50
```
Kibana service status and recent errors.

```bash
sudo systemctl status elasticsearch
sudo journalctl -u elasticsearch --since "10 minutes ago" --no-pager | tail -50
```
Same, for Elasticsearch itself.
