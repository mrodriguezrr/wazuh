# Elasticsearch Shard Rebalancing — Command Reference

Commands used to diagnose and fix disk imbalance on `elasiem-data-02` (89% → target: back under the 85% low watermark), consolidated for reuse next time a node runs hot.

---

## 1. Diagnose — check disk/shard balance before doing anything

**Per-node disk usage, as Elasticsearch sees it (fastest check, no SSH needed):**
```json
GET _cat/allocation?v&s=disk.percent:desc
```

**Confirm configured watermark thresholds** (defaults: low 85%, high 90%, flood_stage 95%):
```json
GET _cluster/settings?include_defaults=true&filter_path=**.disk.watermark*
```

**List every shard on a specific node, sorted by size** — use this to identify which large shards to move:
```json
GET _cat/shards?v&s=store:desc&h=index,shard,prirep,store,node
```

**Real OS-level disk check (cross-check against Elasticsearch's view):**
```bash
df -hT
```

---

## 2. Move specific shards off a hot node

Manually relocate one or more shards in a single batched call — spreads the load across multiple destination nodes rather than dumping it all on one:

```json
POST _cluster/reroute
{
  "commands": [
    { "move": { "index": "<index-name>", "shard": <shard-number>, "from_node": "<source-node>", "to_node": "<destination-node>" } },
    { "move": { "index": "<index-name>", "shard": <shard-number>, "from_node": "<source-node>", "to_node": "<destination-node>" } }
  ]
}
```

**Example actually used:**
```json
POST _cluster/reroute
{
  "commands": [
    { "move": { "index": ".ds-logs-nginx.access-pa-default-2026.08.26-000038", "shard": 0, "from_node": "elasiem-data-02.arborys.net", "to_node": "elasiem-data-04.arborys.net" } },
    { "move": { "index": ".ds-logs-fortigate.traffic-default-2026.08.08-000008", "shard": 1, "from_node": "elasiem-data-02.arborys.net", "to_node": "elasiem-data-01.arborys.net" } },
    { "move": { "index": ".ds-logs-fortigate.traffic-default-2026.08.05-000007", "shard": 2, "from_node": "elasiem-data-02.arborys.net", "to_node": "elasiem-data-06.arborys.net" } }
  ]
}
```

---

## 3. Stop the automatic rebalancer from undoing manual moves

**Important lesson from this session**: Elasticsearch balances by *shard count*, not by *disk bytes*. After a manual move, the automatic rebalancer can see an "imbalanced shard count" and start moving shards right back onto the node you just relieved. If that happens, pause it:

**Pause — allow only primary shard assignment (emergency-safe), block routine rebalancing:**
```json
PUT _cluster/settings
{
  "transient": {
    "cluster.routing.allocation.enable": "primaries"
  }
}
```

**Resume normal rebalancing once the node has stabilized:**
```json
PUT _cluster/settings
{
  "transient": {
    "cluster.routing.allocation.enable": "all"
  }
}
```

**Confirm which mode is currently active:**
```json
GET _cluster/settings?filter_path=**.allocation.enable
```
Note: this was set as `transient`, not `persistent` — it will **not** survive a full cluster restart (reverts to `all` automatically). That's intentional for a temporary fix; if a longer-term pause is ever needed, use `persistent` instead of `transient`.

---

## 4. Monitor progress

**Check all currently active shard relocations/recoveries:**
```json
GET _cat/recovery?active_only=true&v
```
- Non-empty list = relocations still running (check `bytes_percent` per row for progress)
- Empty list = nothing currently moving

**Check whether specific shards you moved actually landed where intended:**
```json
GET _cat/shards/<index1>,<index2>,<index3>?v&h=index,shard,prirep,store,node
```
An arrow (`node-A -> node-B`) in the `node` column means still in transit; a plain node name means it's settled there.

---

## Recommended order of operations, next time this comes up

1. Run the diagnose commands (section 1) to confirm there's a real imbalance and identify target shards
2. Run the move command (section 2) — batch 2-4 large shards across multiple destination nodes at once
3. **Immediately pause rebalancing** (section 3) rather than waiting to see if the auto-rebalancer interferes — this session showed it reliably does
4. Monitor with section 4 until `_cat/recovery` returns empty
5. Confirm final disk numbers via `_cat/allocation`
6. Re-enable rebalancing (section 3, resume command)
