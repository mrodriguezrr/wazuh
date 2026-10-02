# Thunder — Split 10 data nodes into 3 hot + 7 cold

**Cluster:** thunder (Elasticsearch 8.19) · **Prepared by:** SOC Team · **Date:** 2026-10-02

| Item | Value |
|---|---|
| Hot nodes | 3 (`data_hot`, `data_content`) |
| Cold nodes | 7 (`data_cold`) |
| Security logs retention | **40 days hot → cold → delete at 155 days** (sized for the real 1.93 TB disks so no node passes 85%) |
| Fortuna (all) and gaming-server | **7 days, hot only** (weekly indices deleted 14 days after creation, see Step 2.3) |
| Data to move | ~3.8 TB once (≈2.8 TB to hot, ≈1.0 TB to cold) |
| Expected end state | Hot ≈ 69% disk · Cold ≈ 22% disk right after the move · Steady state: hot peaks ≈ 83%, cold ≈ 84% once cold fills to 155 days |
| Duration | Restarts ~2–2.5 h (needs someone watching) · Data moves 6–8 h (raised throttle) or 14–24 h (default) |
| Reindexing | None. Shards are copied as files; searches keep working during moves |

> Cutting Fortuna and gaming-server to 7 days frees enough hot space for 40 days of security logs. 155 days is the most that keeps cold under 85% on 1.93 TB disks. The full 180 days needs about 2.7 TB more on the cold nodes.

All commands run in **Kibana Dev Tools** unless marked **[shell]**.

---

## Step 0 — Pre-checks (do not start until all pass)

### 0.1 Cluster is green and nothing is moving
```
GET _cluster/health?filter_path=status,number_of_data_nodes,relocating_shards,initializing_shards,unassigned_shards
```
Expect: `status: green`, `number_of_data_nodes: 10`, `relocating_shards: 0`, `initializing_shards: 0`, `unassigned_shards: 0`.

### 0.2 Current roles of every node (write these down)
```
GET _cat/nodes?v&h=name,ip,node.role,master,cpu,load_5m,heap.percent,ram.percent,allocated_processors&s=name
```
Role letters: `d` data (all tiers) · `h` data_hot · `s` data_content · `c` data_cold · `w` data_warm · `m` master · `i` ingest · `r` remote_cluster_client · `t` transform · `l` ml.

**Keep every non-data role a node has today** (`m`, `i`, `r`, `t`, `l`…). Only the data role changes. If a data node has `m`, it is master-eligible — do not drop it, or you can lose master quorum.

### 0.3 Disk per node
```
GET _cat/allocation?v&h=node,shards,disk.indices,disk.used,disk.total,disk.percent&s=node
```

### 0.4 No ILM errors
```
GET */_ilm/explain?only_errors=true&expand_wildcards=all&filter_path=indices.*.index,indices.*.step,indices.*.step_info.reason
```
Fix anything listed before continuing (e.g. the two `medianova.traffic … -fixed` indices).

### 0.5 No templates still creating replicas
```
GET _cat/indices?v&h=index,rep,pri.store.size&s=rep:desc&expand_wildcards=open
```
Non-system indices should show `rep 0`. Fix the remaining templates (`fortuna-services-logger`, `gaming-server`, `siem-template`, `ai-security-*`, `mlrep-*`, `winlogbeat-template`, `logstash`) first.

### 0.6 Choose the 3 hot nodes
Pick the 3 nodes with the **most CPU and RAM** (from 0.2). They will take all ingest, forcemerges and recent searches. If the hardware is identical, any 3.

| Hot | Cold |
|---|---|
| `elasiem-data-__` | `elasiem-data-__` |
| `elasiem-data-__` | `elasiem-data-__` |
| `elasiem-data-__` | `elasiem-data-__` |
| | `elasiem-data-__` |
| | `elasiem-data-__` |
| | `elasiem-data-__` |
| | `elasiem-data-__` |

---

## Step 1 — (Optional) Speed up data moves

Only if the network is 10 GbE and disks can take it. Default is 40 MB/s per node.
```
PUT _cluster/settings
{
  "persistent": {
    "indices.recovery.max_bytes_per_sec": "120mb"
  }
}
```

---

## Step 2 — Update the ILM policies

Indices pick up the new ages automatically.

- **Security logs (2.1, 2.2):** 40 d hot, deleted at 155 d. Nothing is deleted today (oldest security data is ~125 days).
- **Fortuna and gaming-server (2.3):** 7 days. The two oldest gaming-server weeks (`2026.37`, `2026.38`, ~80 GB) are deleted as soon as you apply it.

### 2.1 `soc-180d-large`
```
PUT _ilm/policy/soc-180d-large
{
  "policy": {
    "_meta": {
      "owner": "SOC",
      "description": "SOC high-volume logs: 40d hot, cold to 155d"
    },
    "phases": {
      "hot": {
        "min_age": "0ms",
        "actions": {
          "rollover": { "max_age": "7d", "max_primary_shard_size": "50gb" },
          "forcemerge": { "max_num_segments": 1 },
          "set_priority": { "priority": 100 }
        }
      },
      "cold": {
        "min_age": "40d",
        "actions": {
          "set_priority": { "priority": 0 }
        }
      },
      "delete": {
        "min_age": "155d",
        "actions": {
          "delete": { "delete_searchable_snapshot": true }
        }
      }
    }
  }
}
```

### 2.2 `soc-180d-small`
```
PUT _ilm/policy/soc-180d-small
{
  "policy": {
    "_meta": {
      "owner": "SOC",
      "description": "SOC low-volume logs: 40d hot, cold to 155d"
    },
    "phases": {
      "hot": {
        "min_age": "0ms",
        "actions": {
          "rollover": { "max_age": "30d", "max_primary_shard_size": "50gb" },
          "forcemerge": { "max_num_segments": 1 },
          "set_priority": { "priority": 100 }
        }
      },
      "cold": {
        "min_age": "40d",
        "actions": {
          "set_priority": { "priority": 0 }
        }
      },
      "delete": {
        "min_age": "155d",
        "actions": {
          "delete": { "delete_searchable_snapshot": true }
        }
      }
    }
  }
}
```

The cold phase moves data to `data_cold` nodes by itself (implicit `migrate`). No extra action needed.

### 2.3 Fortuna and gaming-server: 7 days

These are **weekly** indices (`…-2026-40`, `gaming-server-pa-2026.40`), and ILM counts their age from the day the index is created. A delete at `7d` would remove each week's index the moment it closes, leaving almost nothing on Monday morning. Deleting at **`14d`** keeps every log for at least 7 days (7–14 days on disk). The capacity numbers allow for this.

**Fortuna game services** (`index_logger_fortuna_services_gameservice*`). This also removes the warm phase. Its `forcemerge` at 2 days puts a write block on the weekly index while Fortuna is still writing to it, and with no warm nodes the warm phase does nothing else.
```
PUT _ilm/policy/fortuna-services-7d
{
  "policy": {
    "_meta": {
      "owner": "SOC",
      "description": "Fortuna game services, weekly indices: keep 7 days (delete 14d after creation)"
    },
    "phases": {
      "hot": {
        "min_age": "0ms",
        "actions": {
          "set_priority": { "priority": 100 }
        }
      },
      "delete": {
        "min_age": "14d",
        "actions": {
          "delete": { "delete_searchable_snapshot": true }
        }
      }
    }
  }
}
```

**Fortuna login and account** (`index_logger_fortuna_services_loginservice*`, `accountservice*`)
```
PUT _ilm/policy/app-audit-180d
{
  "policy": {
    "_meta": {
      "owner": "SOC",
      "description": "Fortuna login/account, weekly indices: keep 7 days (delete 14d after creation)"
    },
    "phases": {
      "hot": {
        "min_age": "0ms",
        "actions": {
          "set_priority": { "priority": 100 }
        }
      },
      "delete": {
        "min_age": "14d",
        "actions": {
          "delete": { "delete_searchable_snapshot": true }
        }
      }
    }
  }
}
```

**Gaming server** (`gaming-server-pa-*`)
```
PUT _ilm/policy/Delete_Indices_After30Days
{
  "policy": {
    "_meta": {
      "owner": "SOC",
      "description": "gaming-server, weekly indices: keep 7 days (delete 14d after creation)"
    },
    "phases": {
      "hot": {
        "min_age": "0ms",
        "actions": {
          "set_priority": { "priority": 100 }
        }
      },
      "delete": {
        "min_age": "14d",
        "actions": {
          "delete": { "delete_searchable_snapshot": true }
        }
      }
    }
  }
}
```
The policy names stay the same because the templates point to them. Only the `_meta` description shows the new retention.

Check whether the current Fortuna game index already has a write block from the old warm phase:
```
GET index_logger_fortuna_services_*/_settings/index.blocks.*?flat_settings=true
```
If `index.blocks.write: "true"` shows on the current week's index, remove it:
```
PUT index_logger_fortuna_services_gameservice*-2026-40/_settings
{ "index.blocks.write": null }
```

### 2.4 (Optional) Send legacy indices to cold too
`legacy-delete-180d` (vSphere, old linux-auth, pfSense, ~7 GB) has no cold phase, so it would stay on hot until deleted. To move it to cold at 40 days:
```
PUT _ilm/policy/legacy-delete-180d
{
  "policy": {
    "_meta": {
      "owner": "SOC",
      "description": "Legacy dated indices: cold at 40d, delete 180d after creation"
    },
    "phases": {
      "cold": {
        "min_age": "40d",
        "actions": {
          "set_priority": { "priority": 0 }
        }
      },
      "delete": {
        "min_age": "180d",
        "actions": {
          "delete": { "delete_searchable_snapshot": true }
        }
      }
    }
  }
}
```

### 2.5 Verify
```
GET _ilm/policy/soc-180d-large,soc-180d-small,fortuna-services-7d,app-audit-180d,Delete_Indices_After30Days,legacy-delete-180d?filter_path=*.policy.phases.*.min_age

GET _cat/indices/index_logger_fortuna*,gaming-server*?v&h=index,creation.date.string,pri.store.size&s=index
```

---

## Step 3 — Restart the 3 HOT nodes first (one at a time)

Hot first, so old data on them goes straight to nodes that will be cold, and nothing moves twice.

> No replicas: while a node is down, its shards are offline. Writes to those shards are rejected and Logstash/agents retry. Do this in a low-traffic window.

For **each** of the 3 hot nodes:

**3.1 Flush (faster restart)**
```
POST _flush
```

**3.2 Stop Elasticsearch** **[shell on the node]**
```bash
sudo systemctl stop elasticsearch
```

**3.3 Edit roles** **[shell]** — `/etc/elasticsearch/elasticsearch.yml`

Replace the `node.roles` line (or add it if missing). Keep any non-data roles the node had in 0.2:
```yaml
# HOT node — add back master / ingest / remote_cluster_client etc. if it had them
node.roles: [ data_hot, data_content, ingest, remote_cluster_client ]
```
> If `node.roles` was **not set** before, the node had **every** role (including master). Check 0.2 and list the roles explicitly.

**3.4 Start** **[shell]**
```bash
sudo systemctl start elasticsearch
sudo journalctl -u elasticsearch -f    # Ctrl+C once "started" appears
```

**3.5 Confirm roles and wait for green**
```
GET _cat/nodes?v&h=name,node.role&s=name

GET _cluster/health?wait_for_status=green&timeout=30m&filter_path=status,relocating_shards,unassigned_shards
```
Green = the node's shards are back. `relocating_shards` above 0 is normal (old data leaving this node). **Do not wait for it to reach 0**, go to the next hot node.

After all 3: older shards start moving from the hot nodes to the other 7.

---

## Step 4 — Restart the 7 COLD nodes (one at a time)

Same process as Step 3, with the cold roles.

**4.1** `POST _flush`

**4.2** **[shell]** `sudo systemctl stop elasticsearch`

**4.3** **[shell]** `/etc/elasticsearch/elasticsearch.yml`
```yaml
# COLD node — add back master / ingest / remote_cluster_client etc. if it had them
node.roles: [ data_cold, remote_cluster_client ]
```

**4.4** **[shell]** `sudo systemctl start elasticsearch`

**4.5** Confirm and wait for green:
```
GET _cat/nodes?v&h=name,node.role&s=name

GET _cluster/health?wait_for_status=green&timeout=30m&filter_path=status,relocating_shards,unassigned_shards
```

After each cold node restarts, its recent (hot) shards begin copying to the 3 hot nodes. The shard keeps serving from the cold node until the copy finishes.

If a restart happens while a shard is being copied to that node, the copy simply restarts. No action needed.

---

## Step 5 — Monitor the data moves (hours, no one needs to watch)

```
GET _cluster/health?filter_path=status,relocating_shards,initializing_shards,unassigned_shards

GET _cat/recovery?v&active_only=true&h=index,shard,source_node,target_node,bytes_percent,time&s=bytes_percent

GET _cat/allocation?v&h=node,shards,disk.indices,disk.percent&s=node
```
Done when `relocating_shards: 0`.

If any shard stays unassigned or will not move:
```
GET _cluster/allocation/explain
```

---

## Step 6 — Final checks

### 6.1 Roles
```
GET _cat/nodes?v&h=name,node.role&s=name
```
3 nodes with `hs` (+ others) · 7 nodes with `c` (+ others) · none with `d`.

### 6.2 Disk
```
GET _cat/allocation?v&h=node,disk.indices,disk.percent&s=disk.percent:desc
```
Expect hot ≈ 69%, cold ≈ 22%. All under 85%.

### 6.3 Data is on the right tier
```
GET logs-*/_ilm/explain?filter_path=indices.*.phase&expand_wildcards=all
```
```
GET _cat/shards/.ds-logs-*?v&h=index,node,store&s=node,index
```
Recent backing indices should be on the hot nodes and indices older than 40 days on the cold nodes.

### 6.4 No ILM errors
```
GET */_ilm/explain?only_errors=true&expand_wildcards=all&filter_path=indices.*.index,indices.*.step,indices.*.step_info.reason
```

### 6.5 Put the move speed back (if Step 1 was used)
```
PUT _cluster/settings
{
  "persistent": {
    "indices.recovery.max_bytes_per_sec": null
  }
}
```

### 6.6 Watch hot-node CPU for the first few days
```
GET _cat/nodes?v&h=name,node.role,cpu,load_1m,load_5m,heap.percent&s=cpu:desc

GET _nodes/stats/thread_pool/write,search,force_merge?filter_path=nodes.*.name,nodes.*.thread_pool.*.queue,nodes.*.thread_pool.*.rejected
```
If hot nodes stay above ~80% CPU or `write` rejections grow, consider removing `forcemerge` from the hot phase of the two SOC policies.

---

## Rollback

On any node, set the roles back to generic data (plus the non-data roles it had) and restart it:
```yaml
node.roles: [ data, ingest, remote_cluster_client ]
```
Elasticsearch spreads the shards evenly again. ILM policies can stay as they are.

---

## Reference — what stays on hot and never goes cold

| Data | Policy | Deleted at |
|---|---|---|
| Cloudflare WAF / traffic | `cloudflare-*-policy` | 30 d |
| Medianova traffic | `medianova-traffic-policy` | 30 d |
| Fortuna login / account | `app-audit-180d` | 7 d (weekly index deleted at 14 d) |
| Fortuna game services | `fortuna-services-7d` | 7 d (weekly index deleted at 14 d) |
| Gaming server | `Delete_Indices_After30Days` | 7 d (weekly index deleted at 14 d) |
| Cluster monitoring | `.monitoring-8-ilm-policy` | 3 d |
| Kibana / system indices | built-in | as managed by Kibana |
