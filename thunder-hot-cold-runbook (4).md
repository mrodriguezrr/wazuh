# Thunder — Split 10 data nodes into 3 hot + 7 cold

**Cluster:** thunder (Elasticsearch 8.19) · **Prepared by:** SOC Team · **Date:** 2026-10-05

| Item | Value |
|---|---|
| Hot nodes | 3 (`data_hot`, `data_content`) |
| Cold nodes | 7 (`data_cold`) |
| Security logs retention | **37 days hot → cold → delete at 152 days** (sized for the real 1.93 TB disks so no node passes 85%) |
| Fortuna login and account | **15 days, hot only** (weekly indices deleted 22 days after creation, see Step 2.3) |
| Fortuna game services and gaming-server | **7 days, hot only** (weekly indices deleted 14 days after creation, see Step 2.3) |
| Data to move | ~3.7 TB once (≈2.7 TB to hot, ≈1.0 TB to cold) |
| Expected end state | Hot ≈ 65% disk · Cold ≈ 23% disk right after the move · Steady state: hot peaks ≈ 80%, cold ≈ 84% once cold fills to 152 days |
| Duration | Container recreation ~2–2.5 h for 10 nodes (needs someone watching) · Data moves 6–8 h (raised throttle) or 14–24 h (default) |
| Reindexing | None. Shards are copied as files; searches keep working during moves |

> 37 days on hot makes the hot nodes peak at about 80%. Cold keeps 115 days under 85% on 1.93 TB disks, so the total is 152 days. The full 180 days needs about 3.1 TB more on the cold nodes.

All commands run in **Kibana Dev Tools** unless marked **[shell]** (root on the data server). Each Elasticsearch data node runs in a **Docker container**, one container per server.

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

### 0.6 Docker checks on every data server **[shell]** — send the output before Step 3

Run on each of the 10 servers. Set `C` to the Elasticsearch container name first.
```bash
docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}'
C=<elasticsearch_container_name>

# a) Compose or plain docker run? (empty = docker run)
docker inspect $C --format 'compose_dir={{index .Config.Labels "com.docker.compose.project.working_dir"}} files={{index .Config.Labels "com.docker.compose.project.config_files"}} service={{index .Config.Labels "com.docker.compose.service"}}'

# b) Node settings passed as environment variables
docker inspect $C --format '{{range .Config.Env}}{{println .}}{{end}}' | grep -iE 'node\.|role|cluster\.name|discovery|ES_JAVA'

# c) Mounts — data MUST be on the host
docker inspect $C --format '{{range .Mounts}}{{.Type}}  {{.Source}} -> {{.Destination}}{{println}}{{end}}'

# d) Roles in the config file the container uses
docker exec $C grep -nE 'node\.(roles|name|attr)' /usr/share/elasticsearch/config/elasticsearch.yml

# e) Restart policy and stop timeout
docker inspect $C --format 'restart={{.HostConfig.RestartPolicy.Name}} stoptimeout={{.Config.StopTimeout}}'

# f) Host disk where the data lives
df -h $(docker inspect $C --format '{{range .Mounts}}{{if eq .Destination "/usr/share/elasticsearch/data"}}{{.Source}}{{end}}{{end}}')
```

| Check | Must be | If not |
|---|---|---|
| **c) `/usr/share/elasticsearch/data`** | A `bind` or `volume` mount to the host | **STOP.** Recreating the container would delete this node's data, and there are no replicas. |
| **b) / d) `node.roles`** | Found in one place | Tells you the method in Step 3: **A** (edit a mounted `elasticsearch.yml`, then restart) or **B** (change an env var, then recreate) |
| **e) `stoptimeout`** | Any | Always stop with `docker stop -t 120`. The default 10 s kills Elasticsearch before it shuts down cleanly. |
| **e) `restart`** | Any | `always` / `unless-stopped` are fine with `docker stop`. Do not stop through `systemctl stop docker`. |

**Back up the file you will change** (on each server, before Step 3):
```bash
# Method A — mounted elasticsearch.yml (use the host path from check c)
cp -a /path/on/host/elasticsearch.yml /path/on/host/elasticsearch.yml.bak-$(date +%F)

# Method B — compose file (use compose_dir from check a)
cp -a <compose_dir>/docker-compose.yml <compose_dir>/docker-compose.yml.bak-$(date +%F)

# Plain docker run — save the full container definition
docker inspect $C > /root/$C-inspect-$(date +%F).json
```

### 0.7 Node plan (from the 2026-10-05 checks)

All containers were created with `/opt/docker/elastic/docker.sh` (plain `docker run`, `--network=host`, data on `/mnt/elastic/data`). Roles are an environment variable, so **each container is recreated** with the same command and new roles. Masters are separate (10.8.101.221–223), so no data node is master-eligible.

| Node | IP | RAM | Heap (keep) | Roles today | **New tier** | **New `node.roles`** | Order |
|---|---|---|---|---|---|---|---|
| elasiem-data-02 | 10.8.101.212 | 70 GB | 50g | data, ingest, ml, rcc | **HOT** | `data_hot,data_content,ingest,ml,remote_cluster_client` | 1 |
| elasiem-data-03 | 10.8.101.213 | 70 GB | 50g | data, ingest, ml, rcc | **HOT** | `data_hot,data_content,ingest,ml,remote_cluster_client` | 2 |
| elasiem-data-04 | 10.8.101.214 | 70 GB | 50g | data, ingest, ml, rcc | **HOT** | `data_hot,data_content,ingest,ml,remote_cluster_client` | 3 |
| elasiem-data-07 | 10.8.101.231 | 31 GB | 24g | data, ingest, ml | cold | `data_cold,ingest,ml` | 4 |
| elasiem-data-08 | 10.8.101.232 | 31 GB | 24g | data, ingest, ml | cold | `data_cold,ingest,ml` | 5 |
| elasiem-data-10 | 10.8.101.234 | 31 GB | 24g | data, ingest, ml | cold | `data_cold,ingest,ml` | 6 |
| elasiem-data-09 | 10.8.101.233 | 70 GB | 50g | data, ingest, ml | cold | `data_cold,ingest,ml` | 7 |
| elasiem-data-05 | 10.8.101.215 | 70 GB | 50g | data, ingest, ml, rcc | cold | `data_cold,ingest,ml,remote_cluster_client` | 8 |
| elasiem-data-06 | 10.8.101.216 | 70 GB | 50g | data, ingest, ml, rcc | cold | `data_cold,ingest,ml,remote_cluster_client` | 9 |
| elasiem-data-01 | 10.8.101.211 | 70 GB | 31g | data, ingest, ml, rcc | cold | `data_cold,ingest,ml,remote_cluster_client` | 10 — **special, see 3.0** |

*rcc = remote_cluster_client.* Non-data roles are kept exactly as today. The 31 GB-RAM nodes (07, 08, 10) are cold because hot takes all ingest and recent searches.

> **Heap (optional, not part of this change):** 50g is above the ~31 GB compressed-pointer limit and takes RAM from the file cache. To change it, pass `31g` instead of `50g` in Step 3. Default in this runbook: keep today's heap so only the roles change.

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

- **Security logs (2.1, 2.2):** 37 d hot, deleted at 152 d. Nothing is deleted today (oldest security data is ~125 days).
- **Fortuna and gaming-server (2.3):** login and account 15 days; game services and gaming-server 7 days. Any gaming-server week older than 14 days (today `2026.37`–`2026.39`, ~115 GB) is deleted as soon as you apply it.

### 2.1 `soc-180d-large`
```
PUT _ilm/policy/soc-180d-large
{
  "policy": {
    "_meta": {
      "owner": "SOC",
      "description": "SOC high-volume logs: 37d hot, cold to 152d"
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
        "min_age": "37d",
        "actions": {
          "set_priority": { "priority": 0 }
        }
      },
      "delete": {
        "min_age": "152d",
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
      "description": "SOC low-volume logs: 37d hot, cold to 152d"
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
        "min_age": "37d",
        "actions": {
          "set_priority": { "priority": 0 }
        }
      },
      "delete": {
        "min_age": "152d",
        "actions": {
          "delete": { "delete_searchable_snapshot": true }
        }
      }
    }
  }
}
```

The cold phase moves data to `data_cold` nodes by itself (implicit `migrate`). No extra action needed.

### 2.3 Fortuna and gaming-server: 15 and 7 days

These are **weekly** indices (`…-2026-40`, `gaming-server-pa-2026.40`), and ILM counts their age from the day the index is created. A delete at `7d` would remove each week's index the moment it closes, leaving almost nothing on Monday morning. So the delete is set one week later than the retention: **`22d`** keeps login and account logs at least 15 days (15–22 on disk), and **`14d`** keeps game services and gaming-server at least 7 days (7–14 on disk). The capacity numbers allow for this.

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
      "description": "Fortuna login/account, weekly indices: keep 15 days (delete 22d after creation)"
    },
    "phases": {
      "hot": {
        "min_age": "0ms",
        "actions": {
          "set_priority": { "priority": 100 }
        }
      },
      "delete": {
        "min_age": "22d",
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
`legacy-delete-180d` (vSphere, old linux-auth, pfSense, ~7 GB) has no cold phase, so it would stay on hot until deleted. To move it to cold at 37 days:
```
PUT _ilm/policy/legacy-delete-180d
{
  "policy": {
    "_meta": {
      "owner": "SOC",
      "description": "Legacy dated indices: cold at 37d, delete 180d after creation"
    },
    "phases": {
      "cold": {
        "min_age": "37d",
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

## Step 3 — Recreate the containers, one node at a time

Order: **02 → 03 → 04 (hot)**, then **07 → 08 → 10 → 09 → 05 → 06 → 01 (cold)**. Hot first, so old data leaves the hot nodes straight to nodes that will be cold, and nothing moves twice.

> No replicas: while a node is down, its shards are offline. Writes to those shards are rejected and Logstash/agents retry. Each node is down ~2–5 minutes. Do this in a low-traffic window.

### 3.0 data-01 only — keep its login config (before data-01's turn)

data-01's container has an edited `elasticsearch.yml` (Keycloak OIDC realm) and a keystore secret (`…keycloak-oidc.rp.client_secret`) that exist **only inside the container**. Copy them to the host so the new container mounts them:
```bash
mkdir -p /mnt/elastic/config-keep
docker cp elasticsearch:/usr/share/elasticsearch/config/elasticsearch.yml      /mnt/elastic/config-keep/
docker cp elasticsearch:/usr/share/elasticsearch/config/elasticsearch.keystore /mnt/elastic/config-keep/
chown 1000:0 /mnt/elastic/config-keep/*; chmod 660 /mnt/elastic/config-keep/*
ls -l /mnt/elastic/config-keep/
```
The script in 3.1 mounts these two files automatically when `/mnt/elastic/config-keep/` exists. **Do not create that folder on any other node.**

The realm in that file (`xpack.security.authc.realms.oidc.keycloak-oidc`, client `kibana-oidc`, issuer `auth.reduno.online/realms/hc-corp-prod`) exists **only on data-01**.

Kibana (checked 2026-10-05 on `elakiba`):

| Kibana container | Connects to | Affected by this change |
|---|---|---|
| `thunder.arborys.net` (config `/opt/docker/kibana-siem/config/kibana.yml`) | data-01, data-02, data-03 (`:44399`) | Stays up: while one of the three is recreated, Kibana uses the other two. Keycloak SSO depends on data-01 only, so SSO may fail during data-01's 2–5 minutes. |
| `thunder.arborys.net-windows` | 10.8.101.218 (another cluster) | No |

Recreate data-01 last and avoid SSO logins during its window. Users already logged in keep their session.

### 3.1 Install the recreate script (once per server) **[shell, root]**

Same settings as `/opt/docker/elastic/docker.sh`; only roles and heap are parameters.
```bash
cat > /root/es-recreate.sh <<'SCRIPT'
#!/bin/bash
# Usage: /root/es-recreate.sh "<node.roles>" "<heap, e.g. 50g>"
set -euo pipefail
ROLES="${1:?roles missing}"; HEAP="${2:?heap missing}"
[ "$(id -u)" = 0 ]                       || { echo "Run as root"; exit 1; }
docker inspect elasticsearch >/dev/null  || { echo "No container named elasticsearch"; exit 1; }
[ -d /mnt/elastic/data ]                 || { echo "/mnt/elastic/data missing - STOP"; exit 1; }
if docker inspect elasticsearch-old >/dev/null 2>&1; then echo "elasticsearch-old already exists - clean up first"; exit 1; fi

EXTRA=()
if [ -d /mnt/elastic/config-keep ]; then
  EXTRA+=(-v /mnt/elastic/config-keep/elasticsearch.yml:/usr/share/elasticsearch/config/elasticsearch.yml)
  EXTRA+=(-v /mnt/elastic/config-keep/elasticsearch.keystore:/usr/share/elasticsearch/config/elasticsearch.keystore)
fi

docker inspect elasticsearch > /root/es-inspect-before-$(date +%F-%H%M).json
echo ">> stopping (up to 120 s)"; docker stop -t 120 elasticsearch
docker rename elasticsearch elasticsearch-old
docker update --restart=no elasticsearch-old >/dev/null   # the old one must never auto-start

echo ">> starting with roles=$ROLES heap=$HEAP"
docker run -d \
--name elasticsearch \
--restart=always \
--privileged \
--network=host \
--hostname=$(hostname) \
--ulimit nofile=1000000:1000000 \
--ulimit memlock=-1:-1 \
-v /mnt/elastic/data:/usr/share/elasticsearch/data \
-v /mnt/elastic/logs:/usr/share/elasticsearch/logs \
-v /mnt/elastic/cert:/usr/share/elasticsearch/config/cert/ \
-v /mnt/elastic/snap:/usr/share/elasticsearch/backup \
"${EXTRA[@]}" \
-e "network.host=$(hostname -i)" \
-e "cluster.name=siem" \
-e "node.name=$(hostname)" \
-e "node.roles=$ROLES" \
-e "discovery.seed_hosts=10.8.101.221,10.8.101.222,10.8.101.223" \
-e "http.port=44399" \
-e "transport.port=44388" \
-e "bootstrap.memory_lock=true" \
-e "ES_JAVA_OPTS=-Xms$HEAP -Xmx$HEAP" \
-e "thread_pool.search.queue_size=1000000" \
-e "thread_pool.write.queue_size=1000000" \
-e "xpack.ml.enabled=true" \
-e "xpack.license.self_generated.type=basic" \
-e "xpack.security.http.ssl.enabled=true" \
-e "xpack.security.http.ssl.verification_mode=certificate" \
-e "xpack.security.http.ssl.certificate=/usr/share/elasticsearch/config/cert/techpro.cr.crt" \
-e "xpack.security.http.ssl.key=/usr/share/elasticsearch/config/cert/techpro.cr.key" \
-e "xpack.security.transport.ssl.enabled=true" \
-e "xpack.security.transport.ssl.verification_mode=certificate" \
-e "xpack.security.transport.ssl.keystore.path=/usr/share/elasticsearch/config/cert/elastic-certificates.p12" \
-e "xpack.security.transport.ssl.truststore.path=/usr/share/elasticsearch/config/cert/elastic-certificates.p12" \
-e "path.repo=/usr/share/elasticsearch/backup" \
docker.elastic.co/elasticsearch/elasticsearch:8.19.12

docker ps --filter name=^elasticsearch$ --format '>> new container: {{.Names}} {{.Status}}'
echo '>> follow the log until you see "started":  docker logs -f --since 1m elasticsearch'
SCRIPT
chmod 700 /root/es-recreate.sh
```

### 3.2 For each node, in order

**a) Dev Tools — flush**
```
POST _flush
```

**b) Shell (root) — recreate with the node's roles and heap (table 0.7)**

| Nodes | Command |
|---|---|
| 02, 03, 04 (hot) | `/root/es-recreate.sh "data_hot,data_content,ingest,ml,remote_cluster_client" 50g` |
| 07, 08, 10 (cold) | `/root/es-recreate.sh "data_cold,ingest,ml" 24g` |
| 09 (cold) | `/root/es-recreate.sh "data_cold,ingest,ml" 50g` |
| 05, 06 (cold) | `/root/es-recreate.sh "data_cold,ingest,ml,remote_cluster_client" 50g` |
| 01 (cold, after 3.0) | `/root/es-recreate.sh "data_cold,ingest,ml,remote_cluster_client" 31g` |

**c) Shell — watch it start**
```bash
docker logs -f --since 1m elasticsearch    # Ctrl+C once you see "started"
```
If it does not start within ~3 minutes or shows errors: **roll back (3.3)** and send the log.

**d) Dev Tools — confirm roles and wait for green**
```
GET _cat/nodes?v&h=name,node.role&s=name

GET _cluster/health?wait_for_status=green&timeout=30m&filter_path=status,relocating_shards,unassigned_shards
```
- Hot nodes show `hilrs`; cold nodes show `cil` or `cilr` (`h` hot, `s` content, `c` cold, `i` ingest, `l` ml, `r` remote_cluster_client).
- Green = the node's shards are back. `relocating_shards` above 0 is normal. **Do not wait for it to reach 0**; go to the next node.

**e) data-01 only — log in to Kibana with Keycloak SSO** to confirm login still works.

### 3.3 Roll back one node (if needed)
```bash
docker stop -t 120 elasticsearch; docker rm elasticsearch
docker rename elasticsearch-old elasticsearch
docker update --restart=always elasticsearch
docker start elasticsearch
```

### 3.4 Clean up the old containers (after Step 5 passes, e.g. next day)
```bash
docker rm elasticsearch-old
```

---

## Step 4 — Monitor the data moves (hours, no one needs to watch)

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

## Step 5 — Final checks

### 5.1 Roles
```
GET _cat/nodes?v&h=name,node.role&s=name
```
3 nodes with `hs` (+ others) · 7 nodes with `c` (+ others) · none with `d`.

### 5.2 Disk
```
GET _cat/allocation?v&h=node,disk.indices,disk.percent&s=disk.percent:desc
```
Expect hot ≈ 65%, cold ≈ 23%. All under 85%.

### 5.3 Data is on the right tier
```
GET logs-*/_ilm/explain?filter_path=indices.*.phase&expand_wildcards=all
```
```
GET _cat/shards/.ds-logs-*?v&h=index,node,store&s=node,index
```
Recent backing indices should be on the hot nodes and indices older than 37 days on the cold nodes.

### 5.4 No ILM errors
```
GET */_ilm/explain?only_errors=true&expand_wildcards=all&filter_path=indices.*.index,indices.*.step,indices.*.step_info.reason
```

### 5.5 Put the move speed back (if Step 1 was used)
```
PUT _cluster/settings
{
  "persistent": {
    "indices.recovery.max_bytes_per_sec": null
  }
}
```

### 5.6 Watch hot-node CPU for the first few days
```
GET _cat/nodes?v&h=name,node.role,cpu,load_1m,load_5m,heap.percent&s=cpu:desc

GET _nodes/stats/thread_pool/write,search,force_merge?filter_path=nodes.*.name,nodes.*.thread_pool.*.queue,nodes.*.thread_pool.*.rejected
```
If hot nodes stay above ~80% CPU or `write` rejections grow, consider removing `forcemerge` from the hot phase of the two SOC policies.

---

## Rollback

Per node, while `elasticsearch-old` still exists: Step 3.3. After the old containers are removed, run `/root/es-recreate.sh` with the node's **original** roles (`data,ingest,ml` or `data,ingest,ml,remote_cluster_client`) and heap from table 0.7. Elasticsearch spreads the shards evenly again. ILM policies can stay as they are.
---

## Reference — what stays on hot and never goes cold

| Data | Policy | Deleted at |
|---|---|---|
| Cloudflare WAF / traffic | `cloudflare-*-policy` | 30 d |
| Medianova traffic | `medianova-traffic-policy` | 30 d |
| Fortuna login / account | `app-audit-180d` | 15 d (weekly index deleted at 22 d) |
| Fortuna game services | `fortuna-services-7d` | 7 d (weekly index deleted at 14 d) |
| Gaming server | `Delete_Indices_After30Days` | 7 d (weekly index deleted at 14 d) |
| Cluster monitoring | `.monitoring-8-ilm-policy` | 3 d |
| Kibana / system indices | built-in | as managed by Kibana |
