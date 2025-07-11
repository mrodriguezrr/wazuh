# Wazuh — Command Reference

---

### Token authentication

```bash
TOKEN=$(curl -u wazuh-wui:[pass] -k -X POST "https://localhost:55000/security/user/authenticate?raw=true")
curl -k -X GET "https://localhost:55000/" -H "Authorization: Bearer $TOKEN"
curl -k -X GET "https://localhost:55000/manager/version/check" -H "Authorization: Bearer $TOKEN"
````

### Cloud

```bash
TOKEN=$(curl -u <user>:<password> -k -X POST "https://<CloudID>.cloud.wazuh.com/api/wazuh/security/user/authenticate?raw=true")
curl -k -X <METHOD> "https://<CloudID>.cloud.wazuh.com/api/wazuh/<ENDPOINT>" -H "Authorization: Bearer $TOKEN"
```

---

## Cluster Health & Index Allocation

```http
GET _cluster/health
GET _cluster/allocation/explain?pretty
GET _cat/shards?h=index,shard,prirep,state,unassigned.reason
GET _cluster/settings?include_defaults
```

Update index settings:

```http
PUT /[IDX_NAME]/_settings
{
  "number_of_replicas": 0,
  "index.auto_expand_replicas": false
}
```

---

## Curl Commands (Basic Auth)

```bash
curl -u admin:<pass> -k -X GET "https://localhost:9200/_cluster/health"
curl -u admin:<pass> -k -X GET "https://localhost:9200/_cluster/allocation/explain?pretty"
curl -u admin:<pass> -k -X GET "https://localhost:9200/_cat/shards?h=index,shard,prirep,state,unassigned.reason"
curl -u admin:<pass> -k -X PUT "https://localhost:9200/[IDX_NAME]/_settings" \
-H 'Content-Type: application/json' \
-d '{ "index.number_of_replicas": 0, "index.auto_expand_replicas": false }'

curl -X DELETE "https://localhost:9200/[index-name]" -u admin:<pass> -k
```

---

## Curl With Certs

```bash
curl --cert /etc/wazuh-indexer/certs/admin.pem \
     --key /etc/wazuh-indexer/certs/admin-key.pem -k \
     -X GET "https://localhost:9200/_cluster/health"

curl --cert /etc/wazuh-indexer/certs/admin.pem \
     --key /etc/wazuh-indexer/certs/admin-key.pem -k \
     -X GET "https://localhost:9200/_cat/shards?h=index,shard,prirep,state,unassigned.reason"

curl -k --cert /etc/wazuh-indexer/certs/admin.pem \
     --key /etc/wazuh-indexer/certs/admin-key.pem -X PUT \
     "https://localhost:9200/[IDX_NAME]/_settings" \
     -H 'Content-Type: application/json' \
     -d '{ "index.number_of_replicas": 0, "index.auto_expand_replicas": false }'
```

---

## Indexer & Dashboard Plugins

```bash
/usr/share/wazuh-indexer/bin/opensearch-plugin list

sudo -u wazuh-dashboard /usr/share/wazuh-dashboard/bin/opensearch-dashboards-plugin list
sudo -u wazuh-dashboard /usr/share/wazuh-dashboard/bin/opensearch-dashboards-plugin remove <PLUGIN_NAME>
sudo -u wazuh-dashboard /usr/share/wazuh-dashboard/bin/opensearch-dashboards-plugin install <PLUGIN_NAME>
```

---

## Reindexing & Field Changes

```bash
GET _cat/indices/wazuh-alerts-*
GET _cat/indices/wazuh-*?h=index
POST wazuh-alerts-4.x-2025.06.30/_doc
{
  "timestamp": "2000-01-01T00:00:00.999-0300",
  "data": { "UsedCpuPercent": 0.0 }
}
```

```bash
GET /_template/wazuh?pretty
GET /wazuh-alerts-4.x-2025.07.01/_mapping/field/full_log
GET _mapping/field/full_log
```

Reindex flow:

```bash
POST _reindex
{
  "source": { "index": "wazuh-alerts-4.x-2025.06.30" },
  "dest": { "index": "wazuh-2025.06.30-backup" }
}

DELETE /wazuh-alerts-4.x-2025.06.30

POST _reindex
{
  "source": { "index": "wazuh-2025.06.30-backup" },
  "dest": { "index": "wazuh-alerts-4.x-2025.06.30" }
}

DELETE /wazuh-2025.06.30-backup
```

---

## ISM Index Policies Review

```bash
GET _plugins/_ism/explain
GET _plugins/_ism/policies
GET _plugins/_ism/policies/30d_policy?pretty=true
GET _plugins/_ism/explain/wazuh-*
```

---

## Journal & Log Checks

```bash
journalctl -xeu wazuh-dashboard --no-pager | grep -Ei "warn|error"
journalctl -xeu wazuh-indexer --no-pager | grep -Ei "warn|error"

cat /var/log/wazuh-indexer/wazuh-cluster.log | grep -Ei "warn|error"
cat /var/log/filebeat/filebeat* | grep -i "warn|error"
cat /var/ossec/logs/ossec.log | grep -i "warn|error"
```

---

## Disk & File Checks

```bash
du -skh /home/ubuntu/* | sort -hr
du / -h --max-depth=1 2>/dev/null
```

---

## Generate Test Logs

```bash
for i in {1..8}; do echo '[log_sample]' >> /home/ubuntu/test ; done
```

---

## Disable Wazuh APT Repo

```bash
sed -i "s/^deb/#deb/" /etc/apt/sources.list.d/wazuh.list
apt-get update
```

---

## SSL Certificate Info

```bash
openssl x509 -in /etc/wazuh-dashboard/certs/dashboard.pem -noout -text
```

---

## Port Tests (PowerShell)

```powershell
(new-object Net.Sockets.TcpClient).Connect("<WAZUH_MANAGER_IP>", 1514)
(new-object Net.Sockets.TcpClient).Connect("<WAZUH_MANAGER_IP>", 1515)
(new-object Net.Sockets.TcpClient).Connect("<WAZUH_MANAGER_IP>", 55000)
(new-object Net.Sockets.TcpClient).Connect("60uucs2tvp15.cloud.wazuh.com", 1514)
```

---

**Author:** Mainor Rodriguez
**Last Updated:** July 11, 2025


