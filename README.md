````markdown
#  Wazuh / OpenSearch Useful Commands
````

---

## 1.  Token On-Prem

```bash
TOKEN=$(curl -u wazuh-wui:[pass] -k -X POST "https://localhost:55000/security/user/authenticate?raw=true")
curl -k -X GET "https://localhost:55000/" -H "Authorization: Bearer $TOKEN"
curl -k -X GET "https://localhost:55000/manager/version/check" -H "Authorization: Bearer $TOKEN"
````

---

## 2.  Cloud Token Usage

```bash
TOKEN=$(curl -u <user>:<password> -k -X POST "https://<CloudID>.cloud.wazuh.com/api/wazuh/security/user/authenticate?raw=true")
curl -k -X <METHOD> "https://<CloudID>.cloud.wazuh.com/api/wazuh/<ENDPOINT>" -H "Authorization: Bearer $TOKEN"
```

---

## 3.  Cluster Health & Index Allocation

```bash
GET _cluster/health
GET _cluster/allocation/explain?pretty
GET _cat/shards?h=index,shard,prirep,state,unassigned.reason
GET _cluster/settings?include_defaults
PUT /[IDX_NAME]/_settings
{
  "number_of_replicas": 0,
  "index.auto_expand_replicas": false
}
```

---

## 4.  Curl Commands (Basic Auth)

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

## 5.  Curl with Certs

```bash
curl --cert /etc/wazuh-indexer/certs/admin.pem --key /etc/wazuh-indexer/certs/admin-key.pem -k -X GET "https://localhost:9200/_cluster/health"
curl --cert /etc/wazuh-indexer/certs/admin.pem --key /etc/wazuh-indexer/certs/admin-key.pem -k -X GET "https://localhost:9200/_cat/shards?h=index,shard,prirep,state,unassigned.reason"
curl -k --cert /etc/wazuh-indexer/certs/admin.pem --key /etc/wazuh-indexer/certs/admin-key.pem -X PUT "https://localhost:9200/[IDX_NAME]/_settings" \
  -H 'Content-Type: application/json' \
  -d '{ "index.number_of_replicas": 0, "index.auto_expand_replicas": false }'
```

---

## 6.  Indexer & Dashboard Plugins

```bash
/usr/share/wazuh-indexer/bin/opensearch-plugin list
sudo -u wazuh-dashboard /usr/share/wazuh-dashboard/bin/opensearch-dashboards-plugin list
sudo -u wazuh-dashboard /usr/share/wazuh-dashboard/bin/opensearch-dashboards-plugin remove <PLUGIN_NAME>
sudo -u wazuh-dashboard /usr/share/wazuh-dashboard/bin/opensearch-dashboards-plugin install <PLUGIN_NAME>
```

---

## 7.  Reindexing & Field Changes

```bash
GET _cat/indices/wazuh-alerts-*
GET _cat/indices/wazuh-*?h=index
GET /wazuh-alerts-*/_stats/store
GET _cat/indices/wazuh-alerts-*?bytes=gb&s=index

```

---

## 8.  Templates & Reindexing

```bash
GET /_template/wazuh?pretty
GET /wazuh-alerts-4.x-2025.MM.DD/_mapping/field/full_log

POST _reindex
{
  "source": { "index": "wazuh-alerts-4.x-2025.MM.DD" },
  "dest":   { "index": "wazuh-2025.MM.DD-backup" }
}
DELETE /wazuh-alerts-4.x-2025.MM.DD
```

---

## 9.  ISM Index Policies

```bash
GET _plugins/_ism/explain
GET _plugins/_ism/policies
GET _plugins/_ism/policies/30d_policy?pretty=true
GET _plugins/_ism/explain/wazuh-*
```

---

## 10.  Journal & Log Checks

```bash
journalctl -xeu wazuh-dashboard --no-pager | grep -Ei "warn|error"
journalctl -xeu wazuh-indexer --no-pager | grep -Ei "warn|error"
cat /var/log/filebeat/filebeat* | grep -i "warn|error"
cat /var/ossec/logs/ossec.log | grep -i "warn|error"
```

---

## 11.  Disk & File Checks

```bash
du -skh /home/ubuntu/* | sort -hr
du / -h --max-depth=1 2>/dev/null
```

---

## 12.  Generate Fake Logs

```bash
for i in {1..8}; do echo '[log_sample]' >> /home/ubuntu/test ; done
```

---

## 13.  Exclude Wazuh APT Repo

```bash
sed -i "s/^deb/#deb/" /etc/apt/sources.list.d/wazuh.list
apt-get update
```

---

## 14.  SSL Cert Info

```bash
openssl x509 -in /etc/wazuh-dashboard/certs/dashboard.pem -noout -text
```

---

## 15.  Port Tests (PowerShell)

```powershell
(new-object Net.Sockets.TcpClient).Connect("<WAZUH_MANAGER_IP>", 1514)
(new-object Net.Sockets.TcpClient).Connect("<WAZUH_MANAGER_IP>", 1515)
(new-object Net.Sockets.TcpClient).Connect("<WAZUH_MANAGER_IP>", 55000)
(new-object Net.Sockets.TcpClient).Connect("60uucs2tvp15.cloud.wazuh.com", 1514)
```

---

## 16.  Regex for Private IPs

```regex
(10\.\d+\.\d+\.\d+)|(172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+)|(192\.168\.\d+\.\d+)
```

---

## 17.  Update Indexer Credentials

```bash
echo '<INDEXER_USERNAME>' | /var/ossec/bin/wazuh-keystore -f indexer -k username
echo '<INDEXER_PASSWORD>' | /var/ossec/bin/wazuh-keystore -f indexer -k password

echo <CUSTOM_USERNAME> | filebeat keystore add username --stdin --force
echo <CUSTOM_PASSWORD> | filebeat keystore add password --stdin --force
```

---

## 18.  Upgrade Agents via API

```bash
PUT /agents/upgrade?agents_list=all&pretty=true
GET /agents/upgrade_result
PUT /agents/upgrade?agents_list=all&wait_for_complete=true&pretty=true
PUT /agents/upgrade?agents_list=005,007&pretty=true
```

---

## 19.  Processor (Object → Not Object)

```json
{
  "rename": {
    "if": "ctx?.data?.data != null && !(ctx?.data?.data instanceof char)",
    "field": "data.data",
    "target_field": "data.data_notObj",
    "ignore_missing": true,
    "ignore_failure": true
  }
}
```

```

```
