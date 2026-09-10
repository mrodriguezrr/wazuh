# Seclab Pipeline Testing — Standard Procedure

A repeatable process for validating any change to a production Logstash pipeline (new field extraction, filter logic, index mapping change) before merging to GitLab. Based on real issues hit and fixed during prior seclab testing sessions — follow this order to avoid re-discovering the same bugs.

---

## Before you start: decide the input mechanism

Check the **production** pipeline's `input {}` block first — the lab version should match it, not simplify it. A simplified stand-in (e.g. UDP injection for a pipeline that really uses `file`) tests a different pipeline than the one going to production, and can hide bugs that only show up with the real input mechanism.

| Production input | Lab input | Why |
|---|---|---|
| `udp { ... }` | `udp`, same port pattern | Direct match, no translation needed |
| `file { ... }` | `file`, pointed at a local log file you append test lines to | Preserves any file-specific behavior (multiline, path globbing, exclude patterns) |

If production uses `file`, don't substitute UDP for convenience — copy the real `input` block and just repoint the `path`.

---

## Phase 1 — Mirror the production index mapping

**1.1 Pull the current production mapping** for whatever index/data stream the pipeline writes to:

```json
GET <production-index-or-data-stream>/_mapping
```

**1.2 Apply your intended field change** to a copy of that mapping (add/remove/modify the field), keeping everything else identical.

**1.3 Build the test index template — with an explicit `priority`, always:**

```json
PUT _index_template/<name>-lab-template
{
  "index_patterns": ["<name>-lab*"],
  "priority": 500,
  "template": {
    "settings": { "number_of_shards": 1, "number_of_replicas": 0 },
    "mappings": { "properties": { /* your mapping, with the field change applied */ } }
  }
}
```

⚠️ **Do not omit `priority`.** A template with no explicit priority defaults to `0`, the lowest possible — if any other template in the cluster (including Elastic's own built-in `logs` template, priority 100, pattern `logs-*-*`) also matches your index name, it silently wins and your mapping never applies. This produces an empty `{"mappings": {}}` with no error message, and is the single most time-consuming bug to diagnose after the fact. Setting `priority` explicitly avoids it entirely.

⚠️ **Avoid names matching `logs-*-*`** (i.e., `logs-<word>-<word>`) unless you actually want a **data stream** — that pattern belongs to Elastic's built-in template and forces data-stream-only creation. A simple name like `<service>-lab-template` with pattern `<service>-lab*` sidesteps this.

---

## Phase 2 — Create the test index

```json
PUT <name>-lab
```

**Verify the template actually applied** before moving on — don't assume:

```json
GET <name>-lab/_mapping
```

Confirm the changed field shows the correct type, and that unrelated fields match production. If this comes back empty, stop — go back to Phase 1 and check `priority`/pattern matching before doing anything else, since nothing downstream will work correctly against an unmapped index.

---

## Phase 3 — Set up the lab pipeline

**3.1 Copy the real pipeline file verbatim** from GitLab/production into a new file under `/etc/logstash/lab-<name>/`. Do not hand-retype it — copy-paste to guarantee the filter logic is byte-identical to what's actually deployed.

**3.2 Make only these changes:**
- `input`: repoint to lab (same type as production — see the table above)
- `output`: point at `<name>-lab` (the index from Phase 2), with `manage_template => false` and `ilm_enabled => false` (you're managing the template yourself, don't let the output plugin try to)
- Add your actual field-change logic (the grok/mutate/etc. being tested)

**3.3 For `file`-input pipelines specifically:**

```
input {
  file {
    path           => "/var/log/<service>/lab.<ext>"
    type           => "<same type as production>"
    codec          => <same codec as production>
    start_position => "beginning"
    sincedb_path   => "/dev/null"
  }
}
```

- `start_position => "beginning"` + `sincedb_path => "/dev/null"` — lab-only settings, never use in production. This makes Logstash re-read the entire file from the start on every restart, which is exactly what you want for repeatable testing but would cause duplicate ingestion in production.
- Create the file and fix ownership **before** starting Logstash:
```bash
touch /var/log/<service>/lab.<ext>
chown logstash:logstash /var/log/<service>/lab.<ext>
chmod 644 /var/log/<service>/lab.<ext>
chmod 755 /var/log/<service>/
```

**3.4 Check `pipelines.yml`** has an entry pointing at your new lab directory:

```yaml
- pipeline.id: <name>-lab
  path.config: "/etc/logstash/lab-<name>/*.conf"
  pipeline.workers: 1
```

**3.5 Check for duplicate/stray configs before starting.** If a similarly-named file already exists elsewhere (commonly `/etc/logstash/conf.d/`, which belongs to the `main` pipeline), it will run *in parallel* with your lab pipeline, silently double-processing the same input file and writing to a different index than you're checking. Confirm:

```bash
grep -r "<name>-lab" /etc/logstash/conf.d/ 2>/dev/null
curl -s http://localhost:9600/_node/pipelines?pretty | grep -A5 '"main"'
```

If `main`'s `pipeline.sources` lists anything with your lab pipeline's name, remove it — `main` should stay production-only.

**3.6 Never leave credentials as placeholders.** If the copied config has a password variable (Ansible template var, keystore reference), swap it for the real value used elsewhere on this box — check a known-working lab pipeline (e.g. `medianova-lab.conf`) for the correct credential rather than guessing.

**3.7 Start clean:**

```bash
sudo systemctl restart logstash
sleep 30
sudo systemctl status logstash
```

Confirm `active (running)`, no repeated `401`/connection warnings in the log. If it shows `deactivating (stop-sigterm)` for more than ~30s, don't wait it out — it's stuck (usually on a bad-credential retry loop):

```bash
sudo systemctl kill -s SIGKILL logstash
sleep 3
ps aux | grep logstash   # confirm nothing lingers
```
Fix the actual cause, then start once, cleanly, and leave it alone while it boots — don't run other commands mid-startup.

---

## Phase 4 — Inject and verify

**4.1 Build test payloads matching production's raw (pre-filter) field names** — not the post-`rename` ECS names. If the pipeline's filter renames `request_uri` → `[url][original]`, your injected line needs `request_uri`, not `url.original`.

**4.2 Inject:**

```bash
# UDP:
echo '<json payload>' | nc -u -w1 127.0.0.1 <port>

# File:
echo '<json payload>' | sudo tee -a /var/log/<service>/lab.<ext>
```

**4.3 Verify at three levels, in order — don't skip to the last one:**

```bash
# 1. Did Logstash log any errors?
sudo journalctl -u logstash --since "1 minute ago" --no-pager | grep -iE "error|warn|exception"

# 2. Did the event reach the filter stage? (bypass ES, check local debug output if configured)
tail -5 /var/log/logstash/<name>-lab-debug.json
```
```json
// 3. Did it land in Elasticsearch with the field change correct?
GET <name>-lab/_search
{ "size": 5, "sort": [{ "@timestamp": "desc" }] }
```

**4.4 Test both the positive and negative case:**
- A payload that **should** trigger the change (confirm the new/modified field populates correctly)
- A payload that **shouldn't** (confirm no unexpected field, no spurious `_grokparsefailure` tag — set `tag_on_failure => []` on any grok that's expected to legitimately not match every event)

**4.5 Test edge cases relevant to the specific change** — e.g. for a new extraction pattern: case sensitivity, values only present in an unexpected field (e.g. query string vs. path), boundary/overlap cases, very long or very short values.

---

## Before promoting to production

- [ ] All positive and negative test cases pass
- [ ] No unintended changes elsewhere in the filter — diff the lab config against the original production file; only your intended change should differ
- [ ] Field type in the test index matches what you'd want in production (check `_mapping`, not just that data landed)
- [ ] Clean up test data before re-running: `POST <name>-lab/_delete_by_query { "query": { "match_all": {} } }`
- [ ] Rename any `-lab`-suffixed internal IDs (e.g. grok `id => "..."`) back to production-appropriate names before merging
- [ ] Raise the GitLab MR with the exact diff, referencing what was validated

---

## Known pitfalls (hit and fixed in prior sessions — don't re-discover these)

| Symptom | Cause | Fix |
|---|---|---|
| `GET <index>/_mapping` returns `{}` | Template has no explicit `priority`, lost to a higher-priority template | Set `priority` explicitly (500+) |
| `cannot create index... matches template [logs]... data streams only` | Index name matches `logs-*-*` | Rename to avoid that pattern, or add `data_stream: {}` and a competing priority |
| Repeated `401` in logs | Placeholder/wrong password left in config | Check a known-working lab config for the real credential |
| Logstash stuck `deactivating` for minutes | Bad credentials + in-flight events can't flush | `SIGKILL`, confirm dead, fix credentials, restart clean |
| Test data appears in the wrong index | Duplicate pipeline config in `conf.d` running in parallel | Check `main` pipeline's `pipeline.sources`, remove stray file |
| CSV/exported values silently read as 0 for large numbers | Thousand-separator commas not stripped before `pd.to_numeric` | Strip commas before parsing (if post-processing exports) |
| Field never populates despite correct grok | Test payload used the wrong field name (post-rename instead of pre-rename) | Match production's raw input field names exactly |
