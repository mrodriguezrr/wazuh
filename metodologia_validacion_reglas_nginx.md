# Metodología de Validación de Reglas de Detección — NGINX

**Techpro SOC — Ingeniería de Detección**
**Plataforma:** Elastic Security (SIEM) · Logstash · nginx
**Alcance:** Reglas de detección sobre logs de acceso de nginx (`logs-nginx.access-*`)

---

## 1. Propósito

Este documento describe el proceso end-to-end que seguimos para validar reglas de detección de nginx antes de darlas por confiables. El objetivo es doble:

1. **Validar la lógica** de la regla — que la query realmente detecte lo que dice detectar, sin bugs silenciosos de sintaxis o de campos.
2. **Validar la funcionalidad** en un laboratorio controlado — que la regla dispare de punta a punta cuando el tráfico que debe detectar atraviesa toda la cadena real (nginx → Logstash → Elastic → alerta).

El principio rector: **que una regla "corra sin errores" no significa que detecte bien.** Una regla puede ejecutarse sin fallar y aun así no disparar nunca, por un campo inexistente, un patrón mal escrito o un data view mal apuntado. La validación existe para cerrar esa brecha entre "no falla" y "funciona".

---

## 2. Principios generales

- **Validar antes de aplicar.** Nunca se modifica una regla de producción sin haber verificado el cambio primero. La documentación oficial o el conocimiento previo pueden estar desactualizados; se verifica contra el comportamiento real del cluster.
- **Ir paso a paso.** Cada etapa se confirma antes de pasar a la siguiente. No se avanza con supuestos; se avanza con evidencia (la salida de una query, el conteo de un bucket, la alerta generada).
- **Aislar la causa.** Cuando algo no funciona, se separa el problema en capas (¿es la query?, ¿el pipeline?, ¿el data view?, ¿el timing?) y se prueba una capa a la vez.
- **Usar datos atribuibles.** Cada prueba usa una IP de rango reservado (TEST-NET) distinta, para que el resultado sea 100% atribuible a esa prueba y no se contamine con tráfico previo.

---

## 3. Fase 1 — Revisión de la lógica de la regla

Antes de tocar el laboratorio, se revisa la definición exportada de la regla (NDJSON) y se evalúan los siguientes puntos.

### 3.1 Tipo de regla y semántica

Identificar el tipo (`threshold`, `eql`, `query`, etc.), porque cada uno tiene reglas de validación distintas:

- **Threshold:** revisar los campos de agrupación (`threshold.field`), el umbral (`value`) y la cardinalidad (`cardinality`). Un documento solo cuenta si tiene **todos** los campos de agrupación poblados; si alguno falta, el documento se descarta y la regla puede no disparar nunca.
- **EQL:** revisar los patrones de match sobre campos individuales y los operadores. Un solo documento que matchee dispara la alerta.

### 3.2 Verificación de campos

Confirmar que los campos que la regla evalúa **existen y están poblados** en los datos reales, y con el tipo correcto:

- Campos de IP (`source.ip`, `destination.ip`) deben ser tipo `ip` — los wildcards de octeto (`10.*.*.*`) **no funcionan** sobre campos `ip`; se debe usar notación CIDR (`"10.0.0.0/8"`) o la función `cidrmatch()` en EQL.
- El campo de host/vhost en logs HTTP normalmente vive en `url.domain` o `destination.domain` según cómo lo pueble el pipeline — verificar cuál, porque agrupar o excluir por un campo vacío rompe la regla en silencio.
- Verificar el mapeo real con:
  ```
  GET <indice>/_mapping/field/<campo1>,<campo2>
  ```

### 3.3 Revisión de patrones (wildcards)

Para reglas con patrones de texto, revisar cada patrón con cuidado. Error típico encontrado: un patrón como `"*exec*("` exige que la URL **termine** en `(`, por lo que no matchea un ataque real como `exec(xp_cmdshell)`. La corrección es `"*exec(*"` (wildcard después del carácter). Se revisa patrón por patrón buscando esta inconsistencia.

### 3.4 Revisión de exclusiones (allowlists)

- Verificar que los patrones de exclusión coincidan con el naming real. Ejemplo: excluir `*-qa.*` no excluye dominios `operationspanel.qa.jetu.cr` porque el patrón real es `.qa.`, no `-qa.`.
- Los allowlists de IP embebidos en la query son deuda técnica; se recomienda moverlos a **exception lists** o **value lists** para que se mantengan sin editar la query.
- Evaluar exclusiones de códigos de estado: excluir 403/404 puede ocultar intentos de ataque bloqueados que quizás se quieran ver.

### 3.5 Data view

Confirmar a qué `data_view_id` apunta la regla y que ese data view cubra el índice esperado. Un data view mal apuntado hace que la regla no vea los datos por más que la query sea perfecta.

### 3.6 Ventana temporal y umbral

Revisar `interval`, `from` y `to`. Confirmar que el solape sea razonable (evitar gaps) y que el umbral esté calibrado sobre el tráfico real, no en un valor arbitrariamente alto que solo detecte catástrofes.

### 3.7 Higiene

Revisar (sin ser bloqueante): tags, mapeo MITRE ATT&CK, descripción explicativa, `actions` (notificación a SOAR/casos), y guía de investigación. Estos elevan la calidad operativa aunque no afecten el disparo.

---

## 4. Fase 2 — Preparación del laboratorio

El laboratorio replica la cadena de ingesta real sin tocar producción.

### 4.1 Componentes

- **Índice de laboratorio dedicado** (ej. `nginx-access-lab`) con el mapeo correcto de los campos que la regla evalúa. Verificar antes de inyectar:
  ```
  GET nginx-access-lab/_mapping/field/@timestamp,source.ip,destination.domain,http.response.status_code
  ```
  `@timestamp` debe ser `date`, `source.ip` debe ser `ip`, etc. Un `@timestamp` mapeado como `text` impide que la regla ordene/filtre por tiempo y nunca dispara.
- **Regla duplicada** apuntando al data view del índice de laboratorio (no al de producción). Confirmar el `data_view_id` de la copia:
  ```
  GET kbn:/api/detection_engine/rules?rule_id=<RULE_ID_DUPLICADA>
  ```
- **Servidor nginx de pruebas** (puerto dedicado) con el `log_format` JSON que el pipeline espera.
- **Pipeline de Logstash de laboratorio** que aplique el mismo `filter` de producción y escriba al índice de laboratorio.

### 4.2 Umbral reducido

Para agilizar, la regla duplicada usa un umbral bajo (ej. `10` en vez de `150`). Esto reduce el volumen de tráfico de prueba necesario sin cambiar la lógica de detección.

---

## 5. Fase 3 — Validación por etapas

Se valida en tres niveles, de menor a mayor superficie de error. Si algo falla, se sabe exactamente en qué capa.

### Etapa 1 — Inyección directa a Elastic (aísla la regla)

Confirma que **la regla y su query funcionan**, aislado de Logstash y nginx. Se escriben documentos ECS ya formados directamente al índice con `_bulk`.

**Consideraciones críticas:**

- **Campos de agrupación:** para reglas threshold, todos los documentos deben compartir el mismo valor en los campos de agrupación (misma IP + mismo dominio) para caer en un solo bucket y superar el umbral.
- **Cardinalidad:** si la regla exige cardinalidad (ej. 50 paths distintos), los documentos deben variar ese campo lo suficiente.
- **Timestamp fresco:** el `@timestamp` debe caer dentro de la ventana de la regla (`from`). Se genera al momento con `date -u +"%Y-%m-%dT%H:%M:%S.000Z"`.
- **Formato NDJSON:** cada acción y documento en una línea, con salto de línea final. Se usa `--data-binary @archivo` (no `-d`, que colapsa saltos de línea).

**Carga de la credencial en la sesión (antes de cualquier `curl`):**

```bash
read -rs ES_PASS && export ES_PASS
echo "[${ES_PASS}]"   # confirmar que NO muestra [] (variable vacía)
```

Nota: `read -rs` es silencioso — la terminal no muestra nada mientras se escribe la clave. Se escribe a ciegas y se da Enter.

**Opción A — Generación con loop y `printf` (a prueba de pegado):**

```bash
TS="$(date -u +%Y-%m-%dT%H:%M:%S.000Z)"
SRC_IP="203.0.113.10"
> /tmp/lab_bulk.ndjson
for i in $(seq 1 12); do
  printf '%s\n' '{"index":{}}' >> /tmp/lab_bulk.ndjson
  printf '%s\n' '{"@timestamp":"'"${TS}"'","http":{"request":{"method":"GET"},"response":{"status_code":429}},"source":{"ip":"'"${SRC_IP}"'"},"destination":{"domain":"test.lab.local"},"url":{"path":"/api/test"},"user_agent":{"original":"lab-test-agent"},"event":{"dataset":"nginx.access"}}' >> /tmp/lab_bulk.ndjson
done
wc -l /tmp/lab_bulk.ndjson   # debe dar 24 (12 docs x 2 líneas)
head -2 /tmp/lab_bulk.ndjson # confirmar que @timestamp muestra fecha real, no ${TS}
```

**Opción B — Generación con heredoc EOF:**

El `@timestamp` debe ser fresco, pero un heredoc es texto estático. Se resuelve generando el timestamp en una variable y usando `<<EOF` **sin comillas** (con comillas `<<'EOF'` NO expande variables y el campo queda como el literal `${TS}`, que Elastic rechaza).

```bash
TS="$(date -u +%Y-%m-%dT%H:%M:%S.000Z)"
SRC_IP="203.0.113.10"
DOMAIN="test.lab.local"

cat > /tmp/lab_bulk.ndjson <<EOF
{"index":{}}
{"@timestamp":"${TS}","http":{"response":{"status_code":429},"request":{"method":"GET"}},"source":{"ip":"${SRC_IP}"},"destination":{"domain":"${DOMAIN}"},"url":{"path":"/api/test"},"user_agent":{"original":"lab-test-agent"},"event":{"dataset":"nginx.access"}}
{"index":{}}
{"@timestamp":"${TS}","http":{"response":{"status_code":429},"request":{"method":"GET"}},"source":{"ip":"${SRC_IP}"},"destination":{"domain":"${DOMAIN}"},"url":{"path":"/api/test"},"user_agent":{"original":"lab-test-agent"},"event":{"dataset":"nginx.access"}}
EOF
# ... repetir el par acción+documento hasta tener la cantidad deseada ...

wc -l /tmp/lab_bulk.ndjson   # debe dar el doble del número de docs
head -2 /tmp/lab_bulk.ndjson # confirmar fecha real expandida en @timestamp
```

> **Nota sobre el action del bulk:** para un **índice normal** (como `nginx-access-lab`) se usa `{"index":{}}`. Para un **data stream** se debe usar `{"create":{}}` (los data streams solo aceptan append).

**Inserción con `--data-binary`:**

Se usa `--data-binary @archivo` (la `@` hace que curl lea el archivo respetando los saltos de línea; `-d` los colapsa y rompe el NDJSON).

```bash
curl -sk -u "secan_lecko:${ES_PASS}" \
  -H 'Content-Type: application/x-ndjson' \
  -X POST "https://thunder.arborys.net:5645/nginx-access-lab/_bulk" \
  --data-binary @/tmp/lab_bulk.ndjson
```

Confirmar `"errors":false`. Si aparece `KeyError: 'errors'` al parsear con python, es que Elastic devolvió un error (típicamente 401) en vez del resultado — ver salida cruda con `head -c 400`.

**Verificación de agrupación (antes de disparar):**

```
POST nginx-access-lab/_refresh

GET nginx-access-lab/_search
{
  "size": 0,
  "query": { "bool": { "filter": [
    { "range": { "@timestamp": { "gte": "now-11m" } } },
    { "term": { "source.ip": "203.0.113.10" } },
    { "term": { "destination.domain": "test.lab.local" } }
  ] } },
  "aggs": { "par": { "multi_terms": { "terms": [ {"field":"source.ip"}, {"field":"destination.domain"} ] } } }
}
```

Verificar: `hits.total.value` igual al número inyectado, y un solo bucket con el `doc_count` esperado. `multi_terms` solo devuelve buckets donde **ambos** campos existen — exactamente lo que exige el threshold.

**Disparo:** Security → Rules → regla duplicada → Run. Verificar la alerta en Security → Alerts, **filtrando por la IP** (`source.ip : "203.0.113.10"`) para no confundirse con alertas previas.

### Etapa 2 — Vía Logstash (valida el pipeline)

Confirma que el **pipeline transforma correctamente** los campos crudos de nginx al ECS que la regla espera (los `rename`, `convert`, `mutate`).

Se envían los **nombres crudos de nginx** (pre-rename: `http_x_real_ip`, `server_name`, `status`, `request_method`, etc.) y se deja que el pipeline los procese. Se puede hacer con `input file` (escribiendo a un `.access.log`) o corriendo Logstash puntualmente con `input stdin`.

**Generación de las líneas crudas de nginx (pre-rename):**

```bash
TS_NGINX="$(date -u +%Y-%m-%dT%H:%M:%S+00:00)"
> /tmp/lab_lines.json
for i in $(seq 1 12); do
  printf '%s\n' '{"time":"'"${TS_NGINX}"'","status":429,"request_method":"GET","http_x_real_ip":"203.0.113.10","remote_addr":"10.0.0.5","server_name":"test.lab.local","server_addr":"127.0.0.1","request_uri":"/api/test","uri":"/api/test","scheme":"https","server_protocol":"HTTP/1.1","http_user_agent":"lab-test-agent","request_id":"lab-'"${i}"'","body_bytes_sent":120,"bytes_sent":340,"request_time":0.012}' >> /tmp/lab_lines.json
done
wc -l /tmp/lab_lines.json   # debe dar 12
```

Estos campos mapean exactamente a lo que el pipeline renombra: `http_x_real_ip → source.ip`, `server_name → destination.domain`, `status → http.response.status_code`, `request_method → http.request.method`.

**Config de laboratorio para Logstash puntual (`input stdin`):**

Se crea un `.conf` con `input stdin`, el mismo `filter` de producción, y `output` al índice de laboratorio (índice normal, no data stream, para que la regla duplicada lo vea). Se quitan los bloques `geoip` si las DBs MaxMind no están en el servidor de laboratorio.

```
input { stdin { codec => json { charset => "ISO-8859-1" } type => "sec-nginx-access" } }

filter {
  if [type] == "sec-nginx-access" {
    mutate { convert => { "status" => "integer" "body_bytes_sent" => "integer" "bytes_sent" => "integer" "request_time" => "float" } }
    if [http_x_real_ip] == "" { mutate { remove_field => ["http_x_real_ip"] } }
    mutate {
      rename => {
        "http_x_real_ip"   => "[source][ip]"
        "remote_addr"      => "[network][forwarded_ip]"
        "request_method"   => "[http][request][method]"
        "request_uri"      => "[url][original]"
        "uri"              => "[url][path]"
        "server_protocol"  => "[http][version]"
        "http_user_agent"  => "[user_agent][original]"
        "request_id"       => "[event][id]"
        "scheme"           => "[url][scheme]"
        "status"           => "[http][response][status_code]"
        "body_bytes_sent"  => "[http][response][bytes]"
        "bytes_sent"       => "[destination][bytes]"
        "server_name"      => "[destination][domain]"
        "server_addr"      => "[destination][ip]"
        "request_time"     => "[event][duration]"
        "time"             => "[event][created]"
      }
    }
    mutate {
      remove_field => ["msec","path","@version","host"]
      add_field => { "[observer][hostname]" => "seclab" "[event][dataset]" => "nginx.access" }
    }
  }
}

output {
  if [type] == "sec-nginx-access" {
    elasticsearch {
      hosts => ["https://thunder.arborys.net:5645"]
      user => "${ES_USER}"
      password => "${ES_PASS}"
      index => "nginx-access-lab"
      ssl_certificate_verification => false
    }
    stdout { codec => rubydebug }
  }
}
```

**Comando de Logstash puntual que levanta el pipeline y corre los logs:**

Toma las líneas crudas por pipe, las pasa por el pipeline, y sale solo al terminar de leer stdin. Requiere un `--path.data` propio para no chocar con el del servicio.

```bash
export ES_USER="secan_lecko"
# ES_PASS ya exportada de antes

cat /tmp/lab_lines.json | /usr/share/logstash/bin/logstash \
  -f /tmp/lab_stdin.conf \
  --path.data /tmp/ls-lab-data \
  2>&1 | tee /tmp/ls-run.log | grep -iE "Could not index|status=>400|Pipeline started" | head -20
```

Qué esperar: `Pipeline started` y **ningún** `Could not index` / `status=>400`. La JVM tarda ~30-40s en arrancar. Con `input stdin`, al terminar de leer el pipe Logstash sale solo (no requiere Ctrl-C). En pantalla se ven los bloques `rubydebug` con el documento transformado — confirmación visual de que `[source][ip]` y `[destination][domain]` salieron bien antes de mirar Elastic.

**Consideración crítica encontrada — campo `host`:** Logstash agrega por defecto un campo `host` (string) al usar `input stdin`. Si el índice ya tiene `host` mapeado como objeto (ECS), el documento es rechazado con `document_parsing_exception`. La solución es agregar `host` al `remove_field` del filter:
```
remove_field => ["msec","path","@version","host"]
```

Corrección rápida sobre un `.conf` existente:
```bash
sed -i 's/remove_field => \["msec","path","@version"\]/remove_field => ["msec","path","@version","host"]/' /tmp/lab_stdin.conf
```

**Verificación:** confirmar que el documento llegó con los campos ECS y que pasó por el pipeline (los docs de Logstash traen `event.created`, `event.id`, `observer.hostname` que los inyectados a mano no tienen):

```
GET nginx-access-lab/_search
{
  "size": 1,
  "query": { "bool": { "filter": [
    { "term": { "source.ip": "<IP>" } },
    { "exists": { "field": "event.created" } }
  ] } },
  "sort": [ { "@timestamp": "desc" } ]
}
```

El filtro `exists: event.created` aísla los documentos que vinieron por Logstash de los inyectados directamente en la Etapa 1.

### Etapa 3 — End-to-end desde nginx (valida la cadena completa)

Confirma que **nginx genera el evento real**, que Logstash lo levanta y que llega a Elastic hasta disparar la regla. Es la validación de punta a punta.

Se genera tráfico real que produzca el evento buscado. Ejemplo para 429 (rate limiting).

**Zona de rate limit** (contexto `http`, en su propio archivo en `conf.d`):

```bash
sudo tee /etc/nginx/conf.d/lab-ratelimit.conf >/dev/null <<'EOF'
limit_req_zone $binary_remote_addr zone=lab_dos_zone:1m rate=1r/s;
EOF
```

**Server block de prueba** (puerto dedicado, sirviendo un archivo real):

```bash
echo "ok" | sudo tee /var/www/html/labtest.txt >/dev/null

sudo tee /etc/nginx/sites-available/lab-dos.conf >/dev/null <<'EOF'
server {
    listen 8888;
    server_name test.lab.local;
    access_log /var/log/nginx/lab.access.log json_combined;
    root /var/www/html;
    location / {
        limit_req zone=lab_dos_zone burst=1 nodelay;
        limit_req_status 429;
        try_files /labtest.txt =404;
    }
}
EOF
sudo ln -sf /etc/nginx/sites-available/lab-dos.conf /etc/nginx/sites-enabled/lab-dos.conf
```

**Aplicar la config** (usar `restart`, no `reload` — ver consideraciones abajo):

```bash
sudo nginx -t && sudo systemctl restart nginx
```

**Loop de curl para generar los 429** (en una sola línea para evitar errores de pegado):

```bash
for i in $(seq 1 25); do curl -s -o /dev/null -w "%{http_code} " -H "X-Real-IP: 198.51.100.20" http://127.0.0.1:8888/; done; echo
```

Se espera `200 200 429 429 429 ...`. El header `X-Real-IP` lleva la IP de prueba (el pipeline la mapea a `source.ip`). Confirmar los 429 escritos en el log:

```bash
grep -c '"status":"429"' /var/log/nginx/lab.access.log   # debe dar >= 10
```

**Manejo del servicio Logstash en modo tail:**

Para la Etapa 3, Logstash corre como **servicio** (no puntual) para leer el `lab.access.log` en modo tail. Si el `sincedb` tiene el archivo registrado de intentos previos, se resetea antes de arrancar:

```bash
sudo rm -f /tmp/logstash-lab-sincedb   # rm, NO truncate (ver 6.6)
sudo systemctl start logstash
```

Esperar ~40s a que cargue. Confirmar que arrancó sin errores de indexación:

```bash
sudo journalctl -u logstash --since "1 min ago" --no-pager | grep -iE "Pipeline started|EACCES|document_parsing|Could not index"
```

**Puntos críticos de nginx (todos encontrados en la práctica):**

- **`limit_req_status 429;` obligatorio:** por defecto nginx devuelve **503** al exceder el límite; sin esta directiva la regla (que busca 429) no ve nada.
- **`limit_req` no aplica a `return` directos:** el request debe atravesar la fase de contenido (`try_files` sirviendo un archivo), no un `return 200`. Con `return`, nginx responde antes de la fase donde actúa `limit_req` y el límite nunca se evalúa.
- **Redefinir la zona requiere `restart`, no `reload`:** cambiar la clave de un `limit_req_zone` (ej. de `$http_x_real_ip` a `$binary_remote_addr`) con un reload deja un error `[emerg]` en el error.log y la config vieja sigue corriendo — todos los requests pasan en 200. Solo `restart` recarga las zonas.
- **Rates en `r/s`, no `r/m`:** con rates por minuto el comportamiento del token bucket es poco predecible en pruebas rápidas; usar `r/s` con `burst` chico.
- **Header `Host` correcto:** si hay varios server blocks en el mismo puerto, el matcheo de `server_name` requiere el header `Host` adecuado.

**Diagnóstico del rate limit:** si todos los requests pasan en 200, revisar el error.log (`sudo tail -5 /var/log/nginx/error.log`) — un `[emerg]` de conflicto de clave o la ausencia de eventos `limiting requests` indica que el límite no se está aplicando.

**Verificación:** confirmar los eventos en el log de nginx, luego en Elastic (filtrando por la IP de esta etapa), y disparar la regla **de inmediato** (la ventana de la regla vence rápido).

---

## 6. Problemas recurrentes y su diagnóstico

Estos son los puntos de falla que aparecen con más frecuencia. Ante un "no dispara", se revisan en este orden.

### 6.1 Autenticación (401)

Síntoma típico: un script de python que parsea la respuesta del bulk falla con `KeyError: 'errors'`. Causa: Elastic devolvió un `security_exception` en vez del resultado del bulk. La variable de entorno con la contraseña se perdió de la sesión. Verificar con:
```bash
echo "[${ES_PASS}]"   # si muestra [], la variable está vacía
```
Nota: `read -rs` es silencioso (no muestra nada mientras se escribe); es fácil dar Enter en vacío creyendo que se colgó.

### 6.2 Data view mal apuntado

La regla duplicada heredó el `data_view_id` de producción y no ve el índice de laboratorio. Es la causa más común de "no dispara" con datos perfectos. Se verifica y corrige apuntando la copia al data view de laboratorio.

### 6.3 Ventana temporal vencida

Los documentos llegaron a Elastic pero su `@timestamp` cayó fuera de la ventana de la regla (`from`) por el tiempo transcurrido entre inyectar y disparar. Se verifica con un `_count` acotado a la ventana (ej. `now-11m`). Si da 0, regenerar tráfico fresco y disparar **de inmediato**. La secuencia correcta es: generar → confirmar en ventana → disparar, sin demoras.

### 6.4 Mapeo incorrecto de `@timestamp`

Si `@timestamp` quedó mapeado como `text` (típico en índices auto-mapeados sin template), la regla no puede ordenar/filtrar por tiempo y falla la ejecución. Se verifica el mapeo antes de inyectar.

### 6.5 Rechazo por conflicto de tipo (`document_parsing_exception`)

Un campo llega con un tipo distinto al mapeado (ej. `host` string vs objeto). Los documentos se rechazan con status 400. Se lee el error del output del bulk/Logstash, que indica el campo exacto en conflicto.

### 6.6 Descubrimiento de archivos en Logstash (sincedb)

Con `input file`, el `sincedb` registra hasta dónde leyó cada archivo. Un archivo ya "visto" no se reprocesa. Además, un `sincedb` tocado con `sudo` queda como root y el servicio (que corre como `logstash`) no puede escribirlo — falla con `EACCES` en bucle. Regla: usar `sudo rm` (no `sudo truncate`) para que Logstash lo recree con el owner correcto.

### 6.7 Confusión al leer alertas

Con varias pruebas usando distintas IPs, la lista de alertas mezcla resultados. Siempre filtrar por la IP de la prueba actual (`source.ip : "<IP>"`) en lugar de buscar a ojo, para confirmar que la alerta corresponde al tráfico correcto.

---

## 7. Buenas prácticas transversales

- **IPs de rango reservado y distintas por etapa:** usar TEST-NET (`203.0.113.0/24`, `198.51.100.0/24`, `192.0.2.0/24`) — no enrutan y no se confunden con tráfico real. Una IP distinta por etapa mantiene el conteo atribuible.
- **Verificar antes de disparar:** nunca disparar la regla sin haber confirmado con una query que los datos cumplen las condiciones (conteo y cardinalidad en ventana).
- **Confirmar el fix con datos reales:** cuando se corrige un patrón, demostrar el antes/después con un `_count` sobre el mismo documento (ej. patrón roto → 0, patrón corregido → 1). No basta con razonar el fix; se prueba.
- **Aplicar el fix también a producción:** la regla duplicada es solo para el laboratorio. Recordar trasladar el cambio validado a la regla de producción.
- **No confundir "corre sin errores" con "detecta bien":** una regla puede ejecutarse limpiamente y aun así tener huecos de cobertura. El laboratorio existe para encontrarlos.

---

## 8. Resumen del flujo

1. **Revisar la lógica** de la regla (tipo, campos, patrones, exclusiones, data view, ventana).
2. **Preparar el laboratorio** (índice con mapeo correcto, regla duplicada apuntada al data view de lab, umbral reducido).
3. **Etapa 1 — Inyección directa:** validar que la query y la regla funcionan.
4. **Etapa 2 — Vía Logstash:** validar que el pipeline transforma bien a ECS.
5. **Etapa 3 — End-to-end desde nginx:** validar la cadena completa.
6. **Confirmar cada disparo** filtrando por la IP de la prueba.
7. **Trasladar los fixes validados** a la regla de producción.

En cada etapa: generar → verificar con query → disparar → confirmar la alerta. Nunca avanzar sin evidencia.
