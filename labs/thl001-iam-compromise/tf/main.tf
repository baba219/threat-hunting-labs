resource "google_compute_firewall" "allow_http" {
  name      = "allow-http"
  network   = "default"
  direction = "INGRESS"

  allow {
    protocol = "tcp"
    ports    = ["80"]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["lab-elk"]
}

resource "google_compute_instance" "lab_elk" {
  name         = "lab-elk"
  machine_type = "e2-standard-4"
  zone         = var.gcp_zone
  tags         = ["lab-elk"]

  boot_disk {
    initialize_params {
      image = "ubuntu-os-cloud/ubuntu-2204-lts"
      size  = 50
      type  = "pd-balanced"
    }
  }

  network_interface {
    network = "default"
    access_config {}
  }

  metadata_startup_script = <<-EOF
#!/usr/bin/env bash
set -euo pipefail

exec > >(tee -a /var/log/startup-script.log) 2>&1
echo "[+] Startup script begin: $(date -Is)"

LAB_USER="${var.lab_username}"
LAB_PASS="${var.lab_password}"

export DEBIAN_FRONTEND=noninteractive

echo "[+] Installing dependencies"
apt-get update -y
apt-get install -y ca-certificates curl gnupg apache2-utils jq python3

echo "[+] Installing Docker Engine"
install -m 0755 -d /etc/apt/keyrings

curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg

cat >/etc/apt/sources.list.d/docker.list <<'DOCKERLIST'
deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu jammy stable
DOCKERLIST

apt-get update -y
apt-get install -y docker-ce docker-ce-cli containerd.io
systemctl enable --now docker

echo "[+] Installing docker-compose v1"
curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose
/usr/local/bin/docker-compose version || true

echo "[+] Preparing /opt/lab"
rm -rf /opt/lab
mkdir -p /opt/lab/{nginx,dataset,bulk,scripts}
chmod -R 777 /opt/lab/dataset
cd /opt/lab

echo "[+] Creating htpasswd file"
htpasswd -bc /opt/lab/nginx/.htpasswd "$LAB_USER" "$LAB_PASS"

echo "[+] Writing nginx.conf"
tee /opt/lab/nginx/nginx.conf >/dev/null <<'NGINX'
events {}
http {
  upstream kibana_upstream { server kibana:5601; }

  server {
    listen 80;
    server_name _;

    auth_basic "Threat Hunting Lab";
    auth_basic_user_file /etc/nginx/.htpasswd;

    location / {
      proxy_pass http://kibana_upstream;
      proxy_set_header Host $host;
      proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
      proxy_set_header X-Forwarded-Proto $scheme;
    }
  }
}
NGINX

echo "[+] Writing docker-compose.yml"
tee /opt/lab/docker-compose.yml >/dev/null <<'YAML'
version: "3.8"
services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.13.4
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
      - ES_JAVA_OPTS=-Xms2g -Xmx2g
    volumes:
      - esdata:/usr/share/elasticsearch/data
    networks: [labnet]

  kibana:
    image: docker.elastic.co/kibana/kibana:8.13.4
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
    depends_on: [elasticsearch]
    networks: [labnet]

  nginx:
    image: nginx:1.27-alpine
    depends_on: [kibana]
    ports:
      - "80:80"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./nginx/.htpasswd:/etc/nginx/.htpasswd:ro
    networks: [labnet]

networks:
  labnet:

volumes:
  esdata:
YAML

echo "[+] Starting the stack"
docker-compose up -d
docker ps

echo "[+] Writing dataset JSONL files into /opt/lab/dataset"

tee /opt/lab/dataset/auth-logs.jsonl >/dev/null <<'JSONL'
{"@timestamp":"2025-12-21T18:05:12Z","event":{"action":"user_login","outcome":"success"},"user":{"email":"alice@corp.com"},"geo":{"country_name":"Canada","city_name":"Montreal"},"source":{"ip":"24.48.123.11"}}
{"@timestamp":"2025-12-21T18:12:44Z","event":{"action":"user_login","outcome":"success"},"user":{"email":"bob@corp.com"},"geo":{"country_name":"Canada","city_name":"Toronto"},"source":{"ip":"99.230.11.7"}}
{"@timestamp":"2025-12-21T18:20:01Z","event":{"action":"user_login","outcome":"success"},"user":{"email":"bob@corp.com"},"geo":{"country_name":"France","city_name":"Paris"},"source":{"ip":"51.158.91.22"}}
{"@timestamp":"2025-12-21T18:22:39Z","event":{"action":"user_login","outcome":"success"},"user":{"email":"bob@corp.com"},"geo":{"country_name":"Russia","city_name":"Moscow"},"source":{"ip":"91.198.174.192"}}
{"@timestamp":"2025-12-21T18:30:18Z","event":{"action":"user_login","outcome":"failure"},"user":{"email":"service-account@corp.com"},"geo":{"country_name":"United States","city_name":"Ashburn"},"source":{"ip":"3.221.14.9"}}
{"@timestamp":"2025-12-21T18:45:55Z","event":{"action":"user_login","outcome":"success"},"user":{"email":"charles@corp.com"},"geo":{"country_name":"Canada","city_name":"Quebec"},"source":{"ip":"142.112.88.9"}}
{"@timestamp":"2025-12-21T18:52:11Z","event":{"action":"user_login","outcome":"success"},"user":{"email":"bob@corp.com"},"geo":{"country_name":"China","city_name":"Beijing"},"source":{"ip":"101.89.33.17"}}
JSONL

tee /opt/lab/dataset/audit-logs.jsonl >/dev/null <<'JSONL'
{"@timestamp":"2025-12-21T17:40:11Z","event":{"action":"setIamPolicy"},"actor":{"email":"admin@corp.com"},"iam":{"role":"roles/viewer","change":"add"}}
{"@timestamp":"2025-12-21T17:45:28Z","event":{"action":"setIamPolicy"},"actor":{"email":"admin@corp.com"},"iam":{"role":"roles/logging.viewer","change":"add"}}
{"@timestamp":"2025-12-21T17:50:02Z","event":{"action":"setIamPolicy"},"actor":{"email":"admin@corp.com"},"iam":{"role":"roles/owner","change":"add"}}
{"@timestamp":"2025-12-21T18:01:19Z","event":{"action":"iam.policy.update"},"actor":{"email":"bob@corp.com"},"iam":{"role":"roles/editor","change":"add"}}
{"@timestamp":"2025-12-21T18:03:47Z","event":{"action":"iam.policy.update"},"actor":{"email":"bob@corp.com"},"iam":{"role":"roles/storage.admin","change":"add"}}
JSONL

tee /opt/lab/dataset/service-accounts.jsonl >/dev/null <<'JSONL'
{"@timestamp":"2025-12-21T18:10:45Z","event":{"action":"createServiceAccountKey"},"service":{"account":"backup-sa@corp.com","key_id":"key-11111"},"actor":{"email":"admin@corp.com"}}
{"@timestamp":"2025-12-21T18:15:09Z","event":{"action":"createServiceAccountKey"},"service":{"account":"backup-sa@corp.com","key_id":"key-22222"},"actor":{"email":"admin@corp.com"}}
{"@timestamp":"2025-12-21T18:21:31Z","event":{"action":"createServiceAccountKey"},"service":{"account":"backup-sa@corp.com","key_id":"key-99999"},"actor":{"email":"bob@corp.com"}}
JSONL

tee /opt/lab/dataset/iam-activity.jsonl >/dev/null <<'JSONL'
{"@timestamp":"2025-12-21T18:25:12Z","service":{"account":"backup-sa@corp.com","key_id":"key-99999"},"event":{"action":"token_generate"},"source":{"ip":"91.198.174.192"}}
{"@timestamp":"2025-12-21T18:26:55Z","service":{"account":"backup-sa@corp.com","key_id":"key-99999"},"event":{"action":"data_access"},"resource":{"type":"cloud_storage","name":"corp-finance-bucket"}}
{"@timestamp":"2025-12-21T18:29:41Z","service":{"account":"backup-sa@corp.com","key_id":"key-99999"},"event":{"action":"data_download"},"resource":{"type":"cloud_storage","name":"corp-hr-bucket"}}
JSONL

echo "[+] Creating make_bulk.py"
tee /opt/lab/scripts/make_bulk.py >/dev/null <<'PY'
import json
from pathlib import Path

def make_bulk(src: Path, dst: Path, index: str):
    dst.parent.mkdir(parents=True, exist_ok=True)
    with src.open("r", encoding="utf-8") as fin, dst.open("w", encoding="utf-8") as fout:
        for line in fin:
            line = line.strip()
            if not line:
                continue
            fout.write(json.dumps({"index": {"_index": index}}) + "\n")
            fout.write(line + "\n")

if __name__ == "__main__":
    mapping = [
        ("/opt/lab/dataset/auth-logs.jsonl",        "/opt/lab/bulk/auth-logs.bulk.ndjson",        "auth-logs-2025.12.21"),
        ("/opt/lab/dataset/audit-logs.jsonl",       "/opt/lab/bulk/audit-logs.bulk.ndjson",       "audit-logs-2025.12.21"),
        ("/opt/lab/dataset/service-accounts.jsonl", "/opt/lab/bulk/service-accounts.bulk.ndjson", "service-accounts-2025.12.21"),
        ("/opt/lab/dataset/iam-activity.jsonl",     "/opt/lab/bulk/iam-activity.bulk.ndjson",     "iam-activity-2025.12.21"),
    ]
    for src, dst, idx in mapping:
        make_bulk(Path(src), Path(dst), idx)
        print(f"Bulk ready: {dst} -> {idx}")
PY
chmod +x /opt/lab/scripts/make_bulk.py

echo "[+] Generating bulk NDJSON files"
python3 /opt/lab/scripts/make_bulk.py

echo "[+] Waiting for Elasticsearch readiness"
for i in {1..120}; do
  if docker exec -i lab-elasticsearch-1 curl -s http://localhost:9200 >/dev/null 2>&1; then
    echo "[+] Elasticsearch is ready"
    break
  fi
  sleep 2
done

echo "[+] Bulk importing into Elasticsearch"
for f in /opt/lab/bulk/*.ndjson; do
  echo "[+] Loading $f ..."
  err=$(docker exec -i lab-elasticsearch-1 \
    curl -s -H "Content-Type: application/x-ndjson" \
    -XPOST "http://localhost:9200/_bulk?refresh=true" \
    --data-binary @- < "$f" | jq -r '.errors')
  echo "[+] errors=$err"
  if [[ "$err" != "false" ]]; then
    echo "[!] Bulk import returned errors for $f"
    exit 20
  fi
done

echo "[+] Waiting for Kibana API through Nginx (http://localhost/api/status)"
for i in {1..180}; do
  code=$(curl -s -u "$LAB_USER:$LAB_PASS" -o /dev/null -w "%%{http_code}" http://localhost/api/status || true)
  if [[ "$code" == "200" ]]; then
    echo "[+] Kibana API is ready"
    break
  fi
  sleep 2
done

create_data_view() {
  local name="$1"
  local pattern="$2"

  resp=$(curl -s -u "$LAB_USER:$LAB_PASS" -w "\n%%{http_code}\n" \
    -X POST "http://localhost/api/data_views/data_view" \
    -H "Content-Type: application/json" \
    -H "kbn-xsrf: true" \
    -d "{
      \"data_view\": {
        \"title\": \"$${pattern}\",
        \"name\": \"$${name}\",
        \"timeFieldName\": \"@timestamp\"
      }
    }")

  body=$(echo "$${resp}" | sed '$d')
  http=$(echo "$${resp}" | tail -n 1)

  if [[ "$${http}" == "200" || "$${http}" == "201" ]]; then
    echo "[+] Data view created: $${name} -> $${pattern}"
    return 0
  fi

  if [[ "$${http}" == "409" ]]; then
    echo "[=] Data view already exists (409): $${name}"
    return 0
  fi

  if echo "$${body}" | jq -e '.message? // empty' >/dev/null 2>&1; then
    msg=$(echo "$${body}" | jq -r '.message')
    if echo "$${msg}" | grep -qi "already exists"; then
      echo "[=] Data view already exists: $${name}"
      return 0
    fi
  fi

  echo "[!] Failed to create data view $${name} ($${pattern}) HTTP=$${http}"
  echo "$${body}" | head -n 80
  return 1
}

create_data_view "auth-logs" "auth-logs-*"
create_data_view "audit-logs" "audit-logs-*"
create_data_view "service-accounts" "service-accounts-*"
create_data_view "iam-activity" "iam-activity-*"

echo "[+] Listing data views (name -> pattern)"
curl -s -u "$LAB_USER:$LAB_PASS" -H "kbn-xsrf: true" http://localhost/api/data_views \
  | jq -r '.data_view[] | "\(.name) -> \(.title)"' || true

echo "[+] Startup script completed successfully: $(date -Is)"
EOF
}
