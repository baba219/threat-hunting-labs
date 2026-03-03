# --- Dynamic lab credentials (Terraform-generated) ---
resource "random_id" "lab_user_suffix" {
  byte_length = 3 # 6 hex chars
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
  target_tags   = ["thl-iam-lab"]
}

resource "google_compute_instance" "thl_iam_lab" {
  name         = "thl-iam-lab"
  project      = var.gcp_project_id
  machine_type = "e2-standard-4"
  zone         = var.gcp_zone
  tags         = ["thl-iam-lab"]

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
rm -rf /opt/lab/{nginx,dataset,bulk,scripts} || true
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

###############################################################################
# Step 3 — SOC-real dataset generator (dynamic timestamps + lots of events)
###############################################################################
echo "[+] Generating SOC-real datasets (last 72h) and BULK NDJSON"

tee /opt/lab/scripts/generate_bulk.py >/dev/null <<'PY'
import json, random
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
    # random timestamp in [START, NOW]
    delta = NOW - START
    return START + timedelta(seconds=random.randint(0, int(delta.total_seconds())))

# ---- Entities (real SOC-like) ----
USERS = [
    {"email":"alice@corp.com","dept":"Finance","role":"user"},
    {"email":"bob@corp.com","dept":"IT","role":"poweruser"},
    {"email":"charles@corp.com","dept":"HR","role":"user"},
    {"email":"diane@corp.com","dept":"Sales","role":"user"},
    {"email":"eve@corp.com","dept":"Security","role":"admin"},
]
SERVICE_ACCTS = [
    {"account":"backup-sa@corp.com"},
    {"account":"ci-cd-sa@corp.com"},
    {"account":"reporting-sa@corp.com"},
]
HOSTS = ["WKSTN-019","WKSTN-044","WKSTN-101","SRV-APP-02","SRV-FILES-01"]
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6)",
    "Mozilla/5.0 (X11; Linux x86_64)",
    "curl/8.5.0",
]
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

# ---- AUTH logs (noise + signals) ----
auth_records = []

# Normal login noise
for _ in range(900):
    dt = rand_dt()
    u = random.choice(USERS)
    ip = random.choice(IPS_CA)
    doc = {
        "@timestamp": iso(dt),
        "event": {"dataset":"auth", "action":"user_login", "outcome":"success"},
        "user": {"email": u["email"], "department": u["dept"], "role": u["role"]},
        "source": {"ip": ip},
        "geo": geo(ip),
        "user_agent": {"original": random.choice(USER_AGENTS)},
        "device": {"name": random.choice(HOSTS)},
        "auth": {"method": random.choice(["password","mfa_push","webauthn"])}
    }
    auth_records.append((index_name("auth-logs", dt), doc))

# Brute force pattern on one user (failures then success)
victim = "diane@corp.com"
attack_ip = random.choice(IPS_WORLD)
base = NOW - timedelta(hours=6)
for i in range(25):
    dt = base + timedelta(minutes=i*2)
    outcome = "failure" if i < 24 else "success"
    doc = {
        "@timestamp": iso(dt),
        "event": {"dataset":"auth", "action":"user_login", "outcome": outcome},
        "user": {"email": victim, "department": "Sales", "role":"user"},
        "source": {"ip": attack_ip},
        "geo": geo(attack_ip),
        "user_agent": {"original": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
        "device": {"name": "VPN-GW-01"},
        "auth": {"method": "password"},
        "related": {"ip":[attack_ip]},
        "rule": {"name":"suspected_bruteforce_sequence"}
    }
    auth_records.append((index_name("auth-logs", dt), doc))

# Impossible travel for bob (CA -> RU -> CN within short window)
bob = "bob@corp.com"
dt1 = NOW - timedelta(hours=2, minutes=20)
dt2 = NOW - timedelta(hours=2, minutes=5)
dt3 = NOW - timedelta(hours=1, minutes=50)
for dt, ip in [(dt1, "99.230.11.7"), (dt2, "91.198.174.192"), (dt3, "101.89.33.17")]:
    doc = {
        "@timestamp": iso(dt),
        "event": {"dataset":"auth", "action":"user_login", "outcome":"success"},
        "user": {"email": bob, "department":"IT", "role":"poweruser"},
        "source": {"ip": ip},
        "geo": geo(ip),
        "user_agent": {"original": random.choice(USER_AGENTS)},
        "device": {"name": "WKSTN-044"},
        "auth": {"method": random.choice(["password","mfa_push"])},
        "rule": {"name":"impossible_travel_candidate"}
    }
    auth_records.append((index_name("auth-logs", dt), doc))

# ---- AUDIT logs (IAM policy changes) ----
audit_records = []
admin = "eve@corp.com"

# Normal admin changes
for _ in range(250):
    dt = rand_dt()
    role = random.choice(["roles/viewer","roles/logging.viewer","roles/compute.viewer","roles/storage.objectViewer"])
    change = random.choice(["add","remove"])
    actor = random.choice([admin,"admin2@corp.com"])
    doc = {
        "@timestamp": iso(dt),
        "event": {"dataset":"audit", "action":"setIamPolicy", "outcome":"success"},
        "actor": {"email": actor},
        "iam": {"role": role, "change": change},
        "resource": {"type":"gcp_project", "name":"corp-prod"},
        "source": {"ip": random.choice(IPS_CA)},
        "geo": geo(random.choice(IPS_CA)),
    }
    audit_records.append((index_name("audit-logs", dt), doc))

# Privilege escalation (owner granted) by bob from foreign IP
dt_pe = NOW - timedelta(hours=1, minutes=15)
doc_pe = {
    "@timestamp": iso(dt_pe),
    "event": {"dataset":"audit", "action":"setIamPolicy", "outcome":"success"},
    "actor": {"email": bob},
    "iam": {"role": "roles/owner", "change":"add"},
    "resource": {"type":"gcp_project", "name":"corp-prod"},
    "source": {"ip": "91.198.174.192"},
    "geo": geo("91.198.174.192"),
    "rule": {"name":"privilege_escalation_owner_grant"}
}
audit_records.append((index_name("audit-logs", dt_pe), doc_pe))

# ---- SERVICE ACCOUNT events (key creation) ----
sa_records = []
# Normal key rotations
for _ in range(120):
    dt = rand_dt()
    sa = random.choice(SERVICE_ACCTS)["account"]
    actor = random.choice([admin,"admin2@corp.com"])
    key_id = f"key-{random.randint(10000,99999)}"
    doc = {
        "@timestamp": iso(dt),
        "event": {"dataset":"service_account", "action":"createServiceAccountKey", "outcome":"success"},
        "service": {"account": sa, "key_id": key_id},
        "actor": {"email": actor},
        "source": {"ip": random.choice(IPS_CA)},
        "geo": geo(random.choice(IPS_CA)),
    }
    sa_records.append((index_name("service-accounts", dt), doc))

# Suspicious key creation for backup-sa by bob from RU IP
dt_sa = NOW - timedelta(hours=1, minutes=5)
doc_sa = {
    "@timestamp": iso(dt_sa),
    "event": {"dataset":"service_account", "action":"createServiceAccountKey", "outcome":"success"},
    "service": {"account":"backup-sa@corp.com", "key_id":"key-99999"},
    "actor": {"email": bob},
    "source": {"ip":"91.198.174.192"},
    "geo": geo("91.198.174.192"),
    "rule": {"name":"suspicious_sa_key_creation"}
}
sa_records.append((index_name("service-accounts", dt_sa), doc_sa))

# ---- IAM activity / data access / exfil-like events ----
iam_records = []

# Normal access noise
for _ in range(220):
    dt = rand_dt()
    sa = random.choice(SERVICE_ACCTS)["account"]
    action = random.choice(["token_generate","data_access","data_list"])
    res = random.choice(["corp-logs-bucket","corp-app-bucket","corp-reports-bucket"])
    doc = {
        "@timestamp": iso(dt),
        "event": {"dataset":"iam_activity", "action": action, "outcome":"success"},
        "service": {"account": sa},
        "resource": {"type":"cloud_storage", "name": res},
        "source": {"ip": random.choice(IPS_CA)},
        "geo": geo(random.choice(IPS_CA)),
    }
    iam_records.append((index_name("iam-activity", dt), doc))

# Exfil chain using compromised key-99999 from RU IP
chain = [
    (NOW - timedelta(hours=1, minutes=0),  "token_generate", "corp-finance-bucket"),
    (NOW - timedelta(minutes=50),          "data_access",    "corp-finance-bucket"),
    (NOW - timedelta(minutes=40),          "data_list",      "corp-hr-bucket"),
    (NOW - timedelta(minutes=30),          "data_download",  "corp-hr-bucket"),
    (NOW - timedelta(minutes=25),          "data_download",  "corp-hr-bucket"),
]
for dt, action, bucket in chain:
    doc = {
        "@timestamp": iso(dt),
        "event": {"dataset":"iam_activity", "action": action, "outcome":"success"},
        "service": {"account":"backup-sa@corp.com", "key_id":"key-99999"},
        "resource": {"type":"cloud_storage", "name": bucket},
        "source": {"ip":"91.198.174.192"},
        "geo": geo("91.198.174.192"),
        "rule": {"name":"suspected_exfil_via_sa_key"}
    }
    iam_records.append((index_name("iam-activity", dt), doc))

# ---- Write BULK files ----
write_bulk(OUT_DIR / "auth.bulk.ndjson", auth_records)
write_bulk(OUT_DIR / "audit.bulk.ndjson", audit_records)
write_bulk(OUT_DIR / "service-accounts.bulk.ndjson", sa_records)
write_bulk(OUT_DIR / "iam-activity.bulk.ndjson", iam_records)

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
# Step 4 — Create Kibana Data Views via API (through Nginx + Basic Auth)
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