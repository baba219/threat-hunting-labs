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
  project      = var.gcp_project_id
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

export DEBIAN_FRONTEND=noninteractive

# --- Generate lab credentials locally (Qwiklabs-friendly) ---
LAB_USER="lab"
LAB_PASS="$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 16)"
echo "[+] Generated lab creds: $${LAB_USER} / (hidden)"
mkdir -p /opt/lab
chmod 755 /opt/lab
printf "Kibana Basic Auth\\nUsername: %s\\nPassword: %s\\n" "$LAB_USER" "$LAB_PASS" > /opt/lab/creds.txt
chmod 600 /opt/lab/creds.txt

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

# --- Datasets (unchanged) ---
echo "[+] Writing dataset JSONL files into /opt/lab/dataset"
# (tes tee JSONL restent identiques ici)

# --- Build bulk ---
echo "[+] Creating make_bulk.py"
# (ton make_bulk.py reste identique ici)

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

  body=$(echo "$resp" | sed '$d')
  http=$(echo "$resp" | tail -n 1)

  if [[ "$http" == "200" || "$http" == "201" ]]; then
    echo "[+] Data view created: $${name} -> $${pattern}"
    return 0
  fi

  if [[ "$http" == "409" ]]; then
    echo "[=] Data view already exists (409): $${name}"
    return 0
  fi

  echo "[!] Failed to create data view $${name} ($${pattern}) HTTP=$${http}"
  echo "$body" | head -n 80
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
