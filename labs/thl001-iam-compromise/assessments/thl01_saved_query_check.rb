# Helper shared by steps 2-5.
# Validates a Kibana "Saved search" exists with an exact title.
#
# It SSH's to the VM hosting Kibana and queries localhost Kibana Saved Objects API.
#
# Expected: Nginx basic auth in front of Kibana (as in your startup script).

module Thl01SavedQueryCheck
  KIB_USER = "student1".freeze
  KIB_PASS = "Password123".freeze

  def self.run(handles:, resources:, maximum_score:, saved_title:)
    compute = handles['project_0.ComputeV1']
    ssh     = handles['user_0.SSH']

    project_id = resources['project_0']['project_id']
    lab_zone   = resources.dig('project_0', 'startup_script.lab_zone')
    vm_name    = resources.dig('project_0', 'startup_script.vm_name') || 'lab-elk'

    ret = { done: false, score: 0, message: "", student_message: "" }

    unless lab_zone && !lab_zone.to_s.strip.empty?
      ret[:message] = "Missing startup_script.lab_zone. Add output \"lab_zone\" in outputs.tf."
      ret[:student_message] = "not_found"
      return ret
    end

    begin
      instance = compute.get_instance(project_id, lab_zone, vm_name, freeze_args: true)
      nat_ip = instance&.network_interfaces&.first&.access_configs&.first&.nat_ip

      if nat_ip.nil? || nat_ip.strip.empty?
        ret[:message] = "No external IP found for VM '#{vm_name}'."
        ret[:student_message] = "not_found"
        return ret
      end

      # Bash script executed on the VM.
      # - Queries Kibana Saved Objects for type=search
      # - Confirms exact match on attributes.title
      cmd = <<~'BASH'
        set -euo pipefail

        TITLE="$1"
        AUTH="$2"

        # Query saved searches
        resp=$(curl -s -u "$AUTH" -H 'kbn-xsrf: true' \
          "http://localhost/api/saved_objects/_find?type=search&per_page=1000&search_fields=title&search=${TITLE}" || true)

        # If Kibana isn't ready or jq missing, fail cleanly
        if ! command -v jq >/dev/null 2>&1; then
          echo "ERROR: jq not found"
          exit 3
        fi

        # exact match check
        found=$(echo "$resp" | jq -r --arg t "$TITLE" '
          (.saved_objects // []) 
          | map(select(.attributes.title == $t)) 
          | length
        ' 2>/dev/null || echo 0)

        if [ "${found}" -gt 0 ]; then
          echo "FOUND"
          exit 0
        fi

        echo "NOT_FOUND"
        exit 2
      BASH

      auth = "#{KIB_USER}:#{KIB_PASS}"
      # Pass args safely
      full_cmd = "bash -lc #{shellescape("bash -lc #{shellescape(cmd)} -- #{shellescape(saved_title)} #{shellescape(auth)}")}"

      out = ssh.ssh_exec(nat_ip, full_cmd)

      if out.include?("FOUND")
        ret = { done: true, score: maximum_score, message: "success", student_message: "success" }
      else
        ret[:message] = "Saved query not found: #{saved_title}. Raw output: #{out.to_s[0,200]}"
        ret[:student_message] = "not_found"
      end

    rescue => e
      ret[:message] = e.message
      ret[:student_message] = "not_found"
    end

    ret
  end

  # Minimal shell escaping for Ruby -> bash -lc contexts
  def self.shellescape(s)
    return "''" if s.nil? || s == ""
    "'" + s.to_s.gsub("'", %q('\'')).to_s + "'"
  end
end
