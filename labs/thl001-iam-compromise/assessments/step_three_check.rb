def check(handles:, resources:, maximum_score:)
  begin
    compute = handles['project_0.ComputeV1']
    ssh     = handles['user_0.SSH']

    project_id = resources['project_0']['project_id']
    vm_name    = resources['project_0']['startup_script.vm_name']   || 'lab-elk'
    lab_zone   = resources['project_0']['startup_script.lab_zone']  || '"filled in at lab start"'

    wanted_title = "THL01-Step3-Auth-Outside-Canada"
    kib_user = "student1"
    kib_pass = "Password123"

    ret_hash = { done: false, score: 0, message: "", student_message: "" }

    instance = compute.get_instance(project_id, lab_zone, vm_name, freeze_args: true)
    nat_ip = instance&.network_interfaces&.dig(0)&.access_configs&.dig(0)&.nat_ip

    if nat_ip.nil? || nat_ip.strip.empty?
      ret_hash[:message] = "No NAT IP found for instance"
      ret_hash[:student_message] = 'error_message'
      return ret_hash
    end

    cmd = %Q{
      set -euo pipefail
      curl -s -u #{kib_user}:#{kib_pass} -H "kbn-xsrf: true" \
        "http://localhost/api/saved_objects/_find?type=search&per_page=1000" \
      | python3 - <<'PY'
import json, sys
wanted = "#{wanted_title}"
data = json.load(sys.stdin)
titles = [o.get("attributes", {}).get("title") for o in data.get("saved_objects", [])]
print("FOUND" if wanted in titles else "NOT_FOUND")
PY
    }.strip

    out = ssh.ssh_exec(nat_ip, cmd).to_s

    if out.include?("FOUND")
      ret_hash = { done: true, score: maximum_score, message: 'success', student_message: 'success' }
    else
      ret_hash[:message] = "Saved search not found: #{wanted_title}"
      ret_hash[:student_message] = 'not_found'
    end

    return ret_hash

  rescue => e
    return { done: false, score: 0, message: e.message, student_message: 'error_message' }
  end
end
