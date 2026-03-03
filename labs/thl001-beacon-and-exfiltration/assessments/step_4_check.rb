def step_4_check(handles:, resources:, maximum_score:)
  begin
    require "json"

    compute = handles["project_0.ComputeV1"]
    ssh     = handles["user_0.SSH"]

    ret_hash = { done: false, score: 0, message: "", student_message: "" }

    project_id = resources["project_0"]["project_id"]

    # Use default_zone (best practice from AUTHLAB005)
    lab_zone = resources["project_0"]["default_zone"].to_s.strip.gsub(/\A"+|"+\z/, "")
    unless lab_zone.match?(/\A[a-z]+-[a-z0-9]+[0-9]-[a-z]\z/)
      ret_hash[:message] = "Invalid zone value: #{lab_zone.inspect}"
      ret_hash[:student_message] = "invalid_zone"
      return ret_hash
    end

    # Dynamic VM name (exported from Terraform)
    instance_name = resources["project_0"]["startup_script.vm_name"].to_s.strip

    # >>> CHANGE ONLY THIS PER STEP <<<
    target_title = "THL01-Key-Usage"

    inst = compute.get_instance(project_id, lab_zone, instance_name, freeze_args: true)
    unless inst
      ret_hash[:student_message] = "no_vm"
      ret_hash[:message] = "VM not found"
      return ret_hash
    end

    nat_ip = inst.network_interfaces[0].access_configs[0].nat_ip rescue nil
    if nat_ip.to_s.strip.empty?
      ret_hash[:student_message] = "no_vm"
      ret_hash[:message] = "No NAT IP on VM"
      return ret_hash
    end

    # 1) Find Kibana container
    kid_cmd = <<~BASH
      set -e
      KID=$(sudo docker ps --format '{{.ID}} {{.Names}}' | awk '$2 ~ /(lab-kibana-1|kibana)/ {print $1; exit}')
      if [ -z "$KID" ]; then
        echo "KIBANA_CONTAINER_NOT_FOUND"
      else
        echo "$KID"
      fi
    BASH

    kid = ssh.ssh_exec(nat_ip, kid_cmd).to_s.strip
    if kid == "KIBANA_CONTAINER_NOT_FOUND" || kid.empty?
      ret_hash[:student_message] = "no_kibana"
      ret_hash[:message] = "Kibana container not found"
      return ret_hash
    end

    # 2) Query saved objects and do EXACT title match
    #
    # IMPORTANT:
    # - Kibana versions differ: saved Discover objects can be type=discover or type=search
    # - search= is NOT exact; we'll filter exactly in Ruby
    types_to_try = ["discover", "search"]

    found = false
    debug_returned = []

    types_to_try.each do |t|
      # URL-encode minimal (spaces etc.) safely via printf trick in shell
      cmd = <<~BASH
        set -e
        TITLE=#{Shellwords.escape(target_title)}
        sudo docker exec -i "#{kid}" sh -lc 'curl -s -H "kbn-xsrf: true" \
          "http://localhost:5601/api/saved_objects/_find?type=#{t}&per_page=10000&search_fields=title&search='"'"'#{target_title}'"'"'"'
      BASH

      resp = ssh.ssh_exec(nat_ip, cmd).to_s.strip
      data = JSON.parse(resp) rescue nil
      next unless data.is_a?(Hash) && data["saved_objects"].is_a?(Array)

      data["saved_objects"].each do |o|
        title = o.dig("attributes", "title").to_s
        debug_returned << { "type" => t, "title" => title }
        if title == target_title
          found = true
          break
        end
      end

      break if found
    end

    if found
      return { done: true, score: maximum_score, message: "success", student_message: "success" }
    else
      ret_hash[:student_message] = "no_saved_search"
      # Helpful debug (creator only): shows what titles Kibana returned
      ret_hash[:message] = "Exact saved object not found for title=#{target_title.inspect}. Returned=#{debug_returned.uniq.inspect}"
      return ret_hash
    end

  rescue => e
    return { done: false, score: 0, message: e.message, student_message: "no_kibana" }
  end
end