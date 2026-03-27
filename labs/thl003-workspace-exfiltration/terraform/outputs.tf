output "vm_ip" {
  value       = google_compute_instance.thl_workspace_lab.network_interface[0].access_config[0].nat_ip
  description = "VM external IP"
}

output "kibana_url" {
  value       = "http://${google_compute_instance.thl_workspace_lab.network_interface[0].access_config[0].nat_ip}"
  description = "Kibana URL (through Nginx basic auth)"
}

output "lab_zone" {
  value       = var.gcp_zone
  description = "Compute Engine zone for the lab VM"
}

output "vm_name" {
  value       = google_compute_instance.thl_workspace_lab.name
  description = "Lab VM instance name (for Activity Tracking)"
}

output "lab_user" {
  value       = local.lab_user
  description = "Kibana Basic Auth Username"
}

output "lab_pass" {
  value       = nonsensitive(random_password.lab_pass.result)
  description = "Kibana Basic Auth Password"
}
