output "kibana_url" {
  value = "http://${google_compute_instance.lab_elk.network_interface[0].access_config[0].nat_ip}"
}

output "lab_zone" {
  value       = var.gcp_zone
  description = "Lab zone"
}

output "vm_name" {
  value       = google_compute_instance.lab_elk.name
  description = "VM name hosting Kibana"
}

