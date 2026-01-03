output "kibana_url" {
  value = "http://${google_compute_instance.lab_elk.network_interface[0].access_config[0].nat_ip}"
}
