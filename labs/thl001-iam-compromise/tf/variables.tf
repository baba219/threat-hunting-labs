variable "gcp_project_id" {
  type        = string
  description = "The GCP project ID to apply this config to."
}

variable "gcp_region" {
  type        = string
  description = "The GCP region to apply this config to."
}

variable "gcp_zone" {
  type        = string
  description = "The GCP zone to apply this config to."
}

variable "lab_username" {
  type        = string
  description = "Qwiklabs student username"
}

variable "lab_password" {
  type        = string
  description = "Qwiklabs student password"
  sensitive   = true
}

