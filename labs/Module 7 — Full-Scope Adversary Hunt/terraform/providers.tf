terraform {
  required_providers {
    google = {
      version = "3.90.1"
    }
    random = {
      source  = "hashicorp/random"
      version = "3.1.3"
    }
  }
}

provider "google" {
  project = var.gcp_project_id
  region  = var.gcp_region
  zone    = var.gcp_zone
}
