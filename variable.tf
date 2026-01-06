# -----------------------------
# Database Configuration
# -----------------------------
variable "db_name" {
  description = "Name of the WordPress database"
  type        = string
  default     = "wordpress_db"
}

variable "db_username" {
  description = "Username for the WordPress database"
  type        = string
  default     = "admin"
}

variable "db_password" {
  description = "Password for the WordPress database"
  type        = string
  default     = "Admin123"
  sensitive   = true
}