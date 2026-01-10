variable "aws_region" {
  description = "AWS region for the infrastructure"
  type        = string
  default     = "eu-west-2"
}

variable "alert_email" {
  description = "Email address to receive infrastructure alerts"
  type        = string
  default     = "majidskhan4@gmail.com"
}

variable "domain_name" {
  description = "Primary domain name for the application"
  type        = string
  default     = "majiktech.uk"
}

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

variable "dbcred1" {
  type = map(string)
  default = {
    username = "admin"
    password = "admin123"
  }
}
