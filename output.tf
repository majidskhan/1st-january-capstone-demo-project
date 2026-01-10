output "wordpress_public_ip" {
  description = "Public IP address of the WordPress EC2 instance"
  value       = aws_instance.wordpress_server.public_ip
}

output "db_endpoint" {
  description = "RDS MySQL endpoint for the WordPress database"
  value       = aws_db_instance.wordpress_db.endpoint
}
