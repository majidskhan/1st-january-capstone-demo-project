# -----------------------------
# VPC Outputs
# -----------------------------
output "vpc_id" {
  description = "ID of the VPC"
  value       = aws_vpc.vpc.id
}

# -----------------------------
# Subnet Outputs
# -----------------------------
output "public_subnet_ids" {
  description = "IDs of the public subnets"
  value       = aws_subnet.public_subnet[*].id
}

output "private_subnet_ids" {
  description = "IDs of the private subnets"
  value       = aws_subnet.private_subnet[*].id
}

# -----------------------------
# Security Group Outputs
# -----------------------------
output "frontend_security_group_id" {
  description = "ID of the frontend security group"
  value       = aws_security_group.capstone_sg_frontend.id
}

output "backend_security_group_id" {
  description = "ID of the backend security group"
  value       = aws_security_group.capstone_sg_backend.id
}

# -----------------------------
# EC2 Instance Outputs
# -----------------------------
output "wordpress_server_id" {
  description = "ID of the WordPress server instance"
  value       = aws_instance.wordpress_server.id
}

output "wordpress_server_public_ip" {
  description = "Public IP of the WordPress server"
  value       = aws_instance.wordpress_server.public_ip
}

# -----------------------------
# Gateway Outputs
# -----------------------------
output "internet_gateway_id" {
  description = "ID of the Internet Gateway"
  value       = aws_internet_gateway.igw.id
}

output "nat_gateway_id" {
  description = "ID of the NAT Gateway"
  value       = aws_nat_gateway.nat.id
}

# -----------------------------
# Route Table Outputs
# -----------------------------
output "public_route_table_id" {
  description = "ID of the public route table"
  value       = aws_route_table.public.id
}

output "private_route_table_id" {
  description = "ID of the private route table"
  value       = aws_route_table.private.id
}

# -----------------------------
# Key Pair Outputs
# -----------------------------
output "key_pair_name" {
  description = "Name of the SSH key pair"
  value       = aws_key_pair.public_key.key_name
}