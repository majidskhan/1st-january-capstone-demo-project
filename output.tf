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

# -----------------------------
# EIP Outputs
# -----------------------------
output "nat_eip_allocation_id" {
  description = "Allocation ID of the NAT Gateway EIP"
  value       = aws_eip.nat_eip.id
}

output "nat_eip_public_ip" {
  description = "Public IP of the NAT Gateway EIP"
  value       = aws_eip.nat_eip.public_ip
}

# -----------------------------
# Database Outputs
# -----------------------------
output "db_subnet_group_name" {
  description = "Name of the database subnet group"
  value       = aws_db_subnet_group.wordpress_db_subnet_group.name
}

output "wordpress_db_endpoint" {
  description = "Endpoint of the WordPress database"
  value       = aws_db_instance.wordpress_db.endpoint
}

output "wordpress_db_address" {
  description = "Address of the WordPress database"
  value       = aws_db_instance.wordpress_db.address
}

output "wordpress_db_port" {
  description = "Port of the WordPress database"
  value       = aws_db_instance.wordpress_db.port
}

# -----------------------------
# IAM Outputs
# -----------------------------
output "ec2_role_arn" {
  description = "ARN of the EC2 IAM role"
  value       = aws_iam_role.ec2_role.arn
}

output "ec2_role_name" {
  description = "Name of the EC2 IAM role"
  value       = aws_iam_role.ec2_role.name
}

output "s3_policy_arn" {
  description = "ARN of the S3 IAM policy"
  value       = aws_iam_policy.s3_policy.arn
}

output "ec2_instance_profile_name" {
  description = "Name of the EC2 instance profile"
  value       = aws_iam_instance_profile.ec2_instance_profile.name
}

# -----------------------------
# S3 Bucket Outputs
# -----------------------------
output "media_bucket_name" {
  description = "Name of the media S3 bucket"
  value       = aws_s3_bucket.media_bucket.bucket
}

output "media_bucket_arn" {
  description = "ARN of the media S3 bucket"
  value       = aws_s3_bucket.media_bucket.arn
}

output "log_bucket_name" {
  description = "Name of the log S3 bucket"
  value       = aws_s3_bucket.log_bucket.bucket
}

output "log_bucket_arn" {
  description = "ARN of the log S3 bucket"
  value       = aws_s3_bucket.log_bucket.arn
}

output "code_bucket_name" {
  description = "Name of the code S3 bucket"
  value       = aws_s3_bucket.code_bucket.bucket
}

output "code_bucket_arn" {
  description = "ARN of the code S3 bucket"
  value       = aws_s3_bucket.code_bucket.arn
}