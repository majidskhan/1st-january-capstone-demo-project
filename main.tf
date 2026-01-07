
locals {
  name = "capstone"
}

# create a vpc
resource "aws_vpc" "vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "${local.name}-vpc"
  }
}

# Get Availability Zones
data "aws_availability_zones" "available" {
  state = "available"
}

# create an ssh key pair
resource "tls_private_key" "keypair" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "public_key" {
  key_name   = "${local.name}-keypair"
  public_key = tls_private_key.keypair.public_key_openssh
}

resource "local_file" "private_key" {
  content  = tls_private_key.keypair.private_key_pem
  filename = "${local.name}-keypair.pem"
  file_permission = "0400"
}
# create public subnets
resource "aws_subnet" "public_subnet" {
  count                   = 2
  vpc_id                  = aws_vpc.vpc.id
  cidr_block              = "10.0.${count.index}.0/24"
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name = "${local.name}-public-subnet-${count.index + 1}"
  }
}

# create private subnets
resource "aws_subnet" "private_subnet" {
  count             = 2
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = "10.0.${count.index + 10}.0/24"
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = {
    Name = "${local.name}-private-subnet-${count.index + 1}"
  }
}

# create an internet gateway
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.vpc.id

  tags = {
    Name = "${local.name}-igw"
  }
}
# create an elastic IP for NAT Gateway
resource "aws_eip" "nat_eip" {
  domain = "vpc"

  tags = {
    Name = "${local.name}-nat-eip"
  }
}

# create a NAT gateway
resource "aws_nat_gateway" "nat" {
  allocation_id = aws_eip.nat_eip.id
  subnet_id     = aws_subnet.public_subnet[0].id

  tags = {
    Name = "${local.name}-nat-gateway"
  }

  depends_on = [aws_internet_gateway.igw]
}
# create a public route table
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Name = "${local.name}-public-rt"
  }
}

# create a private route table
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.vpc.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat.id
  }

  tags = {
    Name = "${local.name}-private-rt"
  }
}

# associate route tables with subnets
resource "aws_route_table_association" "public_assoc" {
  count          = 2
  subnet_id      = aws_subnet.public_subnet[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "private_assoc" {
  count          = 2
  subnet_id      = aws_subnet.private_subnet[count.index].id
  route_table_id = aws_route_table.private.id
}

# Frontend Security Group (ALB / Web Servers)
resource "aws_security_group" "capstone_sg_frontend" {
  name        = "capstone-sg-frontend"
  description = "Frontend security group for ALB and Apache web servers"
  vpc_id      = aws_vpc.vpc.id

  # Allow SSH (administration)
  ingress {
    description = "SSH access"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Allow HTTPS traffic
  ingress {
    description = "HTTPS access"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Allow HTTP traffic
  ingress {
    description = "HTTP access"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Allow all outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${local.name}-sg-frontend"
  }
}

# Backend Security Group (Database Tier)
resource "aws_security_group" "capstone_sg_backend" {
  name        = "capstone-sg-backend"
  description = "Backend security group for database access"
  vpc_id      = aws_vpc.vpc.id

  # Allow MySQL access from application subnets
  ingress {
    description = "MySQL access from application subnets"
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.capstone_sg_frontend.id]
}


  # Allow all outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${local.name}-sg-backend"
  }
}
 # create a wordpress webserver
resource "aws_instance" "wordpress_server" {
  ami                    = "ami-099400d52583dd8c4" # Amazon Linux 2
  instance_type          = "t2.micro"
  subnet_id              = aws_subnet.public_subnet[0].id
  vpc_security_group_ids = [aws_security_group.capstone_sg_frontend.id]
  key_name               = aws_key_pair.public_key.key_name

  user_data = <<-EOF
    #!/bin/bash
    set -e

    # Update system
    yum update -y

    # Install Apache, PHP, MySQL client
    amazon-linux-extras enable php8.0
    yum clean metadata
    yum install -y httpd php php-mysqlnd wget unzip

    # Start and enable Apache
    systemctl start httpd
    systemctl enable httpd

    # Download and install WordPress
    cd /var/www/html
    wget https://wordpress.org/latest.tar.gz
    tar -xzf latest.tar.gz
    cp -r wordpress/* /var/www/html/
    rm -rf wordpress latest.tar.gz

    # Set permissions
    chown -R apache:apache /var/www/html
    chmod -R 755 /var/www/html

    # Configure WordPress
    cp wp-config-sample.php wp-config.php

    sed -i "s/database_name_here/${var.db_name}/" wp-config.php
    sed -i "s/username_here/${var.db_username}/" wp-config.php
    sed -i "s/password_here/${var.db_password}/" wp-config.php
    sed -i "s/localhost/${replace(aws_db_instance.wordpress_db.endpoint, ":3306", "")}/" wp-config.php

    # Restart Apache
    systemctl restart httpd

    # Set hostname
    hostnamectl set-hostname ${local.name}-wordpress
  EOF

  tags = {
    Name = "${local.name}-wordpress-server"
  }
}

#creating database subnet group
resource "aws_db_subnet_group" "wordpress_db_subnet_group" {
  name       = "${local.name}-db-subnet-group"
  subnet_ids = aws_subnet.private_subnet[*].id

  tags = {
    Name = "${local.name}-db-subnet-group"
  }
}

# Creating Mysql wordpress database instance
resource "aws_db_instance" "wordpress_db" {
  identifier = "${local.name}-wordpress-db"

  allocated_storage = 20
  engine            = "mysql"
  engine_version    = "8.0"
  instance_class    = "db.t3.micro"

  db_name  = var.db_name
  username = var.db_username
  password = var.db_password

  db_subnet_group_name   = aws_db_subnet_group.wordpress_db_subnet_group.name
  vpc_security_group_ids = [aws_security_group.capstone_sg_backend.id]

  skip_final_snapshot = true

  tags = {
    Name = "${local.name}-wordpress-db"
  }
}


# creating IAM role
resource "aws_iam_role" "ec2_role" {
  name = "${local.name}-ec2-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

# creating media_bucket IAM policy
resource "aws_iam_policy" "s3_policy" {
  name = "${local.name}-s3-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:*"]   # ⚠️ Should be restricted in production
      Resource = "*"
    }]
  })
}


# Attaching IAM_role_policy to s3 media_bucket policy
resource "aws_iam_role_policy_attachment" "attach_s3_policy" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = aws_iam_policy.s3_policy.arn
}
# creating instance profile
resource "aws_iam_instance_profile" "ec2_instance_profile" {
  name = "${local.name}-instance-profile"
  role = aws_iam_role.ec2_role.name
}
# Create s3 media bucket
resource "aws_s3_bucket" "media_bucket" {
  bucket        = "media-s3-bucket-eu2"
  force_destroy = true

  tags = {
    Name = "${local.name}-media-bucket"
  }
}
# creating log bucket
resource "aws_s3_bucket" "log_bucket" {
  bucket        = "log-s3-bucket-eu2"
  force_destroy = true

  tags = {
    Name = "${local.name}-log-bucket"
  }
}
# cfreating code bucket
resource "aws_s3_bucket" "code_bucket" {
  bucket        = "code-s3-bucket-eu2"
  force_destroy = true

  tags = {
    Name = "${local.name}-code-bucket"
  }
}

# Media bucket access
resource "aws_s3_bucket_public_access_block" "media_access" {
  bucket = aws_s3_bucket.media_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
# Log bucket access
resource "aws_s3_bucket_public_access_block" "log_access" {
  bucket = aws_s3_bucket.log_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
} 

#log bucket ownership & acl
resource "aws_s3_bucket_ownership_controls" "log_ownership" {
  bucket = aws_s3_bucket.log_bucket.id

  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_acl" "log_acl" {
  depends_on = [aws_s3_bucket_ownership_controls.log_ownership]

  bucket = aws_s3_bucket.log_bucket.id
  acl    = "private"
}
