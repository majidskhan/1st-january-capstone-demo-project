
locals {
  name = "capstone"
  db_cred = jsondecode(
    aws_secretsmanager_secret_version.db_cred_version.secret_string
  )
}
# Run Checkov scan for the project
resource "null_resource" "checkov_scan" {
  provisioner "local-exec" {
    command     = "./checkov_scan.sh"
    interpreter = ["bash", "-c"]
  }

  # Cleanup the Checkov output file when resource is destroyed
  provisioner "local-exec" {
    when    = destroy
    command = "rm -f checkov_output.json"
  }

  # Always run the scan on every terraform apply
  triggers = {
    always_run = timestamp()
  }
}

# Output to indicate scan status
output "checkov_scan_status" {
  value = "Checkov scan completed. Check the checkov_output.json file for details."
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

# Frontend ec2 Security Group for Web Servers
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

# Backend Security Group for Database RDS
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

# IAM Role for WordPress EC2 Instances
resource "aws_iam_role" "eu2acp_wordpress_ec2_role" {
  name = "${local.name}-wordpress-ec2-role"

  description = "IAM role for EC2 instances toaccess AWS services S3, Secrets Manager, CloudWatch"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Name    = "${local.name}-wordpress-ec2-role"
    Purpose = "WordPressEC2Access"
  }
}

 # create ec2 wordpress webserver
resource "aws_instance" "wordpress_server" {
  ami                    = "ami-099400d52583dd8c4" # Amazon Linux 2
  instance_type          = "t2.micro"
  subnet_id              = aws_subnet.public_subnet[0].id
  vpc_security_group_ids = [aws_security_group.capstone_sg_frontend.id, aws_security_group.capstone_sg_backend.id ]
  key_name               = aws_key_pair.public_key.key_name

  iam_instance_profile = aws_iam_instance_profile.iam_instance_profile.name
 
  user_data = filebase64("wp_userdata.tf")   

  tags = {
    Name = "${local.name}-wordpress-server"
  }
}   


# AMI Creation from WordPress Webserver
resource "aws_ami_from_instance" "wordpress_ami" {
  name                    = "${local.name}-wordpress-ami"
  source_instance_id      = aws_instance.wordpress_server.id
  snapshot_without_reboot = true

  depends_on = [
    aws_instance.wordpress_server,
    time_sleep.wordpress_ami_wait
  ]

  tags = {
    Name    = "${local.name}-wordpress-ami"
    Project = local.name
  }
}

# Wait for Userdata Completion
resource "time_sleep" "wordpress_ami_wait" {
  depends_on      = [aws_instance.wordpress_server]
  create_duration = "300s"
}

# policy with least privilege for S3, CloudWatch Logs, and Secrets Manager access
resource "aws_iam_policy" "capstone_wordpress_ec2_policy" {
  name        = "${local.name}-wordpress-ec2-policy"
  description = "Least-privilege policy for WordPress EC2 access to S3, CloudWatch Logs, and Secrets Manager."

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket"
        ],
        Resource = [
          aws_s3_bucket.code_bucket.arn,
          "${aws_s3_bucket.code_bucket.arn}/*",
          aws_s3_bucket.media_bucket.arn,
          "${aws_s3_bucket.media_bucket.arn}/*"
        ]
      },
      {
        Effect = "Allow",
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ],
        Resource = "*"
      },
      {
        Effect = "Allow",
        Action = [
          "secretsmanager:GetSecretValue"
        ],
        Resource = aws_secretsmanager_secret.db_credentials.arn
      }
    ]
  })

  tags = {
    Name    = "${local.name}-wordpress-ec2-policy"
    Project = local.name
  }
}

# Attach the policy to the IAM role
resource "aws_iam_role_policy_attachment" "capstone_wordpress_policy_attach" {
  role       = aws_iam_role.capstone_wordpress_ec2_role.name
  policy_arn = aws_iam_policy.capstone_wordpress_ec2_policy.arn
}

# Instance profile to associate IAM role with EC2 instances
resource "aws_iam_instance_profile" "capstone_wordpress_instance_profile" {
  name = "${local.name}-wordpress-instance-profile"
  role = aws_iam_role.capstone_wordpress_ec2_role.name

  tags = {
    Name    = "${local.name}-wordpress-instance-profile"
    Project = local.name
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

# Create RDS MySQL Instance for WordPress
resource "aws_db_instance" "wordpress_db" {
  identifier             = "${local.name}-wordpress-db"

  allocated_storage      = 20
  max_allocated_storage  = 100
  storage_type           = "gp2"

  engine                 = "mysql"
  engine_version         = "8.0"
  instance_class         = "db.t3.micro"

  db_name                = var.db_name
  username               = local.db_cred.username
  password               = local.db_cred.password

  parameter_group_name   = "default.mysql8.0"
  db_subnet_group_name   = aws_db_subnet_group.capstone_db_subnet_group.name
  vpc_security_group_ids = [aws_security_group.capstone_sg_backend.id]

  publicly_accessible    = false
  multi_az               = false

  backup_retention_period = 3
  backup_window           = "03:00-04:00"

  skip_final_snapshot    = true
  deletion_protection    = false

  tags = {
    Name    = "${local.name}-wordpress-db"
    Project = local.name
  }
}

# Application Load Balancer
resource "aws_lb" "wordpress_alb" {
  name               = "${local.name}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.capstone_sg_frontend.id]
  subnets            = aws_subnet.public_subnet[*].id

  enable_deletion_protection = false

  tags = {
    Name = "${local.name}-alb"
  }
}

# HTTP Target Group
resource "aws_lb_target_group" "wordpress_http_tg" {
  name     = "${local.name}-http-tg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.vpc.id

  health_check {
    path                = "/indextest.html"
    protocol            = "HTTP"
    port                = "traffic-port"
    interval            = 60
    timeout             = 30
    healthy_threshold   = 3
    unhealthy_threshold = 5
  }

  tags = {
    Name = "${local.name}-http-target-group"
  }
}

# HTTPS Target Group
resource "aws_lb_target_group" "wordpress_https_tg" {
  name     = "${local.name}-https-tg"
  port     = 443
  protocol = "HTTPS"
  vpc_id   = aws_vpc.vpc.id

  health_check {
    path                = "/indextest.html"
    protocol            = "HTTPS"
    port                = "traffic-port"
    interval            = 60
    timeout             = 30
    healthy_threshold   = 3
    unhealthy_threshold = 5
  }

  tags = {
    Name = "${local.name}-https-target-group"
  }
}

# Target Group Attachment for HTTP
resource "aws_lb_target_group_attachment" "http_attachment" {
  target_group_arn = aws_lb_target_group.wordpress_http_tg.arn
  target_id        = aws_instance.wordpress_server.id
  port             = 80
}

# Target Group Attachment for HTTPS
resource "aws_lb_target_group_attachment" "https_attachment" {
  target_group_arn = aws_lb_target_group.wordpress_https_tg.arn
  target_id        = aws_instance.wordpress_server.id
  port             = 443
}

# launch template for autoscaling group
resource "aws_launch_template" "wordpress_launch_template" {
  name_prefix   = "${local.name}-launch-template-"
  image_id      = aws_ami_from_instance.wordpress_ami.id
  instance_type = "t2.micro"
  key_name      = aws_key_pair.public_key.key_name

  iam_instance_profile {
    name = aws_iam_instance_profile.capstone_wordpress_instance_profile.name
  }

  network_interfaces {
    security_groups = [aws_security_group.capstone_sg_frontend.id, aws_security_group.capstone_sg_backend.id ]
    associate_public_ip_address = true
  }

  user_data = filebase64("wp_userdata.tf")   

  tag_specifications {
    resource_type = "instance"

    tags = {
      Name = "${local.name}-autoscaling-instance"
    }
  }
} 

# Autoscaling policy
resource "aws_autoscaling_policy" "scale_out" {
  name                   = "scale-out-policy"
  scaling_adjustment     = 1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 300
  autoscaling_group_name = aws_autoscaling_group.wordpress_asg.name
}

# auto scaling group
resource "aws_autoscaling_group" "wordpress_asg" {
  name                      = "${local.name}-asg"
  desired_capacity          = 2
  max_size                  = 5
  min_size                  = 1
  health_check_grace_period = 300
  health_check_type         = "EC2"
  force_delete              = true

  launch_template {
    id      = aws_launch_template.wordpress_launch_template.id
    version = "$Latest"
  }

  vpc_zone_identifier = aws_subnet.public_subnet[*].id

  target_group_arns = [
    aws_lb_target_group.wordpress_http_tg.arn,
    aws_lb_target_group.wordpress_https_tg.arn
  ]

  tag {
    key                 = "Name"
    value               = "${local.name}-asg"
    propagate_at_launch = true
  }
}

# HTTP Listener
resource "aws_lb_listener" "wordpress_http_listener" {
  load_balancer_arn = aws_lb.wordpress_alb.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.wordpress_http_tg.arn
  }
}

# Import the hosted zone 
data "aws_route53_zone" "majiktech_zone" {
  name         = "majiktech.uk"
  private_zone = false
}

# Create ACM certificate for ssl
resource "aws_acm_certificate" "wordpress_acm" {
  domain_name       = "majiktech.uk"
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}

# Route53 validation record for ACM certificate
resource "aws_route53_record" "acm_validation" {
  for_each = {
    for dvo in aws_acm_certificate.wordpress_acm.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = data.aws_route53_zone.majiktech_zone.zone_id
}

# Validate ACM certificate
resource "aws_acm_certificate_validation" "wordpress_acm_validation" {
  certificate_arn         = aws_acm_certificate.wordpress_acm.arn
  validation_record_fqdns = [for record in aws_route53_record.acm_validation : record.fqdn]
}

# HTTPS Listener for the WordPress ALB
resource "aws_lb_listener" "wordpress_https_listener" {
  load_balancer_arn = aws_lb.wordpress_alb.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = aws_acm_certificate.wordpress_acm.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.wordpress_https_tg.arn
  }
}

# Route53 validation records for ACM certificate
resource "aws_route53_record" "wordpress_acm_validation" {
  for_each = {
    for dvo in aws_acm_certificate.wordpress_acm_cert.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = data.aws_route53_zone.majiktech_uk.zone_id
}

# Validate ACM certificate using Route53 DNS records
resource "aws_acm_certificate_validation" "wordpress_cert_validation" {
  certificate_arn         = aws_acm_certificate.wordpress_acm_cert.arn
  validation_record_fqdns = [for record in aws_route53_record.wordpress_acm_validation : record.fqdn]
}

resource "aws_cloudwatch_metric_alarm" "high_cpu" {
  alarm_name          = "high-cpu-utilization"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 120
  statistic           = "Average"
  threshold           = 70

  alarm_description   = "Triggers when CPU exceeds 70% utilization"
  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.set27-auto-scaling-group.name
  }

  alarm_actions = [
    aws_autoscaling_policy.scale_out.arn,
    aws_sns_topic.server_alert.arn
  ]
}
