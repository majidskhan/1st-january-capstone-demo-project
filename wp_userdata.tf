locals {
  wordpress_script = <<-EOF
#!/bin/bash
set -e

# System Update
sudo yum update -y
sudo yum upgrade -y

# Install AWS CLI v2
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
sudo yum install -y unzip
unzip awscliv2.zip
sudo ./aws/install


# Install Apache, PHP, MySQL, SSL
sudo yum install -y httpd php php-mysqlnd mod_ssl


# WordPress Setup
cd /var/www/html
echo "This is a test file" > indextest.html

sudo yum install -y wget
wget https://wordpress.org/wordpress-6.3.1.tar.gz
tar -xzf wordpress-6.3.1.tar.gz
cp -r wordpress/* /var/www/html/

rm -rf wordpress wordpress-6.3.1.tar.gz

chmod -R 755 wp-content
chown -R apache:apache wp-content

# WordPress Configuration
mv wp-config-sample.php wp-config.php

sed -i "s@define( 'DB_NAME', 'database_name_here' )@define( 'DB_NAME', '${var.db_name}' )@g" wp-config.php
sed -i "s@define( 'DB_USER', 'username_here' )@define( 'DB_USER', '${var.db_username}' )@g" wp-config.php
sed -i "s@define( 'DB_PASSWORD', 'password_here' )@define( 'DB_PASSWORD', '${var.db_password}' )@g" wp-config.php
sed -i "s@define( 'DB_HOST', 'localhost' )@define( 'DB_HOST', '${element(split(":", aws_db_instance.wordpress_db.endpoint), 0)}' )@g" wp-config.php

# Apache AllowOverride (Permalinks)
sudo sed -i -e '154aAllowOverride All' -e '154d' /etc/httpd/conf/httpd.conf

# CloudFront Media Rewrite
cat <<EOT > /var/www/html/.htaccess
Options +FollowSymlinks
RewriteEngine on
RewriteRule ^wp-content/uploads/(.*)$ https://${data.aws_cloudfront_distribution.cloudfront.domain_name}/\$1 [r=301,NC,L]
# BEGIN WordPress
# END WordPress
EOT

# S3 Sync (Code & Media)
aws s3 cp --recursive /var/www/html/ s3://code-bucket
aws s3 sync /var/www/html/ s3://code-bucket

echo "* * * * * ec2-user /usr/local/bin/aws s3 sync s3://code-bucket /var/www/html/" | sudo tee -a /etc/crontab
echo "* * * * * ec2-user /usr/local/bin/aws s3 sync /var/www/html/wp-content/uploads/ s3://set25-media-bucket1" | sudo tee -a /etc/crontab

sudo systemctl enable httpd
sudo systemctl start httpd

# SELinux Fix
sudo setenforce 0
sudo sed -i 's/^SELINUX=enforcing/SELINUX=permissive/' /etc/selinux/config
# Set Hostname
sudo hostnamectl set-hostname webserver
EOF
}
