#!/bin/bash

# WordPress Backend Configuration for Dedicated Proxy
# Run this on each WordPress server
# Usage: ./setup_wp_backend.sh domain.com proxy_ip proxy_user proxy_pass

if [ $# -ne 4 ]; then
    echo "Usage: $0 <domain> <proxy_ip> <proxy_user> <proxy_pass>"
    echo "Example: ./setup_wp_backend.sh mystore.com 203.0.113.1 squid mypassword123"
    exit 1
fi

DOMAIN=$1
PROXY_IP=$2
PROXY_USER=$3
PROXY_PASS=$4
WP_CONFIG="/var/www/html/wp-config.php"
DB_NAME=$(grep DB_NAME $WP_CONFIG 2>/dev/null | cut -d"'" -f4 || echo "wordpress")

echo "🚀 Configuring WordPress backend for dedicated proxy"
echo "Domain: $DOMAIN"
echo "Proxy IP: $PROXY_IP"
echo "Database: $DB_NAME"

# Update system
sudo apt update

# Install required packages
sudo apt install -y apache2 mysql-server php libapache2-mod-php php-mysql php-curl php-gd php-xml php-mbstring php-zip unzip curl wget

echo "✓ Packages installed"

# === BACKUP CURRENT CONFIGURATION ===
echo "💾 Creating backups..."

sudo cp $WP_CONFIG $WP_CONFIG.backup.$(date +%s) 2>/dev/null || echo "No existing wp-config.php found"
sudo cp /etc/apache2/sites-available/000-default.conf /etc/apache2/sites-available/000-default.conf.backup

echo "✓ Backups created"


# === APACHE CONFIGURATION ===
echo "📝 Configuring Apache..."

sudo tee /etc/apache2/sites-available/000-default.conf > /dev/null <<EOF
<VirtualHost *:80>
    ServerName $DOMAIN
    ServerAlias www.$DOMAIN
    DocumentRoot /var/www/html
    
    # Handle reverse proxy headers
    RemoteIPHeader X-Real-IP
    RemoteIPTrustedProxy $PROXY_IP
    
    # Set environment variables for HTTPS
    SetEnvIf X-Forwarded-Proto "https" HTTPS=on
    SetEnvIf X-Forwarded-Proto "https" REQUEST_SCHEME=https
    
    # Security headers
    Header always set X-Content-Type-Options nosniff
    Header always set X-Frame-Options DENY
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
    
    # Hide server information
    ServerTokens Prod
    Header unset Server
    
    # Performance settings
    <IfModule mod_deflate.c>
        AddOutputFilterByType DEFLATE text/html text/plain text/xml text/css text/javascript application/javascript application/x-javascript
    </IfModule>
    
    # Cache control for static files
    <IfModule mod_expires.c>
        ExpiresActive On
        ExpiresByType text/css "access plus 1 year"
        ExpiresByType application/javascript "access plus 1 year"
        ExpiresByType image/png "access plus 1 year"
        ExpiresByType image/jpg "access plus 1 year"
        ExpiresByType image/jpeg "access plus 1 year"
        ExpiresByType image/gif "access plus 1 year"
        ExpiresByType image/ico "access plus 1 year"
        ExpiresByType image/svg+xml "access plus 1 year"
    </IfModule>
    
    # Security: Block access to sensitive files
    <FilesMatch "\.(htaccess|htpasswd|ini|log|sh|sql|conf)$">
        Require all denied
    </FilesMatch>
    
    # WordPress specific rules
    <Directory "/var/www/html">
        AllowOverride All
        Require all granted
        
        # Prevent access to wp-config.php
        <Files wp-config.php>
            Require all denied
        </Files>
    </Directory>
    
    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
EOF

# Enable required Apache modules
sudo a2enmod rewrite
sudo a2enmod headers
sudo a2enmod remoteip
sudo a2enmod deflate
sudo a2enmod expires
sudo a2enmod ssl

# Test Apache configuration
if sudo apache2ctl configtest; then
    sudo systemctl restart apache2
    echo "✓ Apache configured and restarted"
else
    echo "❌ Apache configuration error"
    exit 1
fi

# === FIREWALL CONFIGURATION ===
echo "🔒 Configuring firewall..."

sudo ufw --force reset
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow only proxy server and SSH
sudo ufw allow 22/tcp comment 'SSH'
sudo ufw allow from $PROXY_IP to any port 80 comment 'HTTP from Proxy'
sudo ufw allow from $PROXY_IP to any port 443 comment 'HTTPS from Proxy'

sudo ufw --force enable
echo "✓ Firewall configured - only proxy server can access web ports"

# === DATABASE CONFIGURATION ===
echo "💾 Updating WordPress database..."

if command -v mysql &> /dev/null; then
    # Update WordPress database URLs
    mysql -e "
    USE $DB_NAME;
    UPDATE wp_options SET option_value = 'https://$DOMAIN' WHERE option_name = 'home';
    UPDATE wp_options SET option_value = 'https://$DOMAIN' WHERE option_name = 'siteurl';
    " 2>/dev/null && echo "✓ Database URLs updated" || echo "⚠️ Database update failed - update manually"
else
    echo "⚠️ MySQL not found - update database URLs manually"
fi

# === PHP OPTIMIZATION ===
echo "⚡ Optimizing PHP..."

# Update PHP settings for WordPress
sudo tee /etc/php/*/apache2/conf.d/99-wordpress.ini > /dev/null <<EOF
; WordPress optimizations
memory_limit = 256M
max_execution_time = 300
max_input_vars = 3000
upload_max_filesize = 64M
post_max_size = 64M
max_file_uploads = 20

; Security
expose_php = Off
display_errors = Off
log_errors = On
allow_url_fopen = Off
allow_url_include = Off

; Performance
opcache.enable = 1
opcache.memory_consumption = 128
opcache.interned_strings_buffer = 8
opcache.max_accelerated_files = 4000
opcache.revalidate_freq = 2
opcache.fast_shutdown = 1
EOF

sudo systemctl restart apache2
echo "✓ PHP optimized"

# === MONITORING SCRIPT ===
echo "📊 Setting up monitoring..."

sudo tee /usr/local/bin/wp-status.sh > /dev/null <<EOF
#!/bin/bash
echo "=== WordPress Backend Status for $DOMAIN ==="
echo "Date: \$(date)"
echo ""
echo "Apache Status:"
systemctl is-active apache2
echo ""
echo "MySQL Status:"
systemctl is-active mysql
echo ""
echo "Disk Usage:"
df -h /var/www/html
echo ""
echo "WordPress Database Size:"
mysql -e "SELECT table_schema AS 'Database', ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) AS 'Size (MB)' FROM information_schema.tables WHERE table_schema='$DB_NAME';" 2>/dev/null
echo ""
echo "Recent Apache Errors:"
tail -5 /var/log/apache2/error.log
echo ""
echo "WordPress Error Log:"
tail -5 /var/www/html/wp-content/debug.log 2>/dev/null || echo "No WordPress error log"
echo ""
echo "Proxy Connection Test:"
curl -s -x $PROXY_USER:$PROXY_PASS@$PROXY_IP:3128 https://httpbin.org/ip | grep origin || echo "Proxy connection failed"
EOF

sudo chmod +x /usr/local/bin/wp-status.sh

# === FILE PERMISSIONS ===
echo "🔧 Setting proper file permissions..."

# Set WordPress file permissions
sudo chown -R www-data:www-data /var/www/html/
sudo find /var/www/html/ -type d -exec chmod 755 {} \;
sudo find /var/www/html/ -type f -exec chmod 644 {} \;
sudo chmod 600 /var/www/html/wp-config.php

echo "✓ File permissions set"

# === WORDPRESS PLUGINS RECOMMENDATION ===
echo "🔌 WordPress plugin recommendations for proxy setup..."

cat << EOF

=== RECOMMENDED WORDPRESS PLUGINS ===
1. Really Simple SSL - Handle SSL redirects
2. WP Rocket or W3 Total Cache - Performance optimization
3. Wordfence Security - Security enhancement
4. UpdraftPlus - Backup solution
5. Yoast SEO - SEO optimization

Install these through WordPress admin dashboard.
EOF

echo ""
echo "🎉 WordPress backend configuration complete!"
echo ""
echo "=== CONFIGURATION SUMMARY ==="
echo "Domain: $DOMAIN"
echo "Proxy Server: $PROXY_IP"
echo "WordPress Path: /var/www/html"
echo ""
echo "=== PROXY CONFIGURATION ===
echo "Forward Proxy: $PROXY_USER:$PROXY_PASS@$PROXY_IP:3128"
echo ""
echo "=== TESTING ==="
echo "1. Test WordPress: curl -H 'Host: $DOMAIN' http://$(hostname -I | awk '{print $1}')"
echo "2. Test proxy: curl -x $PROXY_USER:$PROXY_PASS@$PROXY_IP:3128 https://httpbin.org/ip"
echo "3. Check status: /usr/local/bin/wp-status.sh"
echo ""
echo "=== NEXT STEPS ==="
echo "1. Verify WordPress is accessible from proxy server"
echo "2. Install recommended WordPress plugins"
echo "3. Configure WordPress theme and content"
echo "4. Set up regular backups"
echo ""