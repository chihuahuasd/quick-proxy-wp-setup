#!/bin/bash

# Multi-Domain Dedicated Proxy Server Setup Script
# Run this on each proxy server
# Usage: ./setup_dedicated_proxy.sh "domain1.com:backend_ip1,domain2.com:backend_ip2"

if [ $# -ne 1 ]; then
    echo "Usage: $0 '<domain1:ip1,domain2:ip2>'"
    echo "Example: ./setup_dedicated_proxy.sh 'mystore.com:10.0.0.100,blog.com:10.0.0.101'"
    exit 1
fi

# Parse domain configurations
DOMAIN_CONFIGS="$1"
DOMAINS=()
BACKEND_IPS=()

# Split configurations and validate
IFS=',' read -ra CONFIGS <<< "$DOMAIN_CONFIGS"
for config in "${CONFIGS[@]}"; do
    if [[ $config =~ ^([^:]+):([^:]+)$ ]]; then
        DOMAINS+=("${BASH_REMATCH[1]}")
        BACKEND_IPS+=("${BASH_REMATCH[2]}")
    else
        echo "Error: Invalid format '$config'. Use 'domain:ip' format."
        exit 1
    fi
done

if [ ${#DOMAINS[@]} -eq 0 ]; then
    echo "Error: No valid domain configurations found."
    exit 1
fi
PROXY_USER="squid"
PROXY_PASS="squid"

echo "🚀 Setting up multi-domain dedicated proxy server"
echo "Domains and backends:"
for i in "${!DOMAINS[@]}"; do
    echo "  ${DOMAINS[$i]} → ${BACKEND_IPS[$i]}"
done
echo "Proxy Credentials: $PROXY_USER:$PROXY_PASS"

# Update system
sudo apt update && sudo apt upgrade -y

# Install required packages
sudo apt install -y nginx certbot python3-certbot-nginx squid apache2-utils ufw fail2ban

echo "✓ Packages installed"

# === NGINX REVERSE PROXY SETUP ===
echo "📝 Configuring Nginx reverse proxy for multiple domains..."

# Add rate limiting to nginx.conf (create zones for each domain)
for domain in "${DOMAINS[@]}"; do
    domain_safe=$(echo "$domain" | sed 's/[^a-zA-Z0-9]/_/g')
    sudo sed -i "/http {/a\    limit_req_zone \$binary_remote_addr zone=${domain_safe}:10m rate=10r/s;" /etc/nginx/nginx.conf
done

# Remove default site
sudo rm -f /etc/nginx/sites-enabled/default

# Create HTTP configuration for each domain (for SSL certificate)
for i in "${!DOMAINS[@]}"; do
    domain="${DOMAINS[$i]}"
    echo "Creating initial HTTP config for $domain..."
    
    sudo tee "/etc/nginx/sites-available/$domain" > /dev/null <<EOF
server {
    listen 80;
    server_name $domain;
    
    # ACME challenge for Let's Encrypt
    location /.well-known/acme-challenge/ {
        root /var/www/html;
        try_files \$uri \$uri/ =404;
    }
    
    # Redirect HTTP to HTTPS
    location / {
        return 301 https://\$server_name\$request_uri;
    }
}

# HTTPS configuration will be added after SSL certificate
EOF
    
    # Enable site
    sudo ln -sf "/etc/nginx/sites-available/$domain" "/etc/nginx/sites-enabled/$domain"
done

# Test nginx configuration
if sudo nginx -t; then
    sudo systemctl restart nginx
    echo "✓ Nginx configured and restarted for all domains"
else
    echo "❌ Nginx configuration error"
    exit 1
fi

# === SSL CERTIFICATE INSTALLATION ===
echo "🔐 Installing SSL certificates for all domains..."

# Create ACME challenge directory
sudo mkdir -p /var/www/html/.well-known/acme-challenge/
sudo chown -R www-data:www-data /var/www/html/

# Install SSL certificates for each domain
SSL_SUCCESS=()
for i in "${!DOMAINS[@]}"; do
    domain="${DOMAINS[$i]}"
    echo "Installing SSL certificate for $domain..."
    if sudo certbot --nginx -d "$domain" --non-interactive --agree-tos --email "admin@$domain"; then
        echo "✓ SSL certificate installed successfully for $domain"
        SSL_SUCCESS[$i]=true
    else
        echo "⚠️ SSL certificate installation failed for $domain - continuing with HTTP only"
        SSL_SUCCESS[$i]=false
    fi
done

# === NGINX HTTPS CONFIGURATION ===
echo "📝 Updating Nginx configuration for HTTPS..."

# Create HTTPS configuration for each domain
for i in "${!DOMAINS[@]}"; do
    domain="${DOMAINS[$i]}"
    backend_ip="${BACKEND_IPS[$i]}"
    domain_safe=$(echo "$domain" | sed 's/[^a-zA-Z0-9]/_/g')
    
    echo "Configuring HTTPS for $domain → $backend_ip"
    
    if [ "${SSL_SUCCESS[$i]}" = true ]; then
        # Create complete HTTPS configuration
        sudo tee "/etc/nginx/sites-available/$domain" > /dev/null <<EOF
server {
    listen 80;
    server_name $domain;
    
    # ACME challenge for Let's Encrypt
    location /.well-known/acme-challenge/ {
        root /var/www/html;
        try_files \$uri \$uri/ =404;
    }
    
    # Redirect HTTP to HTTPS
    location / {
        return 301 https://\$server_name\$request_uri;
    }
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name $domain;

    # SSL configuration
    ssl_certificate /etc/letsencrypt/live/$domain/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$domain/privkey.pem;
    
    # SSL settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    
    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains";
    
    location / {
        # Rate limiting
        limit_req zone=${domain_safe} burst=20 nodelay;
        
        proxy_pass http://$backend_ip;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Forwarded-Host \$server_name;
        
        # Proxy timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        
        # Buffer settings
        proxy_buffering on;
        proxy_buffer_size 128k;
        proxy_buffers 4 256k;
        proxy_busy_buffers_size 256k;
        
        # Don't proxy server errors
        proxy_redirect off;
    }
    
    # Cache static files
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot|pdf|zip)$ {
        proxy_pass http://$backend_ip;
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-Proto \$scheme;
        expires 1y;
        add_header Cache-Control "public, immutable";
        access_log off;
    }
    
    # Block access to sensitive files
    location ~* \.(htaccess|htpasswd|ini|log|sh|sql|conf)\$ {
        deny all;
        return 404;
    }
}
EOF
    else
        # Create HTTP-only configuration
        sudo tee "/etc/nginx/sites-available/$domain" > /dev/null <<EOF
server {
    listen 80;
    server_name $domain;
    
    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    
    # ACME challenge for Let's Encrypt
    location /.well-known/acme-challenge/ {
        root /var/www/html;
        try_files \$uri \$uri/ =404;
    }
    
    location / {
        # Rate limiting
        limit_req zone=${domain_safe} burst=20 nodelay;
        
        proxy_pass http://$backend_ip;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Forwarded-Host \$server_name;
        
        # Proxy timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        
        # Buffer settings
        proxy_buffering on;
        proxy_buffer_size 128k;
        proxy_buffers 4 256k;
        proxy_busy_buffers_size 256k;
        
        # Don't proxy server errors
        proxy_redirect off;
    }
    
    # Cache static files
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot|pdf|zip)$ {
        proxy_pass http://$backend_ip;
        proxy_set_header Host \$host;
        expires 1y;
        add_header Cache-Control "public, immutable";
        access_log off;
    }
    
    # Block access to sensitive files
    location ~* \.(htaccess|htpasswd|ini|log|sh|sql|conf)\$ {
        deny all;
        return 404;
    }
}
EOF
    fi
done

# Test and reload nginx
if sudo nginx -t; then
    sudo systemctl reload nginx
    echo "✓ Nginx HTTPS configuration updated for all domains"
else
    echo "❌ Nginx configuration error"
    exit 1
fi

# === SQUID FORWARD PROXY SETUP ===
echo "📝 Configuring Squid forward proxy..."

# Backup original squid config
sudo cp /etc/squid/squid.conf /etc/squid/squid.conf.backup

sudo tee /etc/squid/squid.conf > /dev/null <<EOF
# Squid configuration for multi-domain proxy
# Port configuration
http_port 3128

# Authentication
auth_param basic program /usr/lib/squid/basic_ncsa_auth /etc/squid/passwd
auth_param basic realm Squid Multi-Domain Proxy
auth_param basic credentialsttl 2 hours
auth_param basic casesensitive off

# Access control lists
acl authenticated proxy_auth REQUIRED
acl localnet src 10.0.0.0/8
acl localnet src 172.16.0.0/12
acl localnet src 192.168.0.0/16
acl localnet src fc00::/7
acl localnet src fe80::/10

# WordPress backend access
EOF

# Add ACL for each backend IP
for backend_ip in "${BACKEND_IPS[@]}"; do
    echo "acl backend_server src $backend_ip" | sudo tee -a /etc/squid/squid.conf > /dev/null
done

# Continue with rest of squid config
sudo tee -a /etc/squid/squid.conf > /dev/null <<EOF

# Safe ports and SSL ports
acl SSL_ports port 443
acl Safe_ports port 80
acl Safe_ports port 21
acl Safe_ports port 443
acl Safe_ports port 70
acl Safe_ports port 210
acl Safe_ports port 1025-65535
acl Safe_ports port 280
acl Safe_ports port 488
acl Safe_ports port 591
acl Safe_ports port 777
acl CONNECT method CONNECT

# Access rules
http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports
http_access allow localhost manager
http_access deny manager
http_access allow authenticated
http_access allow backend_server
http_access allow localnet
http_access allow localhost
http_access deny all

# Logging
access_log /var/log/squid/access.log squid
cache_log /var/log/squid/cache.log

# Cache settings optimized for WordPress
cache_dir ufs /var/spool/squid 500 16 256
maximum_object_size 50 MB
cache_mem 256 MB

# DNS settings
dns_nameservers 8.8.8.8 1.1.1.1

# Refresh patterns for WordPress content
refresh_pattern ^ftp:           1440    20%     10080
refresh_pattern ^gopher:        1440    0%      1440
refresh_pattern -i (/cgi-bin/|\?) 0     0%      0
refresh_pattern \.(jpg|png|gif|jpeg|ico|svg|css|js|woff|woff2|ttf|eot)$ 1440 80% 10080 override-expire ignore-reload
refresh_pattern .               0       20%     4320

# Security
forwarded_for on
via on
httpd_suppress_version_string on

# Performance tuning
pipeline_prefetch on
range_offset_limit 200 MB
quick_abort_min 0 KB
quick_abort_max 0 KB
EOF

# Create proxy user with fixed password squid:squid
echo "$PROXY_USER:$(openssl passwd -apr1 $PROXY_PASS)" | sudo tee /etc/squid/passwd
sudo chown proxy:proxy /etc/squid/passwd
sudo chmod 640 /etc/squid/passwd

# Start squid
sudo systemctl restart squid
sudo systemctl enable squid
echo "✓ Squid configured and started"

# === FIREWALL SETUP ===
echo "🔒 Configuring firewall..."

sudo ufw --force reset
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow essential services
sudo ufw allow 22/tcp comment 'SSH'
sudo ufw allow 80/tcp comment 'HTTP'
sudo ufw allow 443/tcp comment 'HTTPS'
sudo ufw allow 3128/tcp comment 'Squid Proxy'

# Allow backend servers
for i in "${!BACKEND_IPS[@]}"; do
    backend_ip="${BACKEND_IPS[$i]}"
    domain="${DOMAINS[$i]}"
    sudo ufw allow from "$backend_ip" comment "Backend for $domain"
done

sudo ufw --force enable
echo "✓ Firewall configured"

# === FAIL2BAN SETUP ===
echo "🛡️ Configuring Fail2Ban..."

sudo tee /etc/fail2ban/jail.local > /dev/null <<EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5

[sshd]
enabled = true

[nginx-http-auth]
enabled = true

[nginx-limit-req]
enabled = true
filter = nginx-limit-req
action = iptables-multiport[name=ReqLimit, port="http,https", protocol=tcp]
logpath = /var/log/nginx/error.log
findtime = 600
bantime = 7200
maxretry = 10

[squid]
enabled = true
port = 3128
filter = squid
logpath = /var/log/squid/access.log
maxretry = 3
EOF

sudo systemctl restart fail2ban
sudo systemctl enable fail2ban
echo "✓ Fail2Ban configured"

# === MONITORING SETUP ===
echo "📊 Setting up monitoring..."

# Create status check script
sudo tee /usr/local/bin/proxy-status.sh > /dev/null <<EOF
#!/bin/bash
echo "=== Multi-Domain Proxy Server Status ==="
echo "Date: \$(date)"
echo ""
echo "Configured Domains:"
EOF

# Add domain status checks
for i in "${!DOMAINS[@]}"; do
    domain="${DOMAINS[$i]}"
    backend_ip="${BACKEND_IPS[$i]}"
    echo "echo \"  $domain → $backend_ip\"" | sudo tee -a /usr/local/bin/proxy-status.sh > /dev/null
done

sudo tee -a /usr/local/bin/proxy-status.sh > /dev/null <<EOF
echo ""
echo "Nginx Status:"
systemctl is-active nginx
echo ""
echo "Squid Status:"
systemctl is-active squid
echo ""
echo "SSL Certificate Status:"
certbot certificates
echo ""
echo "Disk Usage:"
df -h /
echo ""
echo "Memory Usage:"
free -h
echo ""
echo "Recent Nginx Errors:"
tail -5 /var/log/nginx/error.log
echo ""
echo "Recent Squid Activity:"
tail -5 /var/log/squid/access.log | awk '{print \$1, \$4, \$7}'
EOF

sudo chmod +x /usr/local/bin/proxy-status.sh

# Add to crontab for daily monitoring
first_domain="${DOMAINS[0]}"
echo "0 9 * * * /usr/local/bin/proxy-status.sh | mail -s 'Daily Multi-Domain Proxy Status' admin@$first_domain" | sudo crontab -

echo ""
echo "🎉 Multi-domain dedicated proxy server setup complete!"
echo ""
echo "=== CONFIGURATION SUMMARY ==="
echo "Proxy Server IP: $(curl -s ifconfig.me)"
echo "Configured domains and backends:"
for i in "${!DOMAINS[@]}"; do
    echo "  ${DOMAINS[$i]} → ${BACKEND_IPS[$i]}"
done
echo ""
echo "=== FORWARD PROXY CREDENTIALS ==="
echo "Host: $(curl -s ifconfig.me)"
echo "Port: 3128"
echo "Username: $PROXY_USER"
echo "Password: $PROXY_PASS"
echo ""
echo "=== NEXT STEPS ==="
for i in "${!DOMAINS[@]}"; do
    domain="${DOMAINS[$i]}"
    echo "$((i+1)). Update DNS: $domain → $(curl -s ifconfig.me)"
done
echo "$((${#DOMAINS[@]}+1)). Configure backend servers"
echo "$((${#DOMAINS[@]}+2)). Test HTTPS for each domain:"
for domain in "${DOMAINS[@]}"; do
    echo "    curl -I https://$domain"
done
echo "$((${#DOMAINS[@]}+3)). Test proxy: curl -x $PROXY_USER:$PROXY_PASS@$(curl -s ifconfig.me):3128 https://httpbin.org/ip"
echo ""
echo "=== CREDENTIALS SUMMARY ==="
echo "Forward Proxy: $PROXY_USER:$PROXY_PASS@$(curl -s ifconfig.me):3128"
echo "SSL Status:"
for i in "${!DOMAINS[@]}"; do
    domain="${DOMAINS[$i]}"
    if [ "${SSL_SUCCESS[$i]}" = true ]; then
        echo "  $domain: ✓ Enabled"
    else
        echo "  $domain: ❌ Failed - retry with: sudo certbot --nginx -d $domain"
    fi
done
echo ""
