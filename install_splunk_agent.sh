#!/bin/bash
# wget -O splunkforwarder-9.4.0-6b4ebe426ca6-linux-amd64.tgz "https://download.splunk.com/products/universalforwarder/releases/9.4.0/linux/splunkforwarder-9.4.0-6b4ebe426ca6-linux-amd64.tgz"
# Tên file và URL cho phiên bản x86_64
SPLUNK_URL="https://download.splunk.com/products/universalforwarder/releases/9.4.0/linux/splunkforwarder-9.4.0-6b4ebe426ca6-linux-amd64.tgz"
SPLUNK_FILE="splunkforwarder-9.4.0-6b4ebe426ca6-linux-amd64.tgz"
SPLUNK_DIR="/opt/splunkforwarder"
ADMIN_USER="admin"
ADMIN_PASS="Admin@123!"
DEPLOY_POLL="10.25.14.10:8089"
FORWARD_SERVER="10.25.14.16:9997"
SPLUNK_OS_USER="splunk"

# Kiểm tra nếu người dùng hệ điều hành cho Splunk đã tồn tại, nếu không tạo người dùng mới
if id "$SPLUNK_OS_USER" &>/dev/null; then
    echo "User $SPLUNK_OS_USER already exists."
else
    echo "Creating Splunk OS user..."
    useradd -m -d /home/$SPLUNK_OS_USER -s /bin/bash $SPLUNK_OS_USER
    echo "User $SPLUNK_OS_USER created."
fi

# Kiểm tra nếu Splunk đã được cài đặt
if [ -d "$SPLUNK_DIR" ]; then
    echo "Splunk Universal Forwarder is already installed. Removing old version..."
    # Dừng Splunk nếu đang chạy
    $SPLUNK_DIR/bin/splunk stop

    # Gỡ bỏ Splunk
    rm -rf $SPLUNK_DIR
    echo "Old Splunk Universal Forwarder removed."
fi

# Tải xuống Splunk Universal Forwarder cho x86_64
echo "Downloading Splunk Universal Forwarder..."
wget -O $SPLUNK_FILE $SPLUNK_URL

# Giải nén file tar vào /opt/
echo "Extracting Splunk Universal Forwarder..."
tar -xzvf $SPLUNK_FILE -C /opt/

# Đặt quyền cho thư mục Splunk cho người dùng hệ điều hành splunk
echo "Setting executable permissions for Splunk directory..."
chown -R $SPLUNK_OS_USER:$SPLUNK_OS_USER $SPLUNK_DIR
chmod -R 777 $SPLUNK_DIR

# Tạo tệp user-seed.conf để tạo tài khoản admin với mật khẩu
echo "Creating user-seed.conf for admin setup..."
cat <<EOT > $SPLUNK_DIR/etc/system/local/user-seed.conf
[user_info]
USERNAME = $ADMIN_USER
PASSWORD = $ADMIN_PASS
EOT

# Khởi tạo Splunk với cấu hình mặc định và chấp nhận license
echo "Initializing Splunk as user $SPLUNK_OS_USER..."
sudo -u $SPLUNK_OS_USER $SPLUNK_DIR/bin/splunk start --accept-license --answer-yes --no-prompt

# Đảm bảo Splunk tự khởi động khi khởi động lại hệ thống
echo "Setting Splunk to start at boot..."
sudo -u $SPLUNK_OS_USER $SPLUNK_DIR/bin/splunk enable boot-start -user $SPLUNK_OS_USER

# Cấu hình deploy-poll tới địa chỉ 10.57.30.11:8089
echo "Setting deploy-poll..."
sudo -u $SPLUNK_OS_USER $SPLUNK_DIR/bin/splunk set deploy-poll $DEPLOY_POLL -auth $ADMIN_USER:$ADMIN_PASS

# Thêm forward-server tới địa chỉ 10.57.30.11:9997
echo "Adding forward-server..."
sudo -u $SPLUNK_OS_USER $SPLUNK_DIR/bin/splunk add forward-server $FORWARD_SERVER -auth $ADMIN_USER:$ADMIN_PASS

# Khởi động lại Splunk để áp dụng cấu hình mới
echo "Restarting Splunk..."
sudo -u $SPLUNK_OS_USER $SPLUNK_DIR/bin/splunk restart

# Kiểm tra trạng thái Splunk
echo "Checking Splunk status..."
sudo -u $SPLUNK_OS_USER $SPLUNK_DIR/bin/splunk status

echo "Splunk Universal Forwarder installation and configuration completed!"

