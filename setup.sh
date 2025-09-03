#!/bin/bash
# Setup script for IDS project

echo "Setting up Intrusion Detection System..."

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (use sudo)"
    exit 1
fi

# Update package list
echo "Updating package list..."
apt-get update

# Install Python dependencies
echo "Installing Python dependencies..."
pip3 install -r requirements.txt

# Install system dependencies
echo "Installing system dependencies..."
apt-get install -y python3-pyqt5 python3-scapy python3-psutil

# Make scripts executable
echo "Making scripts executable..."
chmod +x blue-wix
chmod +x test_attacks.py

# Create log directory
echo "Creating log directory..."
mkdir -p logs

# Set up log rotation (optional)
echo "Setting up log rotation..."
cat > /etc/logrotate.d/ids << EOF
/home/kali/Downloads/IDS/ids.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    create 644 root root
}
EOF

echo "Setup completed successfully!"
echo ""
echo "Usage:"
echo "  GUI Mode:     sudo python3 ids_gui.py"
echo "  CLI Mode:     sudo ./blue-wix start"
echo "  Test Attacks: sudo ./test_attacks.py"
echo ""
echo "Note: Root privileges are required for packet capture."
