#!/bin/bash

# Bug-Hunting-Arsenal Tool Installation Script
echo "🏹 Setting up Bug-Hunting-Arsenal tools..."

# Update system
sudo apt update

# Install essential tools
echo "Installing essential tools..."
sudo apt install -y curl wget git python3 python3-pip golang-go nodejs npm

# Install common bug hunting tools
echo "Installing bug hunting tools..."
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# Install Python tools
pip3 install requests beautifulsoup4 dnspython

echo "✅ Basic tool setup complete!"
echo "📁 Don't forget to add ~/go/bin to your PATH"
