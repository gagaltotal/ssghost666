#!/bin/bash

# SSGhost666 Installation Script
# Supports: Ubuntu/Debian, Fedora/RHEL/CentOS, Arch Linux, openSUSE, Alpine, and more
# Usage: sudo ./install.sh

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   error "This script must be run as root (use sudo)"
fi

info "SSGhost666 Installation Script"
info "================================"

# Detect OS and package manager
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    VER=$VERSION_ID
else
    error "Cannot detect OS. /etc/os-release not found."
fi

info "Detected OS: $OS $VER"

# Function to install Go
install_go() {
    if command -v go &> /dev/null; then
        GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
        info "Go is already installed (version $GO_VERSION)"
        
        # Check if version is 1.23 or higher
        REQUIRED_VERSION="1.23"
        if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$GO_VERSION" | sort -V | head -n1)" = "$REQUIRED_VERSION" ]; then
            return 0
        else
            warn "Go version $GO_VERSION is too old. Upgrading to 1.23+..."
        fi
    fi

    info "Installing Go 1.23..."
    
    # Determine architecture
    ARCH=$(uname -m)
    case $ARCH in
        x86_64)
            GO_ARCH="amd64"
            ;;
        aarch64|arm64)
            GO_ARCH="arm64"
            ;;
        armv7l)
            GO_ARCH="armv6l"
            ;;
        *)
            error "Unsupported architecture: $ARCH"
            ;;
    esac

    GO_VERSION="1.23.5"
    GO_TARBALL="go${GO_VERSION}.linux-${GO_ARCH}.tar.gz"
    
    cd /tmp
    wget -q "https://go.dev/dl/${GO_TARBALL}" || error "Failed to download Go"
    
    # Remove old Go installation if exists
    rm -rf /usr/local/go
    
    tar -C /usr/local -xzf "${GO_TARBALL}"
    rm "${GO_TARBALL}"
    
    # Add Go to PATH if not already there
    if ! grep -q '/usr/local/go/bin' /etc/profile; then
        echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
    fi
    
    export PATH=$PATH:/usr/local/go/bin
    
    info "Go installed successfully: $(go version)"
}

# Function to install Chrome/Chromium (optional, for JS rendering features)
install_chrome() {
    if command -v google-chrome &> /dev/null || command -v chromium &> /dev/null || command -v chromium-browser &> /dev/null; then
        info "Chrome/Chromium is already installed"
        return 0
    fi

    warn "Chrome/Chromium not found. Installing for JS rendering features..."
    
    case $OS in
        ubuntu|debian|linuxmint|pop)
            apt-get update -qq
            apt-get install -y chromium-browser || apt-get install -y chromium
            ;;
        fedora|rhel|centos|rocky|almalinux)
            if [ "$OS" = "fedora" ]; then
                dnf install -y chromium
            else
                dnf install -y epel-release
                dnf install -y chromium
            fi
            ;;
        arch|manjaro)
            pacman -S --noconfirm chromium
            ;;
        opensuse*|sles)
            zypper install -y chromium
            ;;
        alpine)
            apk add --no-cache chromium
            ;;
        *)
            warn "Chrome/Chromium installation not configured for $OS. Please install manually if you need JS rendering features (-js-render, -dom-xss)."
            ;;
    esac
}

# Function to install dependencies based on distro
install_dependencies() {
    info "Installing system dependencies..."
    
    case $OS in
        ubuntu|debian|linuxmint|pop)
            apt-get update -qq
            apt-get install -y wget curl git build-essential
            ;;
        fedora|rhel|centos|rocky|almalinux)
            if [ "$OS" = "fedora" ]; then
                dnf install -y wget curl git gcc make
            else
                yum install -y wget curl git gcc make
            fi
            ;;
        arch|manjaro)
            pacman -Sy --noconfirm wget curl git base-devel
            ;;
        opensuse*|sles)
            zypper refresh
            zypper install -y wget curl git gcc make
            ;;
        alpine)
            apk update
            apk add --no-cache wget curl git gcc musl-dev make
            ;;
        void)
            xbps-install -Sy wget curl git gcc make
            ;;
        gentoo)
            emerge --sync
            emerge wget curl git
            ;;
        *)
            warn "Unknown distribution: $OS. Attempting generic installation..."
            ;;
    esac
    
    info "Dependencies installed"
}

# Function to build and install SSGhost666
install_ssghost666() {
    info "Building SSGhost666..."
    
    # Get current directory
    SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
    
    cd "$SCRIPT_DIR"
    
    # Check if go.mod exists
    if [ ! -f "go.mod" ]; then
        error "go.mod not found. Please run this script from the SSGhost666 source directory."
    fi
    
    # Build
    info "Compiling (this may take a minute)..."
    go build -ldflags="-s -w" -o ssghost666 . || error "Build failed"
    
    # Install to /usr/local/bin
    info "Installing to /usr/local/bin..."
    cp ssghost666 /usr/local/bin/ssghost666
    chmod +x /usr/local/bin/ssghost666
    
    # Create config directory
    mkdir -p /etc/ssghost666
    
    # Copy example files if they exist
    [ -f "auth-flow-example.json" ] && cp auth-flow-example.json /etc/ssghost666/
    [ -f "jslibs-db-example.json" ] && cp jslibs-db-example.json /etc/ssghost666/
    
    info "SSGhost666 installed successfully!"
}

# Main installation flow
main() {
    install_dependencies
    install_go
    install_chrome
    install_ssghost666
    
    echo ""
    info "==============================================="
    info "Installation complete!"
    info "==============================================="
    info ""
    info "Usage: ssghost666 -url https://target.com"
    info "Help:  ssghost666 -h"
    info ""
    info "Example configurations:"
    info "  - Auth flow: /etc/ssghost666/auth-flow-example.json"
    info "  - JS libs DB: /etc/ssghost666/jslibs-db-example.json"
    info ""
    info "IMPORTANT: Only scan applications you own or have"
    info "           explicit authorization to test."
    info ""
}

main
