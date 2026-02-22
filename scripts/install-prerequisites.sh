#!/bin/bash
# SOVD Explorer - Prerequisites Installation Script
# Run this script to install system dependencies required for Tauri on Linux

set -e

echo "=== SOVD Explorer Prerequisites Installer ==="
echo ""

# Detect package manager
if command -v apt-get &> /dev/null; then
    PM="apt"
elif command -v dnf &> /dev/null; then
    PM="dnf"
elif command -v pacman &> /dev/null; then
    PM="pacman"
elif command -v zypper &> /dev/null; then
    PM="zypper"
else
    echo "Error: Could not detect package manager"
    echo "Please install the following packages manually:"
    echo "  - GTK 3 development libraries"
    echo "  - WebKit2GTK 4.1 development libraries"
    echo "  - libayatana-appindicator (or libappindicator)"
    echo "  - librsvg2 development libraries"
    exit 1
fi

echo "Detected package manager: $PM"
echo ""

case $PM in
    apt)
        echo "Installing dependencies for Debian/Ubuntu..."
        sudo apt-get update
        sudo apt-get install -y \
            libwebkit2gtk-4.1-dev \
            libgtk-3-dev \
            libayatana-appindicator3-dev \
            librsvg2-dev \
            libssl-dev \
            libjavascriptcoregtk-4.1-dev \
            libsoup-3.0-dev \
            build-essential \
            curl \
            wget \
            file \
            patchelf
        ;;
    dnf)
        echo "Installing dependencies for Fedora..."
        sudo dnf install -y \
            webkit2gtk4.1-devel \
            gtk3-devel \
            libappindicator-gtk3-devel \
            librsvg2-devel \
            openssl-devel \
            javascriptcoregtk4.1-devel \
            libsoup3-devel \
            @development-tools
        ;;
    pacman)
        echo "Installing dependencies for Arch Linux..."
        sudo pacman -Syu --needed \
            webkit2gtk-4.1 \
            gtk3 \
            libayatana-appindicator \
            librsvg \
            openssl \
            base-devel
        ;;
    zypper)
        echo "Installing dependencies for openSUSE..."
        sudo zypper install -y \
            webkit2gtk3-devel \
            gtk3-devel \
            libappindicator3-devel \
            librsvg-devel \
            libopenssl-devel \
            -t pattern devel_basis
        ;;
esac

echo ""
echo "=== Prerequisites installed successfully ==="
echo ""
echo "You can now build the project:"
echo "  npm run tauri dev    # Development mode"
echo "  npm run tauri build  # Production build"
