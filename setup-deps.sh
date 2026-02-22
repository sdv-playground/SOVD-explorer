#!/bin/bash
# =============================================================================
# SOVD Explorer - Dependency Setup Script
#
# Installs all system-level and toolchain dependencies required to build and
# run the SOVD Explorer Tauri application.
#
# Supported: Ubuntu/Debian, Fedora, Arch Linux, openSUSE
# Usage:     chmod +x setup-deps.sh && ./setup-deps.sh
# =============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "============================================="
echo "  SOVD Explorer - Dependency Setup"
echo "============================================="
echo ""

# ---------------------------------------------------------------------------
# 1. Detect package manager
# ---------------------------------------------------------------------------
if command -v apt-get &> /dev/null; then
    PM="apt"
elif command -v dnf &> /dev/null; then
    PM="dnf"
elif command -v pacman &> /dev/null; then
    PM="pacman"
elif command -v zypper &> /dev/null; then
    PM="zypper"
else
    error "Could not detect a supported package manager."
    echo "  Install the following manually:"
    echo "    - pkg-config, build-essential / base-devel"
    echo "    - GTK 3 dev, WebKit2GTK 4.1 dev, libsoup 3 dev"
    echo "    - JavaScriptCoreGTK 4.1 dev, librsvg2 dev"
    echo "    - libayatana-appindicator dev, OpenSSL dev"
    echo "    - patchelf, curl, wget, file"
    exit 1
fi

info "Detected package manager: $PM"
echo ""

# ---------------------------------------------------------------------------
# 2. Install system libraries required by Tauri 2 on Linux
# ---------------------------------------------------------------------------
info "Installing system libraries for Tauri 2..."

case $PM in
    apt)
        sudo apt-get update
        sudo apt-get install -y \
            build-essential \
            curl \
            wget \
            file \
            patchelf \
            pkg-config \
            libglib2.0-dev \
            libgtk-3-dev \
            libwebkit2gtk-4.1-dev \
            libjavascriptcoregtk-4.1-dev \
            libsoup-3.0-dev \
            libayatana-appindicator3-dev \
            librsvg2-dev \
            libssl-dev \
            libpango1.0-dev \
            libcairo2-dev \
            libgdk-pixbuf-2.0-dev \
            libatk1.0-dev
        ;;
    dnf)
        sudo dnf install -y \
            @development-tools \
            curl \
            wget \
            file \
            patchelf \
            pkgconf-pkg-config \
            glib2-devel \
            gtk3-devel \
            webkit2gtk4.1-devel \
            javascriptcoregtk4.1-devel \
            libsoup3-devel \
            libappindicator-gtk3-devel \
            librsvg2-devel \
            openssl-devel \
            pango-devel \
            cairo-devel \
            gdk-pixbuf2-devel \
            atk-devel
        ;;
    pacman)
        sudo pacman -Syu --needed \
            base-devel \
            curl \
            wget \
            file \
            patchelf \
            pkgconf \
            glib2 \
            gtk3 \
            webkit2gtk-4.1 \
            libayatana-appindicator \
            librsvg \
            openssl \
            pango \
            cairo \
            gdk-pixbuf2 \
            atk
        ;;
    zypper)
        sudo zypper install -y \
            -t pattern devel_basis \
            curl \
            wget \
            file \
            patchelf \
            pkg-config \
            glib2-devel \
            gtk3-devel \
            webkit2gtk3-devel \
            libsoup3-devel \
            libappindicator3-devel \
            librsvg-devel \
            libopenssl-devel \
            pango-devel \
            cairo-devel \
            gdk-pixbuf-devel \
            atk-devel
        ;;
esac

echo ""

# ---------------------------------------------------------------------------
# 3. Verify / install Rust toolchain
# ---------------------------------------------------------------------------
if command -v rustc &> /dev/null; then
    RUST_VER=$(rustc --version)
    info "Rust already installed: $RUST_VER"
else
    warn "Rust not found. Installing via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
    info "Rust installed: $(rustc --version)"
fi

# ---------------------------------------------------------------------------
# 4. Verify / install Node.js & npm
# ---------------------------------------------------------------------------
if command -v node &> /dev/null && command -v npm &> /dev/null; then
    info "Node.js already installed: $(node --version), npm $(npm --version)"
else
    warn "Node.js / npm not found."
    echo "  Install Node.js >= 18 from https://nodejs.org or via nvm:"
    echo "    curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash"
    echo "    nvm install 18"
    exit 1
fi

# ---------------------------------------------------------------------------
# 5. Install Tauri CLI (if not present)
# ---------------------------------------------------------------------------
if npx tauri --version &> /dev/null 2>&1; then
    info "Tauri CLI available via npx"
else
    warn "Installing @tauri-apps/cli as a dev dependency..."
    cd "$SCRIPT_DIR"
    npm install --save-dev @tauri-apps/cli
fi

# ---------------------------------------------------------------------------
# 6. Install npm dependencies
# ---------------------------------------------------------------------------
info "Installing npm dependencies..."
cd "$SCRIPT_DIR"
npm install

# ---------------------------------------------------------------------------
# 7. Verify pkg-config can find the critical libraries
# ---------------------------------------------------------------------------
echo ""
info "Verifying pkg-config can locate required libraries..."

MISSING=0
for lib in glib-2.0 gobject-2.0 gio-2.0 gdk-3.0 gtk+-3.0 webkit2gtk-4.1 \
           javascriptcoregtk-4.1 libsoup-3.0 pango cairo gdk-pixbuf-2.0 \
           librsvg-2.0 openssl; do
    if pkg-config --exists "$lib" 2>/dev/null; then
        echo "  [OK]   $lib"
    else
        echo "  [MISS] $lib"
        MISSING=$((MISSING + 1))
    fi
done

echo ""
if [ "$MISSING" -gt 0 ]; then
    warn "$MISSING library(ies) still not found by pkg-config."
    warn "You may need to set PKG_CONFIG_PATH or install additional -dev packages."
else
    info "All required libraries found."
fi

# ---------------------------------------------------------------------------
# 8. Summary
# ---------------------------------------------------------------------------
echo ""
echo "============================================="
echo "  Setup complete!"
echo "============================================="
echo ""
echo "  To start the application:"
echo "    ./start.sh"
echo ""
echo "  Or manually:"
echo "    npm run tauri dev     # Development mode"
echo "    npm run tauri build   # Production build"
echo ""
