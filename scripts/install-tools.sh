#!/usr/bin/env bash
# install-tools.sh — Install all RE tools for unravel
#
# Usage:
#   ./scripts/install-tools.sh          # Install to ./bin
#   ./scripts/install-tools.sh /opt/re  # Install to custom dir
#
# Sections:
#   1. System packages (apt): binutils, rizin, radare2, binwalk, nasm, etc.
#   2. Android RE tools (downloaded): apktool, jadx, dex2jar, procyon, jd-cli,
#      bundletool, adb
#   3. .NET / native decompilers: retdec, ilspycmd, Ghidra
#
set -euo pipefail

# Versions
APKTOOL_VERSION="2.12.1"
JADX_VERSION="1.5.3"
DEX2JAR_VERSION="2.4"
PROCYON_VERSION="0.6.0"
JDCLI_VERSION="1.2.1"
BUNDLETOOL_VERSION="1.18.3"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

BIN_DIR="${1:-$(pwd)/bin}"
TMP_DIR="$(mktemp -d)"

trap 'rm -rf "$TMP_DIR"' EXIT

info()  { echo -e "${CYAN}[*]${NC} $*"; }
ok()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
fail()  { echo -e "${RED}[-]${NC} $*"; }

installed=0
skipped=0
failed=0

mkdir -p "$BIN_DIR"

echo ""
echo "============================================"
echo "  Unravel RE Tools Installer"
echo "============================================"
echo "  Target: $BIN_DIR"
echo "============================================"
echo ""

# ─── Helpers ──────────────────────────────────────────────────────────

check_java() {
    if command -v java &>/dev/null; then
        ok "Java found: $(java -version 2>&1 | head -1)"
        return 0
    else
        warn "Java not found — JAR-based tools will not work"
        warn "Install: sudo apt install default-jre"
        return 1
    fi
}

download() {
    local url="$1" dest="$2"
    info "Downloading $(basename "$dest")..."
    if curl -fSL --progress-bar -o "$dest" "$url"; then
        return 0
    else
        fail "Failed to download: $url"
        return 1
    fi
}

make_jar_wrapper() {
    local name="$1" jar="$2"
    cat > "$BIN_DIR/$name" << WRAPPER
#!/usr/bin/env bash
exec java -jar "\$(dirname "\$0")/$jar" "\$@"
WRAPPER
    chmod +x "$BIN_DIR/$name"
}

# ─── Java check ───────────────────────────────────────────────────────

HAS_JAVA=true
check_java || HAS_JAVA=false
echo ""

# ═══════════════════════════════════════════════════════════════════════
#  Section 1: System packages (apt)
# ═══════════════════════════════════════════════════════════════════════

if command -v apt-get >/dev/null 2>&1; then
    info "Installing system packages via apt..."
    sudo apt-get update

    # Core binary analysis tools
    sudo apt-get install -y \
      binutils \
      file \
      xxd \
      binwalk \
      nasm \
      ltrace \
      strace \
      elfutils \
      upx-ucl \
      netcat-openbsd \
      python3 \
      python3-pip \
      unzip \
      wget \
      curl \
    && ok "Core system packages installed" && ((installed++)) || { fail "Some apt packages failed"; ((failed++)) || true; }

    # rizin and radare2
    if sudo apt-get install -y rizin radare2 2>/dev/null; then
        ok "rizin & radare2 installed"
        ((installed++)) || true
    else
        warn "rizin/radare2 not available via apt — install manually"
        ((skipped++)) || true
    fi

    # Capstone CLI (cstool) via pip
    if ! command -v cstool >/dev/null 2>&1; then
        if python3 -m pip install --user capstone 2>/dev/null; then
            ok "capstone (cstool) installed via pip"
            ((installed++)) || true
        else
            warn "capstone pip install failed — install manually"
            ((skipped++)) || true
        fi
    else
        ok "capstone (cstool) already installed"
        ((installed++)) || true
    fi

    echo ""
else
    warn "apt-get not found — skipping system packages"
    warn "Install binutils, rizin, radare2, binwalk, nasm manually for your distro"
    ((skipped++)) || true
    echo ""
fi

# ═══════════════════════════════════════════════════════════════════════
#  Section 2: Android RE tools (downloaded)
# ═══════════════════════════════════════════════════════════════════════

# ─── 1. apktool ──────────────────────────────────────────────────────

info "Installing apktool v${APKTOOL_VERSION}..."
if download \
    "https://github.com/iBotPeaches/Apktool/releases/download/v${APKTOOL_VERSION}/apktool_${APKTOOL_VERSION}.jar" \
    "$BIN_DIR/apktool.jar"; then
    make_jar_wrapper "apktool" "apktool.jar"
    ok "apktool installed"
    ((installed++)) || true
else
    fail "apktool failed"
    ((failed++)) || true
fi

# ─── 2. jadx ─────────────────────────────────────────────────────────

info "Installing jadx v${JADX_VERSION}..."
if download \
    "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip" \
    "$TMP_DIR/jadx.zip"; then
    unzip -qo "$TMP_DIR/jadx.zip" -d "$BIN_DIR/jadx-dist"
    ln -sf "$BIN_DIR/jadx-dist/bin/jadx" "$BIN_DIR/jadx"
    ln -sf "$BIN_DIR/jadx-dist/bin/jadx-gui" "$BIN_DIR/jadx-gui"
    chmod +x "$BIN_DIR/jadx-dist/bin/jadx" "$BIN_DIR/jadx-dist/bin/jadx-gui"
    ok "jadx installed"
    ((installed++)) || true
else
    fail "jadx failed"
    ((failed++)) || true
fi

# ─── 3. dex2jar ──────────────────────────────────────────────────────

info "Installing dex2jar v${DEX2JAR_VERSION}..."
if download \
    "https://github.com/pxb1988/dex2jar/releases/download/v${DEX2JAR_VERSION}/dex-tools-v${DEX2JAR_VERSION}.zip" \
    "$TMP_DIR/dex2jar.zip"; then
    unzip -qo "$TMP_DIR/dex2jar.zip" -d "$BIN_DIR"
    # Normalize directory name
    if [ -d "$BIN_DIR/dex-tools-v${DEX2JAR_VERSION}" ]; then
        rm -rf "$BIN_DIR/dex2jar-dist"
        mv "$BIN_DIR/dex-tools-v${DEX2JAR_VERSION}" "$BIN_DIR/dex2jar-dist"
    elif [ -d "$BIN_DIR/dex-tools-${DEX2JAR_VERSION}" ]; then
        rm -rf "$BIN_DIR/dex2jar-dist"
        mv "$BIN_DIR/dex-tools-${DEX2JAR_VERSION}" "$BIN_DIR/dex2jar-dist"
    fi
    chmod +x "$BIN_DIR/dex2jar-dist"/*.sh 2>/dev/null || true
    ln -sf "$BIN_DIR/dex2jar-dist/d2j-dex2jar.sh" "$BIN_DIR/d2j-dex2jar"
    ok "dex2jar installed"
    ((installed++)) || true
else
    fail "dex2jar failed"
    ((failed++)) || true
fi

# ─── 4. procyon ──────────────────────────────────────────────────────

info "Installing procyon v${PROCYON_VERSION}..."
if download \
    "https://github.com/mstrobel/procyon/releases/download/v${PROCYON_VERSION}/procyon-decompiler-${PROCYON_VERSION}.jar" \
    "$BIN_DIR/procyon-decompiler.jar"; then
    make_jar_wrapper "procyon" "procyon-decompiler.jar"
    ok "procyon installed"
    ((installed++)) || true
else
    fail "procyon failed"
    ((failed++)) || true
fi

# ─── 5. jd-cli ───────────────────────────────────────────────────────

info "Installing jd-cli v${JDCLI_VERSION}..."
if download \
    "https://repo1.maven.org/maven2/com/github/kwart/jd/jd-cli/${JDCLI_VERSION}/jd-cli-${JDCLI_VERSION}.jar" \
    "$BIN_DIR/jd-cli.jar"; then
    make_jar_wrapper "jd-cli" "jd-cli.jar"
    ok "jd-cli installed"
    ((installed++)) || true
else
    fail "jd-cli failed"
    ((failed++)) || true
fi

# ─── 6. bundletool ───────────────────────────────────────────────────

info "Installing bundletool v${BUNDLETOOL_VERSION}..."
if download \
    "https://github.com/google/bundletool/releases/download/${BUNDLETOOL_VERSION}/bundletool-all-${BUNDLETOOL_VERSION}.jar" \
    "$BIN_DIR/bundletool.jar"; then
    make_jar_wrapper "bundletool" "bundletool.jar"
    ok "bundletool installed"
    ((installed++)) || true
else
    fail "bundletool failed"
    ((failed++)) || true
fi

# ─── 7. adb (platform-tools) ─────────────────────────────────────────

info "Installing adb (platform-tools)..."
if command -v adb &>/dev/null; then
    ok "adb already installed: $(command -v adb)"
    ((installed++)) || true
elif download \
    "https://dl.google.com/android/repository/platform-tools-latest-linux.zip" \
    "$TMP_DIR/platform-tools.zip"; then
    unzip -qo "$TMP_DIR/platform-tools.zip" -d "$BIN_DIR"
    ln -sf "$BIN_DIR/platform-tools/adb" "$BIN_DIR/adb"
    ln -sf "$BIN_DIR/platform-tools/fastboot" "$BIN_DIR/fastboot"
    ok "adb installed"
    ((installed++)) || true
else
    fail "adb failed"
    ((failed++)) || true
fi

# ═══════════════════════════════════════════════════════════════════════
#  Section 3: Native decompilers (manual / build-from-source)
# ═══════════════════════════════════════════════════════════════════════

# ─── 8. retdec ───────────────────────────────────────────────────────

info "Checking retdec..."
if command -v retdec-decompiler &>/dev/null || command -v retdec &>/dev/null; then
    ok "retdec already installed: $(command -v retdec-decompiler || command -v retdec)"
    ((installed++)) || true
else
    # Try apt first
    if command -v apt-get >/dev/null 2>&1 && sudo apt-get install -y retdec 2>/dev/null; then
        ok "retdec installed via apt"
        ((installed++)) || true
    else
        warn "retdec requires building from source (~5GB, 30+ min)"
        warn "  git clone https://github.com/avast/retdec && cd retdec"
        warn "  mkdir build && cd build && cmake .. && make -j\$(nproc) && sudo make install"
        warn "Skipping retdec (install manually if needed)"
        ((skipped++)) || true
    fi
fi

# ─── 9. ilspycmd ─────────────────────────────────────────────────────

info "Checking ilspycmd..."
if command -v ilspycmd &>/dev/null; then
    ok "ilspycmd already installed: $(command -v ilspycmd)"
    ((installed++)) || true
elif command -v dotnet &>/dev/null; then
    info "Installing ilspycmd via dotnet tool..."
    if dotnet tool install -g ilspycmd 2>/dev/null || dotnet tool update -g ilspycmd 2>/dev/null; then
        ok "ilspycmd installed via dotnet"
        ((installed++)) || true
    else
        fail "ilspycmd installation failed"
        ((failed++)) || true
    fi
else
    warn "dotnet SDK not found — cannot install ilspycmd"
    warn "  Install: https://dotnet.microsoft.com/download"
    warn "  Then: dotnet tool install -g ilspycmd"
    ((skipped++)) || true
fi

# ─── 10. Ghidra ──────────────────────────────────────────────────────

info "Checking Ghidra..."
if command -v analyzeHeadless &>/dev/null; then
    ok "Ghidra already installed"
    ((installed++)) || true
else
    warn "Ghidra not found. Download from https://ghidra-sre.org"
    warn "  Add analyzeHeadless to PATH after installation"
    ((skipped++)) || true
fi

# ─── Summary ─────────────────────────────────────────────────────────

echo ""
echo "============================================"
echo "  Installation Summary"
echo "============================================"
echo -e "  ${GREEN}Installed: ${installed}${NC}"
echo -e "  ${YELLOW}Skipped:   ${skipped}${NC}"
echo -e "  ${RED}Failed:    ${failed}${NC}"
echo "============================================"
echo ""
echo "Option 1: Use --tools-dir flag (no PATH change needed):"
echo "  unravel app dissect ./app.apk --tools-dir $BIN_DIR"
echo ""
echo "Option 2: Auto-detect (run unravel from project root):"
echo "  cd $(dirname "$BIN_DIR") && unravel dissect ./app.apk"
echo "  (unravel auto-detects ./bin directory)"
echo ""
echo "Option 3: Add to PATH permanently:"
echo "  export PATH=\"$BIN_DIR:\$PATH\""
echo "  echo 'export PATH=\"$BIN_DIR:\$PATH\"' >> ~/.bashrc"
echo ""
echo "Verify with:"
echo "  unravel android tools status"
echo "  unravel app dissect ./app.apk --debug"
echo "============================================"
