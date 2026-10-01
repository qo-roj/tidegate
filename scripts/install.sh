#!/usr/bin/env bash
set -euo pipefail

# Tidegate — Installer
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/qo-roj/tidegate/main/scripts/install.sh | bash
#   TIDEGATE_MIRROR=https://mirror.local bash install.sh       # Fleet mirror
#   bash install.sh --local /path/to/tidegate-binary          # Local binary (dev)
#   bash install.sh --build                                     # Build from source (needs Go)
#   bash install.sh --system                                    # /usr/local/bin (needs sudo)
#   bash install.sh --user                                      # ~/.local/bin (default fallback)
#   bash install.sh --no-path-edit                              # Don't touch shell rc files
#
# Default scope is "auto": install to /usr/local/bin when it is writable
# (or passwordless sudo exists), otherwise ~/.local/bin. If the chosen
# directory is not in PATH, the installer writes the PATH entry into the
# rc file of your login shell (~/.bashrc, ~/.zshrc, fish config) plus
# ~/.profile automatically — open a new terminal to pick it up.
# (--add-to-path is accepted as a deprecated no-op; this is now automatic.)

VERSION="${VERSION:-latest}"
CONFIG_DIR="${HOME}/.config/tidegate"
DATA_DIR="${HOME}/.local/share/tidegate"
LOCAL_BINARY=""
DO_BUILD=false
INSTALL_SCOPE="auto"   # auto | user | system
NO_PATH_EDIT=false

# Parse args
while [[ $# -gt 0 ]]; do
    case "$1" in
        --local)    [[ $# -ge 2 ]] || { echo "Missing value for --local"; exit 1; }; LOCAL_BINARY="$2"; shift 2 ;;
        --build)   DO_BUILD=true; shift ;;
        --version) [[ $# -ge 2 ]] || { echo "Missing value for --version"; exit 1; }; VERSION="$2"; shift 2 ;;
        --user)    INSTALL_SCOPE="user"; shift ;;
        --system)  INSTALL_SCOPE="system"; shift ;;
        --no-path-edit) NO_PATH_EDIT=true; shift ;;
        --add-to-path) shift ;;   # deprecated: PATH edit is automatic now
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

# Resolve install directory.
#
# System paths work out of the box on every distro; ~/.local/bin needs a PATH
# entry many users don't have (Linux Mint, stock Debian, etc.). Scope "auto"
# picks a system path when we can write to one without an interactive sudo
# prompt breaking `curl | bash`; otherwise falls back to ~/.local/bin.
SYSTEM_DIR="/usr/local/bin"
install_dir_user="${HOME}/.local/bin"

dir_writable() {
    [[ -d "$1" && -w "$1" ]]
}

# Interactive? When the script itself is piped (curl | bash), stdin is the
# pipe and a sudo password prompt would collide with script streaming; only
# allow prompting sudo when stdin is a real tty (script run from a file).
INTERACTIVE=false
if [ -t 0 ]; then INTERACTIVE=true; fi

sudo_cmd() {
    if [[ "$INTERACTIVE" == true ]]; then
        sudo "$@"
    else
        sudo -n "$@"
    fi
}

can_sudo() {
    command -v sudo >/dev/null 2>&1 && sudo_cmd true 2>/dev/null
}

if [[ "$INSTALL_SCOPE" == "system" ]]; then
    if dir_writable "$SYSTEM_DIR" || can_sudo; then
        INSTALL_DIR="$SYSTEM_DIR"
    else
        echo "✗ Cannot install system-wide: $SYSTEM_DIR is not writable and sudo is unavailable."
        echo "  Passwordless sudo works non-interactively; otherwise download and run interactively:"
        echo "    curl -fsSL <installer-url> -o install.sh && bash install.sh --system"
        echo "  Or install to your user directory: bash install.sh --user"
        exit 1
    fi
elif [[ "$INSTALL_SCOPE" == "user" ]]; then
    INSTALL_DIR="$install_dir_user"
else
    if dir_writable "$SYSTEM_DIR"; then
        INSTALL_DIR="$SYSTEM_DIR"
    else
        INSTALL_DIR="$install_dir_user"
    fi
fi

# Mirror URL (can be overridden for fleet/private hosting)
DOWNLOAD_BASE="${TIDEGATE_MIRROR:-https://github.com/qo-roj/tidegate/releases}"

echo "🦞 Tidegate — Redaction Gateway for AI Agents"
echo ""

# Detect OS and architecture
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$OS" in
    linux)  PLATFORM="linux" ;;
    darwin) PLATFORM="darwin" ;;
    *) echo "Unsupported OS: $OS"; exit 1 ;;
esac

case "$ARCH" in
    x86_64|amd64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

echo "Detected: ${PLATFORM}/${ARCH}"
echo ""

# Place a staged binary into $INSTALL_DIR, using sudo when the dir is not
# directly writable (prompting allowed when interactive, passwordless only
# when piped).
install_binary() {
    local staged="$1"
    if dir_writable "$INSTALL_DIR"; then
        cp "$staged" "${INSTALL_DIR}/tidegate"
        chmod +x "${INSTALL_DIR}/tidegate"
    elif can_sudo; then
        sudo_cmd install -m 0755 "$staged" "${INSTALL_DIR}/tidegate"
    else
        echo "✗ Cannot write to ${INSTALL_DIR} and no sudo available."
        exit 1
    fi
    echo "✓ Binary installed to ${INSTALL_DIR}/tidegate"
}

# Create directories (user install dir; system dirs are expected to exist)
mkdir -p "$install_dir_user" "$CONFIG_DIR" "$DATA_DIR"

# Install method 1: local binary (development)
if [[ -n "$LOCAL_BINARY" ]]; then
    echo "Installing from local binary: $LOCAL_BINARY"
    install_binary "$LOCAL_BINARY"

# Install method 2: build from source
elif [[ "$DO_BUILD" == true ]]; then
    if ! command -v go &>/dev/null; then
        echo "✗ Go is not installed. Install Go or use --local / a release binary."
        exit 1
    fi
    echo "Building from source..."
    TMP_SRC="$(mktemp -d)"
    git clone https://github.com/qo-roj/tidegate "$TMP_SRC" 2>/dev/null || {
        echo "✗ Could not clone repo. If the GitHub repo doesn't exist yet,"
        echo "  use --local /path/to/binary or build manually."
        exit 1
    }
    STAGED="$(mktemp)"
    # CGO_ENABLED=0: static binary, runs on any distro regardless of the
    # build host's glibc (Debian 11 etc.). modernc/sqlite is pure Go.
    (cd "$TMP_SRC" && CGO_ENABLED=0 go build -o "$STAGED" ./cmd/tidegate)
    rm -rf "$TMP_SRC"
    install_binary "$STAGED"
    rm -f "$STAGED"
    echo "✓ Built and installed"

# Install method 3: download from mirror/GitHub releases
else
    if [[ "$VERSION" == "latest" ]]; then
        DOWNLOAD_URL="${DOWNLOAD_BASE}/latest/download/tidegate-${PLATFORM}-${ARCH}"
    else
        DOWNLOAD_URL="${DOWNLOAD_BASE}/download/${VERSION}/tidegate-${PLATFORM}-${ARCH}"
    fi

    echo "Downloading Tidegate ${VERSION}..."
    echo "  Source: ${DOWNLOAD_URL}"
    echo ""

    STAGED="$(mktemp)"
    if curl -fsSL "$DOWNLOAD_URL" -o "$STAGED" 2>/dev/null; then
        install_binary "$STAGED"
        rm -f "$STAGED"
    else
        echo "✗ Failed to download from ${DOWNLOAD_URL}"
        echo ""
        echo "The GitHub repo may not exist yet. Alternative install methods:"
        echo ""
        echo "  1. Build from source (requires Go):"
        echo "     bash install.sh --build"
        echo ""
        echo "  2. Install a local binary (development):"
        echo "     bash install.sh --local /path/to/tidegate"
        echo ""
        echo "  3. Use a fleet mirror:"
        echo "     TIDEGATE_MIRROR=https://your-mirror bash install.sh"
        exit 1
    fi
fi

# Check if binary is in PATH; if not, add it to the rc files automatically
path_in_path() {
    [[ ":$PATH:" == *":${1}:"* ]]
}

if ! path_in_path "$INSTALL_DIR"; then
    if [[ "$NO_PATH_EDIT" == true ]]; then
        echo ""
        echo "⚠ ${INSTALL_DIR} is not in your PATH and --no-path-edit given."
        echo "  Add it yourself: export PATH=\"${INSTALL_DIR}:\$PATH\""
    else
        # ~/.profile — sourced by login shells (Mint, Ubuntu, Debian); covers
        # the session PATH even when the interactive shell uses a different rc.
        EDITED=""
        PROFILE_FILE="${HOME}/.profile"
        if [[ ! -f "$PROFILE_FILE" ]] || ! grep -qs "TIDEGATE_PATH" "$PROFILE_FILE"; then
            {
                echo ""
                echo "# TIDEGATE_PATH — added by tidegate installer"
                echo "export PATH=\"${INSTALL_DIR}:\$PATH\""
            } >> "$PROFILE_FILE"
            EDITED="${PROFILE_FILE}"
        fi

        # Login shell's interactive rc — what a fresh terminal actually reads.
        # Mint/GNOME terminals are non-login bash shells: they read .bashrc
        # ONLY, not .profile, so without this the command stays missing until
        # the next full login/reboot.
        SHELL_NAME="$(basename "${SHELL:-/bin/bash}")"
        case "$SHELL_NAME" in
            bash)
                RC_FILE="${HOME}/.bashrc"
                if [[ ! -f "$RC_FILE" ]] || ! grep -qs "TIDEGATE_PATH" "$RC_FILE"; then
                    { echo ""; echo "# TIDEGATE_PATH — added by tidegate installer"; echo "export PATH=\"${INSTALL_DIR}:\$PATH\""; } >> "$RC_FILE"
                    EDITED="${EDITED:+$EDITED and }${RC_FILE}"
                fi
                ;;
            zsh)
                RC_FILE="${HOME}/.zshrc"
                if [[ ! -f "$RC_FILE" ]] || ! grep -qs "TIDEGATE_PATH" "$RC_FILE"; then
                    { echo ""; echo "# TIDEGATE_PATH — added by tidegate installer"; echo "export PATH=\"${INSTALL_DIR}:\$PATH\""; } >> "$RC_FILE"
                    EDITED="${EDITED:+$EDITED and }${RC_FILE}"
                fi
                ;;
            fish)
                RC_FILE="${HOME}/.config/fish/config.fish"
                mkdir -p "$(dirname "$RC_FILE")"
                if [[ ! -f "$RC_FILE" ]] || ! grep -qs "TIDEGATE_PATH" "$RC_FILE"; then
                    { echo ""; echo "# TIDEGATE_PATH — added by tidegate installer"; echo "set -gx PATH ${INSTALL_DIR} \$PATH"; } >> "$RC_FILE"
                    EDITED="${EDITED:+$EDITED and }${RC_FILE}"
                fi
                ;;
        esac

        echo ""
        if [[ -n "$EDITED" ]]; then
            echo "✓ Added ${INSTALL_DIR} to PATH via ${EDITED}"
            echo "  Open a NEW terminal (or run: source ~/.bashrc) and tidegate will be found."
        else
            echo "✓ PATH entry already present in your rc files."
        fi
    fi
fi

# Create default config if it doesn't exist
if [[ ! -f "${CONFIG_DIR}/tidegate.conf" ]]; then
    cat > "${CONFIG_DIR}/tidegate.conf" << 'CONF'
# Tidegate Configuration
# Docs: https://github.com/qo-roj/tidegate/blob/main/docs/rules-guide.md

[gateway]
port = 8842
log_level = info
# tls = false  # set true for paranoid mode (local TLS)

[cloud]
# Cloud providers — keys read from env vars by default
# ANTHROPIC_API_KEY, OPENAI_API_KEY, etc.
# Or set explicitly:
# anthropic = sk-ant-xxx
# openai = sk-xxx

[local]
# Local model for sensitive data processing
ollama_url = http://localhost:11434
ollama_model = llama3:8b

[redaction]
# All built-in patterns enabled by default
# See rules/defaults.conf for the full list

[preset]
# Choose: desktop, server, paranoid, or training-data
# desktop         — Omarchy / personal workstation (default)
# server          — Production server with user data
# paranoid        — Maximum redaction
# training-data   — Redact all PII for fine-tuning datasets
desktop
CONF
    echo "✓ Default config created at ${CONFIG_DIR}/tidegate.conf"
fi

# Check for Ollama
echo ""
if command -v ollama &>/dev/null; then
    echo "✓ Ollama detected"
else
    echo "⚠ Ollama not found. Local-only content will be blocked (not summarized)."
    echo "  Install Ollama: https://ollama.com"
    echo "  Or run: tidegate setup-ollama"
fi

# Done
echo ""
echo "─────────────────────────────────────"
echo "  Tidegate installed successfully"
echo "─────────────────────────────────────"
echo ""
echo "Next steps:"
echo ""
echo "  1. Start the gateway:"
echo "     tidegate start"
echo ""
echo "  2. Configure your agents:"
echo "     tidegate install --agent claude-code"
echo "     tidegate install --agent codex"
echo "     tidegate install --agent hermes"
echo ""
echo "  3. Verify it's working:"
echo "     tidegate audit --live"
echo ""
echo "  4. Review your rules:"
echo "     tidegate config edit"
echo ""
echo "Docs: https://github.com/qo-roj/tidegate"