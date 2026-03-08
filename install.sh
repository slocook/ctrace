#!/usr/bin/env bash
set -euo pipefail

REPO_URL="https://github.com/slocook/ctrace.git"
INSTALL_DIR="${CTRACE_HOME:-$HOME/.local/share/ctrace}"

echo "=== ctrace installer ==="
echo ""

# Check for uv
if ! command -v uv &>/dev/null; then
    echo "Error: uv is not installed. Install it from https://docs.astral.sh/uv/"
    exit 1
fi

# If running from a checkout, use that directory; otherwise clone
if [ -f "$(dirname "$0")/SKILL.md" ] 2>/dev/null; then
  CTRACE_DIR="$(cd "$(dirname "$0")" && pwd)"
else
  # curl | bash mode — clone the repo
  if [ -d "$INSTALL_DIR/.git" ]; then
    echo "Updating existing installation at $INSTALL_DIR"
    git -C "$INSTALL_DIR" pull --ff-only
  else
    echo "Cloning ctrace to $INSTALL_DIR"
    git clone "$REPO_URL" "$INSTALL_DIR"
  fi
  CTRACE_DIR="$INSTALL_DIR"
fi

# Install dependencies
echo "Installing ctrace with uv..."
uv sync --directory "$CTRACE_DIR"

# Platform-specific sudoers setup
setup_sudoers() {
    local tracer_path="$1"
    local sudoers_file="/etc/sudoers.d/ctrace"
    local group

    if [[ "$(uname)" == "Darwin" ]]; then
        group="staff"
    elif getent group sudo &>/dev/null; then
        group="sudo"
    elif getent group wheel &>/dev/null; then
        group="wheel"
    else
        group="$(id -gn)"
    fi

    echo ""
    echo "ctrace needs passwordless sudo access to $tracer_path."
    echo "This will add a sudoers rule: %${group} ALL=(root) NOPASSWD: ${tracer_path}"
    echo ""
    read -rp "Set up sudoers rule? [y/N] " response
    if [[ "$response" =~ ^[Yy]$ ]]; then
        echo "%${group} ALL=(root) NOPASSWD: ${tracer_path}" | sudo tee "$sudoers_file" > /dev/null
        sudo chmod 0440 "$sudoers_file"
        echo "Sudoers rule installed at $sudoers_file"
    else
        echo "Skipped. You'll need to enter your password for each trace, or set up sudoers manually."
    fi
}

if [[ "$(uname)" == "Darwin" ]]; then
    if ! command -v dtrace &>/dev/null; then
        echo "Warning: dtrace not found. It should be included with macOS."
    fi
    setup_sudoers "/usr/sbin/dtrace, /usr/bin/fs_usage, /usr/bin/sc_usage"
elif [[ "$(uname)" == "Linux" ]]; then
    if ! command -v bpftrace &>/dev/null; then
        echo "Warning: bpftrace not found. Install it with your package manager."
        echo "  Ubuntu/Debian: sudo apt install bpftrace"
        echo "  Fedora: sudo dnf install bpftrace"
    fi
    BPFTRACE_PATH="$(command -v bpftrace 2>/dev/null || echo "/usr/bin/bpftrace")"
    setup_sudoers "$BPFTRACE_PATH"
fi

# Register MCP server (user scope = available in all projects)
claude mcp add --scope user ctrace -- \
  uv run --directory "$CTRACE_DIR" ctrace-mcp

# Install skill
SKILL_DIR="$HOME/.claude/skills/ctrace"
mkdir -p "$SKILL_DIR"
cp "$CTRACE_DIR/SKILL.md" "$SKILL_DIR/SKILL.md"

echo ""
echo "Done. ctrace MCP server registered and skill installed."
echo "Verify: claude mcp list"
