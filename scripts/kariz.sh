#!/usr/bin/env bash
# Kariz manager: installs Kariz and its web panel on a Linux server with systemd, and
# connects the server to a panel. Tunnels, servers, private networks and updates are made
# in the web panel (docs/panel.md), never here.
#
# One line, as root:
#   bash <(curl -fsSL https://raw.githubusercontent.com/MAHDI-byte64/tun2/main/scripts/kariz.sh)
#
# Without arguments it opens a menu. The same actions as commands (see `help`):
#   kariz-manager install [--version vX.Y.Z] [--binary PATH] [--archive FILE] [--offline]
#   kariz-manager update | uninstall [--yes]
#   kariz-manager panel install [--domain D | --ip ADDRESS] | link | password | status | logs | uninstall
#   kariz-manager panel cert [--domain D | --ip ADDRESS]   change the domain or address of the panel
#                                        (a new IP address is followed by itself: panel heal)
#   kariz-manager --agent CODE [--yes]   connect this server to a panel (its join code); a
#                                        server that is connected already is switched to it
#   kariz-manager agent status | logs | remove
#   kariz-manager status              what runs here, and this server's addresses
#
# If GitHub limits your downloads, set GITHUB_TOKEN to a personal access token: it lifts the limit.
set -euo pipefail

REPO="MAHDI-byte64/tun2"
BIN=/usr/local/bin/kariz
MANAGER=/usr/local/bin/kariz-manager
CONF_DIR=/etc/kariz
UNIT=/etc/systemd/system/kariz@.service
# The web panel (docs/panel.md) and its agent.
PANEL_BIN=/usr/local/bin/kariz-panel
PANEL_DIR=/etc/kariz-panel
PANEL_DATA=/var/lib/kariz-panel
PANEL_CONF=$PANEL_DIR/panel.toml
AGENT_CONF=$PANEL_DIR/agent.toml
# What the panel's certificate is for (a domain or an IP address), and what was stopped
# for a moment while Let's Encrypt looked at port 80.
PANEL_DOMAIN=$PANEL_DIR/domain
ACME_STOPPED=/run/kariz-acme-stopped
PANEL_UNIT=/etc/systemd/system/kariz-panel.service
AGENT_UNIT=/etc/systemd/system/kariz-agent.service
# What gives the panel a certificate for the server's new IP address by itself (`panel heal`),
# and the address it last failed to get one for, with when.
HEAL_SERVICE=/etc/systemd/system/kariz-panel-heal.service
HEAL_TIMER=/etc/systemd/system/kariz-panel-heal.timer
HEAL_FAILED=$PANEL_DATA/heal-failed
RAW_URL="https://raw.githubusercontent.com/$REPO/main/scripts/kariz.sh"

# ---- Looks ----

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    C_RESET=$'\e[0m' C_BOLD=$'\e[1m' C_DIM=$'\e[2m'
    C_TEAL=$'\e[38;5;45m' C_AQUA=$'\e[38;5;75m' C_PURPLE=$'\e[38;5;141m' C_SAND=$'\e[38;5;179m'
    C_RED=$'\e[38;5;203m' C_YELLOW=$'\e[38;5;220m' C_GREEN=$'\e[38;5;84m'
    C_GRAY=$'\e[38;5;245m' C_LINK=$'\e[4;38;5;51m' C_PINK=$'\e[38;5;213m'
    # The background of the highlighted row in the menu and the pickers.
    C_SEL=$'\e[48;5;237m'
else
    C_RESET='' C_BOLD='' C_DIM='' C_TEAL='' C_AQUA='' C_PURPLE='' C_SAND='' C_RED='' C_YELLOW='' C_GREEN=''
    C_GRAY='' C_LINK='' C_PINK='' C_SEL=''
fi

# A web address, in the colour of a link (underlined), so it stands out and is easy to find.
url() { printf '%s%s%s' "$C_LINK" "$1" "$C_RESET"; }

# The width of boxes and rules: the terminal's, between 44 and 76 columns, less the margins.
box_width() {
    local cols=${COLUMNS:-}
    [[ "$cols" =~ ^[0-9]+$ ]] || cols=$(tput cols 2>/dev/null || echo 80)
    [[ "$cols" =~ ^[0-9]+$ ]] || cols=80
    ((cols > 76)) && cols=76
    ((cols < 44)) && cols=44
    echo $((cols - 4))
}

# One row of a card: a label and its value.
kv() { printf '  %s│%s %s%-12s%s %s\n' "$C_DIM$C_TEAL" "$C_RESET" "$C_GRAY" "$1" "$C_RESET" "$2"; }

# The top and the bottom of a card, with a title in the top.
card_top() {
    local title=$1 w line
    w=$(box_width)
    printf -v line '%*s' $((w - ${#title} - 5)) ''
    printf '\n  %s╭─%s %s%s%s %s%s╮%s\n' "$C_DIM$C_TEAL" "$C_RESET" "$C_BOLD$C_TEAL" "$title" "$C_RESET" "$C_DIM$C_TEAL" "${line// /─}" "$C_RESET"
}
card_end() {
    local w line
    w=$(box_width)
    printf -v line '%*s' $((w - 2)) ''
    printf '  %s╰%s╯%s\n' "$C_DIM$C_TEAL" "${line// /─}" "$C_RESET"
}

# A line of $1 box-drawing dashes.
rule() {
    local line
    printf -v line '%*s' "${1:-52}" ''
    printf '%s' "${line// /─}"
}

# The box with the name, what it is and the version: the top of every screen.
title_box() {
    # The text that sets the width is plain ASCII (the diamond is counted as 1), so the box
    # fits whatever the locale.
    local w inner title="Kariz manager" tag="tunnel core and web panel" version="" pad
    w=$(box_width)
    inner=$((w - 2))
    [[ -x "$BIN" ]] && version="v$(bin_version "$BIN")"
    pad=$((inner - 2 - 2 - ${#title} - 2 - ${#tag} - ${#version} - 2))
    ((pad < 1)) && pad=1
    printf '  %s╭%s╮%s\n' "$C_DIM$C_AQUA" "$(rule "$inner")" "$C_RESET"
    printf '  %s│%s  %s%s%s  %s%s%s%*s%s%s%s  %s│%s\n' "$C_DIM$C_AQUA" "$C_RESET" "$C_BOLD$C_TEAL" "◆ $title" "$C_RESET" \
        "$C_PINK" "$tag" "$C_RESET" "$pad" "" "$C_GRAY" "$version" "$C_RESET" "$C_DIM$C_AQUA" "$C_RESET"
    printf '  %s╰%s╯%s\n' "$C_DIM$C_AQUA" "$(rule "$inner")" "$C_RESET"
}

# The big one, for the first screens and for the menu when the terminal is tall enough.
banner() {
    local -a art=(
        ' _  __   _   ___  ___  ____'
        '| |/ /  /_\ | _ \|_ _||_  /'
        "| ' <  / _ \\|   / | |  / / "
        '|_|\_\/_/ \_\_|_\|___|/___|'
    )
    local -a tint=("$C_TEAL" "$C_TEAL" "$C_AQUA" "$C_PURPLE")
    local i
    printf '\n'
    for i in "${!art[@]}"; do
        printf '  %s%s%s\n' "$C_BOLD${tint[i]}" "${art[i]}" "$C_RESET"
    done
    title_box
    printf '  %s© ErfanXRay%s  %s·%s  %s\n' "$C_BOLD$C_SAND" "$C_RESET" "$C_DIM" "$C_RESET" "$(url "github.com/$REPO")"
}

# A heading for a part of a longer job.
section() {
    printf '\n  %s◆ %s%s\n  %s%s%s\n' "$C_BOLD$C_TEAL" "$*" "$C_RESET" "$C_DIM$C_TEAL" "$(rule "$(box_width)")" "$C_RESET"
}

info() { printf '  %s●%s %s\n' "$C_TEAL" "$C_RESET" "$*"; }
ok() { printf '  %s✔%s %s\n' "$C_GREEN" "$C_RESET" "$*"; }
warn() { printf '  %s▲ %s%s\n' "$C_YELLOW" "$*" "$C_RESET" >&2; }
die() {
    printf '  %s✖ %s%s\n' "$C_RED" "$*" "$C_RESET" >&2
    exit 1
}

# Answers come from the terminal even when the script itself was piped in, or from the
# file in KARIZ_INPUT (the tests). Opened once, in the parent shell, so every question
# reads on from the same place. The braces keep the 2>/dev/null to the open itself: on a
# bare `exec` it would silence the whole script, the questions included.
IN_FD=""
open_input() {
    [[ -n "$IN_FD" ]] && return 0
    { exec {IN_FD}<"${KARIZ_INPUT:-/dev/tty}"; } 2>/dev/null || IN_FD=""
    [[ -n "$IN_FD" ]] ||
        die "This needs a terminal to ask questions; use the commands instead (kariz-manager help)."
}

# Asks a question and stores the answer in the variable named $1. Not run in $(...), so
# a missing answer ends the script instead of looping. $2: prompt, $3: default (may be
# empty).
ask() {
    local _var=$1 _prompt=$2 _default=${3:-} _answer
    open_input
    if [[ -n "$_default" ]]; then
        printf '  %s?%s %s %s[%s]%s: ' "$C_AQUA" "$C_RESET" "$_prompt" "$C_DIM" "$_default" "$C_RESET"
    else
        printf '  %s?%s %s: ' "$C_AQUA" "$C_RESET" "$_prompt"
    fi
    if ! IFS= read -r -u "$IN_FD" _answer; then
        echo
        die "No answer to: $_prompt"
    fi
    _answer=${_answer%$'\r'}
    printf -v "$_var" '%s' "${_answer:-$_default}"
}

# Asks to pick one option from a numbered list; the answer is its number or its word.
# Into the variable named $1. $2: the question, $3: the default word, then the options
# as "word" or "word|description".
choose() {
    local _var=$1 _prompt=$2 _default=$3 _pick _o _n=0 _def=""
    shift 3
    if ui_interactive; then
        choose_arrow "$_var" "$_prompt" "$_default" "$@"
        return
    fi
    local _words=()
    printf '  %s%s%s\n' "$C_BOLD" "$_prompt" "$C_RESET"
    for _o in "$@"; do
        _n=$((_n + 1))
        _words+=("${_o%%|*}")
        [[ "${_o%%|*}" == "$_default" ]] && _def=$_n
        if [[ "$_o" == *"|"* ]]; then
            printf '    %s%d)%s %-10s %s%s%s\n' "$C_TEAL" "$_n" "$C_RESET" "${_o%%|*}" "$C_DIM" "${_o#*|}" "$C_RESET"
        else
            printf '    %s%d)%s %s\n' "$C_TEAL" "$_n" "$C_RESET" "$_o"
        fi
    done
    while true; do
        ask _pick "Choose" "$_def"
        if [[ "$_pick" =~ ^[0-9]+$ ]] && ((_pick >= 1 && _pick <= _n)); then
            _pick=${_words[$((_pick - 1))]}
        fi
        for _o in "${_words[@]}"; do
            if [[ "$_pick" == "$_o" ]]; then
                printf -v "$_var" '%s' "$_pick"
                return
            fi
        done
        warn "Type a number from 1 to $_n."
    done
}

confirm() {
    local _yes
    ask _yes "$1 (y/n)" "${2:-n}"
    [[ "$_yes" == y* || "$_yes" == Y* ]]
}

# ---- The terminal: keys, pickers and screens ----
# On a real terminal a question with options is a list to move in with the arrow keys, and the
# menu is drawn in place. Anywhere else (a pipe, the tests' answers in KARIZ_INPUT) the same
# questions are numbered and read as lines, so nothing here needs a terminal.

UI_ROWS=24 UI_COLS=80 UI_KEY=""

# Whether this is a terminal that can take arrow keys.
ui_interactive() {
    [[ -z "${KARIZ_INPUT:-}" && -t 1 ]] || return 1
    if [[ -z "$IN_FD" ]]; then
        { exec {IN_FD}</dev/tty; } 2>/dev/null || IN_FD=""
    fi
    [[ -n "$IN_FD" && -t "$IN_FD" ]]
}

# The terminal's size, in UI_ROWS and UI_COLS (and COLUMNS, which the boxes follow).
ui_term_size() {
    local size=""
    if [[ -n "$IN_FD" ]]; then
        size=$(stty size <&"$IN_FD" 2>/dev/null || true)
    fi
    UI_ROWS=${size%% *}
    UI_COLS=${size##* }
    [[ "$UI_ROWS" =~ ^[0-9]+$ ]] && ((UI_ROWS > 0)) || UI_ROWS=24
    [[ "$UI_COLS" =~ ^[0-9]+$ ]] && ((UI_COLS > 0)) || UI_COLS=80
    COLUMNS=$UI_COLS
}

# Undoes what the menu and the pickers change: the hidden cursor, no line wrap, no echo.
ui_restore_terminal() {
    if [[ -t 1 ]]; then
        printf '\e[?25h\e[?7h'
    fi
    if [[ -n "$IN_FD" ]]; then
        stty echo icanon <&"$IN_FD" 2>/dev/null || true
    fi
    return 0
}

# The top of a screen: the screen is cleared and the title box drawn. The scrollback is kept,
# so a long output (an install, an error) can still be scrolled back to.
screen_header() {
    printf '\e[H\e[2J'
    title_box
}

# Waits up to a second for a key and stores it in UI_KEY: up, down, home, end, pgup, pgdn,
# enter, esc, backspace, other, or the character. Returns 1 at the end of the input, 2 when
# no key was pressed.
read_key() {
    local key="" rest="" status=0
    UI_KEY=""
    IFS= read -rsn1 -t 1 -u "$IN_FD" key || status=$?
    ((status > 128)) && return 2
    ((status == 0)) || return 1
    case "$key" in
        "") UI_KEY=enter && return 0 ;;
        $'\177' | $'\b') UI_KEY=backspace && return 0 ;;
        $'\e') ;;
        *) UI_KEY=$key && return 0 ;;
    esac
    IFS= read -rsn2 -t 0.05 -u "$IN_FD" rest || true
    case "$rest" in
        '[A' | 'OA') UI_KEY=up ;;
        '[B' | 'OB') UI_KEY=down ;;
        '[H' | 'OH' | '[1' | '[7') UI_KEY=home ;;
        '[F' | 'OF' | '[4' | '[8') UI_KEY=end ;;
        '[5') UI_KEY=pgup ;;
        '[6') UI_KEY=pgdn ;;
        '') UI_KEY=esc ;;
        *) UI_KEY=other ;;
    esac
    # The rest of Home, End and Page Up / Down: a "~", or modifiers up to a letter. The
    # short sequences (the arrows) are whole already, so a key typed right after one is kept.
    case "$rest" in
        '[1' | '[4' | '[5' | '[6' | '[7' | '[8')
            local c="" n=0
            while ((n++ < 4)) && IFS= read -rsn1 -t 0.01 -u "$IN_FD" c; do
                [[ "$c" == "~" || "$c" =~ [A-Za-z] ]] && break
            done
            ;;
    esac
    return 0
}

# "Press any key" at the end of a screen. Without a terminal it waits for a line, as before.
pause() {
    if ui_interactive; then
        printf '\n  %s╰─ Press any key to continue%s ' "$C_DIM$C_GRAY" "$C_RESET"
        IFS= read -rsn1 -u "$IN_FD" _ || true
        # The rest of an arrow key, so the menu does not get it.
        while IFS= read -rsn1 -t 0.02 -u "$IN_FD" _; do :; done
        printf '\n'
    else
        printf '\n  %sEnter: back to the menu%s' "$C_DIM" "$C_RESET"
        read -r -u "$IN_FD" _ || true
    fi
}

# The picker of `choose` on a terminal: the options are rows to move in, drawn in place.
# Esc or q leaves the command (Ctrl+C does too).
choose_arrow() {
    local _var=$1 _prompt=$2 _default=$3 _o _i _sel=0 _n _drawn=0 _w _pad _fill _line _frame _status
    shift 3
    local _words=() _descs=() _wide=4
    for _o in "$@"; do
        _words+=("${_o%%|*}")
        if [[ "$_o" == *"|"* ]]; then _descs+=("${_o#*|}"); else _descs+=(""); fi
        ((${#_words[-1]} > _wide)) && _wide=${#_words[-1]}
    done
    _n=${#_words[@]}
    for _i in "${!_words[@]}"; do
        [[ "${_words[_i]}" == "$_default" ]] && _sel=$_i
    done
    open_input
    ui_term_size
    _w=$(box_width)
    printf '  %s%s%s\n' "$C_BOLD" "$_prompt" "$C_RESET"
    # No cursor and no line wrap, so every option is one line to redraw; no echo of keys.
    printf '\e[?25l\e[?7l'
    stty -echo <&"$IN_FD" 2>/dev/null || true
    while true; do
        _frame=""
        ((_drawn)) && _frame+=$'\e'"[${_drawn}A"$'\r'
        for _i in "${!_words[@]}"; do
            if ((_i == _sel)); then
                _pad=$((_w - 11 - _wide - ${#_descs[_i]}))
                ((_pad < 1)) && _pad=1
                printf -v _fill '%*s' "$_pad" ''
                printf -v _line '  %s❯%s %s %d  %-*s  %s%s%s' "$C_TEAL" "$C_RESET" "$C_SEL$C_BOLD" $((_i + 1)) \
                    "$_wide" "${_words[_i]}" "${_descs[_i]}" "$_fill" "$C_RESET"
            else
                printf -v _line '     %s%d%s  %-*s  %s%s%s' "$C_GRAY" $((_i + 1)) "$C_RESET" \
                    "$_wide" "${_words[_i]}" "$C_DIM" "${_descs[_i]}" "$C_RESET"
            fi
            _frame+="$_line"$'\e[K\n'
        done
        _frame+="  ${C_DIM}${C_GRAY}↑/↓ move · Enter select · Esc cancel${C_RESET}"$'\e[K\n'
        printf '%s' "$_frame"
        _drawn=$((_n + 1))
        _status=0
        read_key || _status=$?
        case $_status in
            1) UI_KEY=esc ;;
            2) continue ;;
        esac
        case "$UI_KEY" in
            up | k) _sel=$(((_sel - 1 + _n) % _n)) ;;
            down | j | $'\t') _sel=$(((_sel + 1) % _n)) ;;
            home | pgup) _sel=0 ;;
            end | pgdn) _sel=$((_n - 1)) ;;
            [1-9]) ((UI_KEY <= _n)) && _sel=$((UI_KEY - 1)) ;;
            enter) break ;;
            esc | q | Q)
                printf '\e[%dA\r\e[J' $((_drawn + 1))
                ui_restore_terminal
                printf '  %s‹ Cancelled%s\n' "$C_DIM$C_GRAY" "$C_RESET"
                exit 130
                ;;
        esac
    done
    printf '\e[%dA\r\e[J' $((_drawn + 1))
    ui_restore_terminal
    printf '  %s✔%s %s %s%s%s\n' "$C_GREEN" "$C_RESET" "$_prompt" "$C_BOLD$C_TEAL" "${_words[_sel]}" "$C_RESET"
    printf -v "$_var" '%s' "${_words[_sel]}"
}

# ---- Checks ----

need_root() {
    [[ $EUID -eq 0 ]] || die "Run as root (sudo)."
}

need_systemd() {
    command -v systemctl >/dev/null || die "This needs a Linux server with systemd."
}

need_kariz() {
    [[ -x "$BIN" ]] || die "Kariz is not installed yet: run '$(basename "$0") install' first."
}

# ---- Download and install ----

arch() {
    case "$(uname -m)" in
        x86_64 | amd64) echo x86_64 ;;
        aarch64 | arm64) echo aarch64 ;;
        armv7l | armv7*) echo armv7 ;;
        *) die "No Kariz build for this CPU ($(uname -m))." ;;
    esac
}

# The key releases are signed with. Only the release workflow has the
# private half. It is checked with openssl (1.1.1 or later, or 3).
RELEASE_KEY_PEM='-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAbJ1ZKvKHAFSS1iv5+SRjDyFucqS/PHPWPzzpBoZM3qo=
-----END PUBLIC KEY-----'
# A user can pin a key of their own (a fork, or a test): KARIZ_RELEASE_KEY_PEM.
RELEASE_KEY_PEM=${KARIZ_RELEASE_KEY_PEM:-$RELEASE_KEY_PEM}

# Checks the signature of a downloaded archive: $1 the directory with the archive, its
# .sha256 and its .sig, $2 the archive's name, $3 the version. Releases before 0.11 were not
# signed: they are accepted with a warning; from 0.11 on a missing or wrong signature stops
# the installation.
verify_signature() {
    local dir=$1 name=$2 version=$3
    local file="$dir/$name.tar.gz"
    if [[ ! -s "$file.sig" ]]; then
        if version_lt "${version#v}" "0.11.0"; then
            warn "This release is not signed (releases before 0.11 were not): only its checksum was checked."
            return 0
        fi
        die "This release has no signature: it will not be installed."
    fi
    if ! command -v openssl >/dev/null; then
        die "Checking the signature needs openssl (apt install openssl). Nothing was installed."
    fi
    printf '%s\n' "$RELEASE_KEY_PEM" >"$dir/release-key.pem"
    openssl pkeyutl -verify -pubin -inkey "$dir/release-key.pem" -rawin \
        -in "$file.sha256" -sigfile "$file.sig" >/dev/null 2>&1 ||
        die "The signature does not match: this download is not from the Kariz release key. Nothing was installed."
    # The signed checksum file must name this archive, so a signed archive of another CPU
    # cannot be put in its place.
    [[ "$(awk '{print $2}' "$file.sha256" | sed 's/^\*//')" == "$name.tar.gz" ]] ||
        die "The signed checksum is for another file. Nothing was installed."
    ok "The release signature is good."
}

# 0 if version $1 is lower than $2 (plain numbers, x.y.z; a suffix after a dash is ignored).
version_lt() {
    local a=${1%%-*} b=${2%%-*}
    [[ "$a" != "$b" && "$(printf '%s\n%s\n' "$a" "$b" | sort -V | head -n1)" == "$a" ]]
}

# curl or wget, with the token if there is one. $1: URL, $2: output file or
# - for stdout, $3: extra header (optional).
fetch() {
    local url=$1 out=$2 header=${3:-}
    local auth=()
    [[ -n "${GITHUB_TOKEN:-}" ]] && auth=(-H "Authorization: Bearer $GITHUB_TOKEN")
    if command -v curl >/dev/null; then
        local extra=()
        [[ -n "$header" ]] && extra=(-H "$header")
        # FETCH_MAX: seconds one request may take (set for a quick look, never for a download).
        [[ -n "${FETCH_MAX:-}" ]] && extra+=(--max-time "$FETCH_MAX")
        curl -fsSL --retry 3 "${auth[@]}" "${extra[@]}" -o "$out" "$url"
    elif command -v wget >/dev/null; then
        local extra=()
        [[ -n "${GITHUB_TOKEN:-}" ]] && extra+=(--header="Authorization: Bearer $GITHUB_TOKEN")
        [[ -n "$header" ]] && extra+=(--header="$header")
        [[ -n "${FETCH_MAX:-}" ]] && extra+=(--timeout="$FETCH_MAX")
        wget -q "${extra[@]}" -O "$out" "$url"
    else
        die "Needs curl or wget."
    fi
}

latest_version() {
    fetch "https://api.github.com/repos/$REPO/releases/latest" - |
        sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1
}

# Downloads release asset $2 of version $1 to file $3. With a token it goes through the
# API, otherwise the public download link.
download_asset() {
    local version=$1 name=$2 out=$3
    if [[ -z "${GITHUB_TOKEN:-}" ]]; then
        fetch "https://github.com/$REPO/releases/download/$version/$name" "$out"
        return
    fi
    local api
    api=$(fetch "https://api.github.com/repos/$REPO/releases/tags/$version" - |
        awk -v name="$name" '
            /"url": *"https:\/\/api.github.com\/.*\/releases\/assets\// {
                gsub(/.*"url": *"|".*/, ""); url = $0
            }
            $0 ~ "\"name\": *\"" name "\"" { print url; exit }
        ')
    [[ -n "$api" ]] || die "Release $version has no $name."
    fetch "$api" "$out" "Accept: application/octet-stream"
}

install_unit() {
    cat >"$UNIT" <<'EOF'
[Unit]
Description=Kariz tunnel %i
Documentation=https://github.com/MAHDI-byte64/tun2
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/kariz run -c /etc/kariz/%i.toml
Restart=always
RestartSec=2
LimitNOFILE=1048576
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
}

install_panel_units() {
    cat >"$PANEL_UNIT" <<'EOF'
[Unit]
Description=Kariz web panel
Documentation=https://github.com/MAHDI-byte64/tun2
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/kariz-panel serve -c /etc/kariz-panel/panel.toml
Restart=always
RestartSec=2
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
    cat >"$AGENT_UNIT" <<'EOF'
[Unit]
Description=Kariz agent (connects this server to a Kariz panel)
Documentation=https://github.com/MAHDI-byte64/tun2
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/kariz-panel agent -c /etc/kariz-panel/agent.toml
Restart=always
RestartSec=2
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
}

# Downloads the manager script into $1: the one of the release installed here, so that it
# matches the programs (the panel and the agent put that same one in place when they start),
# else the newest one, from main (a release before the tag existed, or none installed yet).
fetch_manager() {
    local v
    v=$(bin_version "$BIN" 2>/dev/null || true)
    if [[ -n "$v" ]] && fetch "https://raw.githubusercontent.com/$REPO/v$v/scripts/kariz.sh" "$1" 2>/dev/null &&
        bash -n "$1" 2>/dev/null; then
        return 0
    fi
    fetch "$RAW_URL" "$1" && bash -n "$1" 2>/dev/null
}

# Puts this script in place as kariz-manager: from its own file when it is one, else
# from the repository (when it was run through `bash <(curl ...)`).
install_manager() {
    local self=${BASH_SOURCE[0]}
    if [[ -f "$self" && "$(realpath "$self")" != "$MANAGER" ]]; then
        install -m 0755 "$self" "$MANAGER"
    elif [[ ! -f "$MANAGER" ]] || [[ "$(realpath "$self")" != "$MANAGER" ]]; then
        local tmp
        tmp=$(mktemp)
        if fetch_manager "$tmp"; then
            install -m 0755 "$tmp" "$MANAGER"
        else
            warn "Could not install the kariz-manager command (download failed)."
        fi
        rm -f "$tmp"
    fi
}

# A copy of this script run from a file of its own (a new one copied to the server) takes
# the place of the installed kariz-manager at once. Without this it did so only while Kariz
# itself was installed or updated, so with the core up to date the old menu came back from
# the kariz-manager command.
sync_manager() {
    local self=${BASH_SOURCE[0]:-}
    [[ -f "$self" && -f "$MANAGER" && "$EUID" -eq 0 ]] || return 0
    [[ "$(realpath "$self")" != "$(realpath "$MANAGER")" ]] || return 0
    cmp -s "$self" "$MANAGER" && return 0
    if install -m 0755 "$self" "$MANAGER"; then
        ok "This script is now the installed kariz-manager."
    else
        warn "Could not replace $MANAGER with this script."
    fi
}

# Installs Kariz (and the web panel, when the archive carries it) from a release archive
# already on disk — for a server with no internet. $1 is the `.tar.gz`; its `.sha256` (and,
# from 0.11, its `.sig`) must be next to it. The checksum and signature are checked exactly as
# for a download, so an offline install is no less safe than an online one.
install_from_archive() {
    local file=$1
    [[ -s "$file" ]] || die "No archive at $file."
    local dir base name version a tmp
    dir=$(cd "$(dirname "$file")" && pwd) || die "Cannot read the folder of $file."
    base=$(basename "$file")
    name=${base%.tar.gz}
    [[ "$name" != "$base" ]] ||
        die "$base is not a Kariz release archive (expected kariz-VERSION-ARCH-linux.tar.gz)."
    a=$(arch)
    [[ "$name" == *"-$a-linux" ]] ||
        die "$base is not built for this CPU ($a): copy over the -$a-linux archive instead."
    [[ -s "$dir/$base.sha256" ]] ||
        die "The checksum is missing: expected $base.sha256 next to the archive."
    version=$(sed -n 's/^kariz-v\{0,1\}\([0-9][0-9.]*\).*/\1/p' <<<"$name")
    # An unparsable name is treated as a current release, so a missing signature stops it.
    version=${version:-9999}
    tmp=$(mktemp -d)
    if ! { cp "$file" "$tmp/$base" && cp "$dir/$base.sha256" "$tmp/$base.sha256"; }; then
        rm -rf "$tmp"
        die "Could not read the archive and its checksum."
    fi
    [[ -s "$dir/$base.sig" ]] && cp "$dir/$base.sig" "$tmp/$base.sig"
    if ! (cd "$tmp" && sha256sum -c --quiet "$base.sha256"); then
        rm -rf "$tmp"
        die "Checksum mismatch: $base does not match its .sha256 (damaged or the wrong file)."
    fi
    verify_signature "$tmp" "$name" "$version"
    if ! tar -xzf "$tmp/$base" -C "$tmp"; then
        rm -rf "$tmp"
        die "Could not unpack $base."
    fi
    [[ -x "$tmp/$name/kariz" ]] ||
        { rm -rf "$tmp"; die "The archive does not contain the kariz program."; }
    install -m 0755 "$tmp/$name/kariz" "$BIN"
    # Releases from 0.8 carry the web panel and its agent in the same archive.
    if [[ -f "$tmp/$name/kariz-panel" ]]; then
        install -m 0755 "$tmp/$name/kariz-panel" "$PANEL_BIN"
    fi
    rm -rf "$tmp"
    ok "Installed from $base (offline)."
}

# Prints a local release archive for this CPU — kariz-*-<arch>-linux.tar.gz that has its
# .sha256 next to it — looked for in the current folder, next to this script, /root and
# /opt/kariz; the newest version when there is more than one. Nothing when none is found.
find_local_archive() {
    local a self dir f
    a=$(arch)
    self=$(realpath "${BASH_SOURCE[0]:-$0}" 2>/dev/null || true)
    {
        for dir in "$PWD" ${self:+"$(dirname "$self")"} /root /opt/kariz; do
            [[ -d "$dir" ]] || continue
            for f in "$dir"/kariz-*-"$a"-linux.tar.gz; do
                [[ -s "$f" && -s "$f.sha256" ]] && printf '%s\t%s\n' "$(basename "$f")" "$f"
            done
        done
    } 2>/dev/null | sort -V | tail -n1 | cut -f2-
}

cmd_install() {
    need_root
    need_systemd
    local version="" binary="" panel_binary="" archive="" offline=0
    while [[ $# -gt 0 ]]; do
        case $1 in
            --version) version=$2 && shift 2 ;;
            --binary) binary=$2 && shift 2 ;;
            --panel-binary) panel_binary=$2 && shift 2 ;;
            --archive) archive=$2 && shift 2 ;;
            --offline) offline=1 && shift ;;
            *) die "install: unknown option $1" ;;
        esac
    done
    if [[ -n "$panel_binary" ]]; then
        [[ -x "$panel_binary" ]] || die "No executable at $panel_binary."
        install -m 0755 "$panel_binary" "$PANEL_BIN"
    fi
    if [[ -n "$archive" ]]; then
        install_from_archive "$archive"
    elif [[ -n "$binary" ]]; then
        [[ -x "$binary" ]] || die "No executable at $binary."
        install -m 0755 "$binary" "$BIN"
    elif ((offline)); then
        local a found
        a=$(arch)
        found=$(find_local_archive)
        [[ -n "$found" ]] ||
            die "Offline install: no kariz-*-$a-linux.tar.gz found in the current folder, next to this script, /root or /opt/kariz. Copy the archive there with its .sha256 and .sig, or pass --archive FILE."
        install_from_archive "$found"
    else
        local a tmp found
        a=$(arch)
        [[ -n "$version" ]] || version=$(FETCH_MAX=15 latest_version 2>/dev/null || true)
        if [[ -z "$version" ]]; then
            # GitHub could not be reached (no internet, or it is rate-limiting). Fall back to a
            # local archive if one was copied over, else explain the offline install.
            found=$(find_local_archive)
            if [[ -n "$found" ]]; then
                warn "Could not reach GitHub — installing from the local archive found here."
                install_from_archive "$found"
            else
                die "Could not reach GitHub to find the latest release. If this server has no internet, download kariz-<version>-$a-linux.tar.gz with its .sha256 and .sig on a machine that does, copy them next to this script, and run the install again (or: kariz-manager install --archive FILE). If GitHub is limiting you, set GITHUB_TOKEN."
            fi
        else
            info "Downloading Kariz $version for $a"
            local name="kariz-$version-$a-linux"
            tmp=$(mktemp -d)
            download_asset "$version" "$name.tar.gz" "$tmp/$name.tar.gz"
            download_asset "$version" "$name.tar.gz.sha256" "$tmp/$name.tar.gz.sha256"
            # The signature is optional to download (releases before 0.11 have none).
            (download_asset "$version" "$name.tar.gz.sig" "$tmp/$name.tar.gz.sig") 2>/dev/null ||
                rm -f "$tmp/$name.tar.gz.sig"
            (cd "$tmp" && sha256sum -c --quiet "$name.tar.gz.sha256") ||
                die "Checksum mismatch: the download is damaged."
            verify_signature "$tmp" "$name" "$version"
            tar -xzf "$tmp/$name.tar.gz" -C "$tmp"
            install -m 0755 "$tmp/$name/kariz" "$BIN"
            # Releases from 0.8 carry the web panel and its agent in the same archive.
            if [[ -f "$tmp/$name/kariz-panel" ]]; then
                install -m 0755 "$tmp/$name/kariz-panel" "$PANEL_BIN"
            fi
            rm -rf "$tmp"
        fi
    fi
    mkdir -p "$CONF_DIR"
    chmod 700 "$CONF_DIR"
    install_unit
    if [[ -x "$PANEL_BIN" ]]; then
        install_panel_units
    fi
    install_manager
    ok "Installed: $("$BIN" --version)"
    info "Manage it any time with: ${C_BOLD}kariz-manager${C_RESET}"
}

# The version number of an installed program ("kariz 1.4.0" gives 1.4.0), or nothing.
bin_version() {
    { "$1" --version 2>/dev/null || true; } | sed -n 's/^[^0-9]*\([0-9][0-9.]*\).*/\1/p' | head -n 1
}

# Looks for a newer release, and says what here is behind it. Returns 1 (and says nothing)
# when nothing is, when GitHub does not answer in a few seconds, or with
# KARIZ_NO_UPDATE_CHECK set. LATEST and BEHIND are left for the caller.
update_available() {
    [[ -z "${KARIZ_NO_UPDATE_CHECK:-}" ]] || return 1
    LATEST=$(FETCH_MAX=6 latest_version 2>/dev/null || true)
    LATEST=${LATEST#v}
    [[ -n "$LATEST" ]] || return 1
    BEHIND=""
    local v
    if [[ -x "$BIN" ]]; then
        v=$(bin_version "$BIN")
        if [[ -n "$v" ]] && version_lt "$v" "$LATEST"; then BEHIND="the tunnel core $v"; fi
    fi
    if [[ -x "$PANEL_BIN" ]]; then
        v=$(bin_version "$PANEL_BIN")
        if [[ -n "$v" ]] && version_lt "$v" "$LATEST"; then
            BEHIND="${BEHIND:+$BEHIND, }the panel and agent program $v"
        fi
    fi
    [[ -n "$BEHIND" ]]
}

# Tells the user a newer release is out and offers to update everything here (the core,
# the panel and the agent). Asked only at a terminal: `kariz-manager update` does it by hand.
offer_update() {
    update_available || return 0
    OFFERED=1
    echo
    warn "Kariz $LATEST is out. Here: $BEHIND."
    info "An older agent or panel can refuse what the newer panel sends (an auto tunnel, mux settings)."
    if confirm "Update everything on this server now? (running tunnels restart for a moment)" y; then
        (cmd_update) || warn "The update did not finish: kariz-manager update shows why."
    fi
}

# Puts the kariz-manager script of the release now installed in place (a best-effort; the
# running copy goes on, and the menu reopens as the new one: reload_if_replaced).
refresh_manager() {
    local tmp
    tmp=$(mktemp)
    if FETCH_MAX=20 fetch_manager "$tmp" 2>/dev/null; then
        if cmp -s "$tmp" "$MANAGER"; then
            :
        elif install -m 0755 "$tmp" "$MANAGER"; then
            ok "The kariz-manager script is updated."
        else
            warn "Could not replace $MANAGER with the newest script."
        fi
    else
        warn "Could not download the newest kariz-manager script: the old one stays (run the update again later)."
    fi
    rm -f "$tmp"
}

# The checksum of the installed script: to see that an update replaced it under this menu.
manager_sum() { cksum <"$MANAGER" 2>/dev/null || true; }

# The menu that is open is the old script even after an update has written the new one to
# disk (bash has read the old file already). When the installed script is not what runs
# any more, the menu opens again as the new one.
reload_if_replaced() {
    [[ -n "$MANAGER_SUM" && "$(manager_sum)" != "$MANAGER_SUM" ]] || return 0
    local self=${BASH_SOURCE[0]:-}
    # A copy run from a file of its own that was installed as it is has nothing new to show.
    if [[ -f "$self" && "$(realpath "$self")" != "$(realpath "$MANAGER")" ]] && cmp -s "$self" "$MANAGER"; then
        return 0
    fi
    ui_restore_terminal
    info "The kariz-manager script was updated: opening the new menu."
    [[ -n "$IN_FD" ]] && exec {IN_FD}<&-
    exec "$MANAGER"
}

cmd_update() {
    need_root
    need_kariz
    local before local_install=0 a
    before=$("$BIN" --version)
    for a in "$@"; do
        [[ "$a" == --binary || "$a" == --panel-binary || "$a" == --archive || "$a" == --offline ]] && local_install=1
    done
    cmd_install "$@"
    # A copy of this script that is already installed is not replaced by an install: the
    # newest one is fetched (not for an install from files of your own).
    if ((!local_install)) && [[ -z "${KARIZ_NO_UPDATE_CHECK:-}" && "$(realpath "${BASH_SOURCE[0]}" 2>/dev/null)" == "$MANAGER" ]]; then
        refresh_manager
    fi
    local restarted=0
    for unit in $(systemctl list-units --type=service --state=active --plain --no-legend 'kariz@*' | awk '{print $1}'); do
        systemctl restart "$unit" && restarted=$((restarted + 1))
    done
    ok "$before -> $("$BIN" --version); $restarted running tunnel(s) restarted"
    local svc
    for svc in kariz-panel kariz-agent; do
        if systemctl is-active --quiet "$svc"; then
            systemctl restart "$svc"
            info "Restarted $svc."
        fi
    done
    ensure_heal_timer
}

# Removes the private network links (GRE interfaces named kz-...) the panel made here.
remove_net_links() {
    local link
    command -v ip >/dev/null || return 0
    for link in $({ ip -o link show 2>/dev/null || true; } | sed -n 's/^[0-9]*: \(kz-[a-z0-9]*\)[@:].*/\1/p'); do
        ip link del "$link" 2>/dev/null && info "Removed the private network link $link."
    done
    return 0
}

# Removes the agent completely: its service, settings and identity, what it remembers, the
# update files, and the private network links it made.
agent_remove() {
    systemctl disable --now kariz-agent 2>/dev/null || true
    rm -f "$AGENT_UNIT" "$AGENT_CONF" "$PANEL_DIR/link-transport" "$PANEL_DIR/net.toml" "$PANEL_DIR/connected"
    rm -rf "$PANEL_DIR/updates"
    systemctl daemon-reload
    remove_net_links
}

# Removes Kariz from this server completely: the tunnels, the agent, the web panel and the
# programs. It asks once (--yes: no questions, and the configs and the panel's data go too).
cmd_uninstall() {
    need_root
    local yes=${1:-} purge=0 unit tunnels=0
    tunnels=$(systemctl list-unit-files --plain --no-legend 'kariz@*' 2>/dev/null | grep -vc '@\.service' || true)
    if [[ "$yes" != --yes ]]; then
        echo
        warn "This removes Kariz from this server completely:"
        info "every tunnel on it ($tunnels) is stopped and removed,"
        has_agent && info "its agent is removed: the server disconnects from its panel (remove it in the panel too),"
        [[ -f "$PANEL_UNIT" || -f "$PANEL_CONF" ]] && info "the web panel on it is removed,"
        info "and the kariz, kariz-panel and kariz-manager programs go."
        confirm "Remove Kariz completely?" || return 0
        confirm "Also delete the tunnel configs and the panel's data (tokens, servers, certificate)?" && purge=1
    else
        purge=1
    fi
    for unit in $(systemctl list-unit-files --plain --no-legend 'kariz@*' | awk '{print $1}') \
        $(systemctl list-units --all --plain --no-legend 'kariz@*' | awk '{print $1}'); do
        [[ "$unit" == *@.service ]] && continue
        systemctl disable --now "$unit" 2>/dev/null || true
    done
    rm -f "$UNIT" "$BIN"
    if has_agent || [[ -f "$AGENT_UNIT" ]]; then
        agent_remove
        ok "The agent is removed."
    fi
    if [[ -f "$PANEL_UNIT" || -f "$PANEL_CONF" ]]; then
        if ((purge)); then panel_uninstall --yes; else panel_uninstall --yes --keep-data; fi
    fi
    rm -f "$PANEL_BIN"
    systemctl daemon-reload
    if ((purge)); then
        rm -rf "$CONF_DIR" "$PANEL_DIR" "$PANEL_DATA"
    fi
    ok "Kariz is removed."
    rm -f "$MANAGER"
}

# ---- Addresses ----

# The server's own addresses, as defaults for the address the panel is reached at.
own_ip4() {
    { ip -4 route get 1.1.1.1 2>/dev/null || true; } | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -n 1
}

own_ip6() {
    { ip -6 route get 2606:4700:4700::1111 2>/dev/null || true; } | sed -n 's/.* src \([0-9a-fA-F:]*\).*/\1/p' | head -n 1
}

# Whether $1 is a global IPv6 address (not link-local, unique local or loopback).
public_ip6() {
    local a=${1,,}
    [[ "$a" == *:* ]] || return 1
    case $a in
        ::1 | :: | fe[89ab]* | f[cd]* | ff*) return 1 ;;
    esac
    return 0
}

# This server on one line: its name and the IPv4 and IPv6 addresses it has.
server_line() {
    local v4 v6
    v4=$(own_ip4)
    v6=$(own_ip6)
    printf '  %s%s%s' "$C_BOLD" "$(hostname 2>/dev/null || echo this-server)" "$C_RESET"
    if [[ -n "$v4" ]]; then
        printf '   %sIPv4%s %s' "$C_DIM" "$C_RESET" "$v4"
        public_ip4 "$v4" || printf ' %s(private)%s' "$C_DIM" "$C_RESET"
    fi
    if [[ -n "$v6" ]]; then
        printf '   %sIPv6%s %s' "$C_DIM" "$C_RESET" "$v6"
        public_ip6 "$v6" || printf ' %s(private)%s' "$C_DIM" "$C_RESET"
    fi
    [[ -n "$v4$v6" ]] || printf '   %sno network address found%s' "$C_DIM" "$C_RESET"
    echo
}

# Whether the IPv4 address $1 is on one of this server's network interfaces.
ip_is_here() {
    { ip -4 -o addr show 2>/dev/null || true; } | awk -v a="$1" '{ sub(/\/.*/, "", $4); if ($4 == a) f = 1 } END { exit !f }'
}

# ---- The web panel and its agent ----

# The panel's address, certificate and ports, from its settings.
panel_setting() { sed -n "s/^$1 = \"\(.*\)\"/\1/p" "$PANEL_CONF" | head -n 1; }

# What the panel's Let's Encrypt certificate is for (a domain or an IP address); nothing for a
# certificate of your own.
panel_identity() {
    [[ -s "$PANEL_DOMAIN" ]] && head -n 1 "$PANEL_DOMAIN"
    return 0
}

# The server's new IPv4 address, when the panel's certificate is for an IP address the server
# does not have any more and the address it has now is public (one Let's Encrypt can certify).
# Returns 1 when there is none: the certificate is for a domain or of your own, its address is
# still here, or the server is behind NAT (its public address cannot be seen from here, and is
# the one that was typed at install).
panel_new_ip() {
    local old new
    [[ -f "$PANEL_CONF" ]] || return 1
    old=$(panel_identity)
    public_ip4 "$old" || return 1
    ! ip_is_here "$old" || return 1
    new=$(own_ip4)
    [[ -n "$new" && "$new" != "$old" ]] || return 1
    public_ip4 "$new" || return 1
    printf '%s' "$new"
}

# This server's address as another machine would use it: --host, else what the certificate is
# for (the new address when the server's IP address changed), else its IPv4, else IPv6.
panel_host() {
    local host=${1:-}
    [[ -n "$host" ]] || host=$(panel_new_ip) || host=""
    [[ -n "$host" ]] || host=$(panel_identity)
    [[ -n "$host" ]] || host=$(own_ip4)
    [[ -n "$host" ]] || host=$(own_ip6)
    [[ -n "$host" ]] || host="<this-server>"
    printf '%s' "$host"
}

panel_show() {
    local host=$1 fingerprint=${2:-}
    local listen path agent
    listen=$(panel_setting listen)
    path=$(panel_setting path)
    agent=$(panel_setting agent_listen)
    local link
    card_top "Web panel"
    kv "address" "$(url "https://$host:${listen##*:}/$path/")"
    if [[ -n "$(panel_setting cert_file)" ]]; then
        kv "certificate" "$(panel_setting cert_file)"
        kv "" "${C_DIM}not self-signed: no browser warning${C_RESET}"
    elif [[ -n "$fingerprint" ]]; then
        kv "certificate" "SHA-256 $fingerprint"
        kv "" "${C_DIM}self-signed: the browser warns; compare this fingerprint${C_RESET}"
        kv "" "${C_DIM}no warning with a real one: kariz-manager panel cert${C_RESET}"
    fi
    if [[ -n "$agent" ]]; then
        kv "agents" "port ${agent##*:}: TCP and UDP, and TCP and UDP $((${agent##*:} + 1)) ${C_DIM}(open them for the servers you add)${C_RESET}"
    fi
    link=$("$PANEL_BIN" login-link -c "$PANEL_CONF" --host "$host" 2>/dev/null || true)
    kv "sign in" "$(url "$link")"
    kv "" "${C_DIM}works once, for 60 minutes; make another with: kariz-manager panel link${C_RESET}"
    card_end
}

# Reads one line without echo into the variable named $1 (the answer comes from the terminal,
# or from KARIZ_INPUT in the tests).
ask_secret() {
    local _var=$1 _prompt=$2 _s
    open_input
    printf '  %s?%s %s: ' "$C_AQUA" "$C_RESET" "$_prompt"
    if ! IFS= read -r -s -u "$IN_FD" _s; then
        echo
        die "No answer to: $_prompt"
    fi
    echo
    _s=${_s%$'\r'}
    printf -v "$_var" '%s' "$_s"
}

# What is wrong with the password $1, or nothing if it will do: at least 12 characters, three of
# the four kinds (lower case, UPPER CASE, digits, symbols), no common word, no run of one character.
password_problem() {
    local p=$1 low=${1,,} classes=0 w i
    if ((${#p} < 12)); then
        echo "it needs at least 12 characters"
        return 0
    fi
    [[ $p =~ [a-z] ]] && classes=$((classes + 1))
    [[ $p =~ [A-Z] ]] && classes=$((classes + 1))
    [[ $p =~ [0-9] ]] && classes=$((classes + 1))
    [[ $p =~ [^a-zA-Z0-9] ]] && classes=$((classes + 1))
    if ((classes < 3)); then
        echo "use at least three of: lower case, UPPER CASE, digits, symbols"
        return 0
    fi
    for w in password qwerty letmein admin kariz 123456 abcdef iloveyou welcome; do
        if [[ $low == *"$w"* ]]; then
            echo "it holds a common word ($w)"
            return 0
        fi
    done
    for ((i = 0; i + 3 < ${#p}; i++)); do
        if [[ ${p:i:1} == "${p:i+1:1}" && ${p:i:1} == "${p:i+2:1}" && ${p:i:1} == "${p:i+3:1}" ]]; then
            echo "it repeats one character"
            return 0
        fi
    done
    return 0
}

# Asks for a new admin password (twice, hidden) until it is good enough; into the variable named $1.
ask_password() {
    local _var=$1 _p1 _p2 _why
    printf '  %sAt least 12 characters, with three of: lower case, UPPER CASE, digits, symbols.%s\n' "$C_DIM" "$C_RESET"
    while true; do
        ask_secret _p1 "Admin password"
        _why=$(password_problem "$_p1")
        if [[ -n "$_why" ]]; then
            warn "Too weak: $_why."
            continue
        fi
        ask_secret _p2 "Type it again"
        if [[ "$_p1" != "$_p2" ]]; then
            warn "They are not the same."
            continue
        fi
        printf -v "$_var" '%s' "$_p1"
        return
    done
}

# Sets the panel's admin password from the variable named $1 (and signs every session out).
apply_password() {
    local -n _pw=$1
    printf '%s\n' "$_pw" | "$PANEL_BIN" reset-password -c "$PANEL_CONF" --stdin 2>/dev/null
}

# Asked once on a server that has the core but no panel and no agent: should this server get the
# web panel? The answer is remembered, so it is not asked at every start.
PANEL_ASKED=$CONF_DIR/.panel-asked
offer_panel() {
    [[ -z "${KARIZ_NO_OFFER:-}" ]] || return 0
    [[ -x "$BIN" ]] || return 0
    [[ -f "$PANEL_CONF" || -f "$AGENT_CONF" || -f "$PANEL_ASKED" ]] && return 0
    OFFERED=1
    section "The web panel"
    info "This server has no web panel. It is where servers and tunnels are made, in a browser."
    mkdir -p "$CONF_DIR"
    : >"$PANEL_ASKED"
    if confirm "Install the web panel on this server now?" n; then
        (panel_install) || warn "The panel was not installed: kariz-manager panel install shows why."
    else
        info "Any time later: kariz-manager, then 3 (Install the web panel here)."
    fi
}

# Whether there is a terminal to ask questions on (or the tests' answers): a run from a script
# with no terminal, as in CI, goes on with the defaults instead of stopping to ask.
have_terminal() {
    [[ -n "${KARIZ_INPUT:-}" ]] || { : </dev/tty; } 2>/dev/null
}

# Whether $1 can be a server's name in the panel.
valid_server_name() { [[ "$1" =~ ^[A-Za-z0-9._-]{1,40}$ ]]; }

# Asks what this server is called in the panel and puts the answer in the variable named $1.
# The host name is the default; Enter keeps it.
ask_server_name() {
    local _var=$1 _def _reply
    _def=$(hostname 2>/dev/null | tr -c 'A-Za-z0-9._\n-' '-' | cut -c1-40)
    [[ -n "$_def" ]] || _def=panel
    while true; do
        ask _reply "What should this server be called in the panel?" "$_def"
        if valid_server_name "$_reply"; then
            printf -v "$_var" '%s' "$_reply"
            return
        fi
        warn "Letters, digits, - _ . and at most 40 characters."
    done
}

panel_install() {
    need_root
    need_systemd
    local port="" host="" domain="" ip="" email="" yes=0 cert="" key="" name="" password_file="" version=()
    while [[ $# -gt 0 ]]; do
        case $1 in
            --port) port=$2 && shift 2 ;;
            --name) name=${2:-} && shift 2 ;;
            --password-file) password_file=${2:-} && shift 2 ;;
            --host) host=$2 && shift 2 ;;
            --domain) domain=${2:-} && shift 2 ;;
            --ip) ip=${2:-} && shift 2 ;;
            --email) email=${2:-} && shift 2 ;;
            --cert-file) cert=${2:-} && shift 2 ;;
            --key-file) key=${2:-} && shift 2 ;;
            --yes) yes=1 && shift ;;
            --version) version=(--version "$2") && shift 2 ;;
            *) die "panel install: unknown option $1" ;;
        esac
    done
    [[ -z "$cert" && -z "$key" ]] || [[ -f "$cert" && -f "$key" ]] ||
        die "--cert-file and --key-file go together, and both must be files."
    if [[ ! -x "$PANEL_BIN" ]]; then
        cmd_install "${version[@]}"
    fi
    [[ -x "$PANEL_BIN" ]] ||
        die "This Kariz release has no web panel. Install 0.8 or later: kariz-manager update"
    # What this server is called in the panel: asked (the host name is the default), or given
    # with --name; with --yes the host name stays unless --name says otherwise.
    if [[ -z "$name" ]] && ((!yes)) && [[ ! -f "$PANEL_CONF" ]] && have_terminal; then
        ask_server_name name
    fi
    [[ -z "$name" ]] || valid_server_name "$name" ||
        die "The name is letters, digits, - _ . and at most 40 characters."
    local init_args=(-c "$PANEL_CONF" --data-dir "$PANEL_DATA")
    [[ -z "$name" ]] || init_args+=(--name "$name")
    if [[ -n "$port" ]]; then
        init_args+=(--port "$port")
    fi
    mkdir -p "$PANEL_DIR" "$PANEL_DATA"
    chmod 700 "$PANEL_DIR" "$PANEL_DATA"
    # A new panel gets its certificate first (the panel is only ever served over TLS that
    # the browser trusts); one that is already set up keeps what it has.
    if [[ ! -f "$PANEL_CONF" ]]; then
        if [[ -n "$cert" ]]; then
            init_args+=(--cert-file "$(own_file "$cert")" --key-file "$(own_file "$key")")
        else
            choose_identity "$domain" "$ip" "$yes" || die "Cancelled."
            if [[ -z "$email" ]] && ((!yes)); then
                ask email "Email for expiry notices (optional, Enter to skip)" ""
            fi
            get_cert "$CERT_IDENTITY" "$CERT_KIND" "$email" "$yes"
            init_args+=(--cert-file "$CERT_LIVE/fullchain.pem" --key-file "$CERT_LIVE/privkey.pem")
            printf '%s
' "$CERT_IDENTITY" >"$PANEL_DOMAIN"
        fi
    fi
    local out fingerprint
    out=$("$PANEL_BIN" init "${init_args[@]}")
    fingerprint=$(printf '%s\n' "$out" | sed -n 's/.*SHA-256 \([0-9a-f]*\).*/\1/p')
    install_panel_units
    systemctl enable --now kariz-panel
    sleep 2
    systemctl is-active --quiet kariz-panel ||
        die "The panel did not start: journalctl -u kariz-panel -n 50"
    ok "The web panel is running."
    ensure_heal_timer
    # An admin password of your own, so the panel can be opened without a link (a one-time
    # sign-in link works without it): asked, or read from the first line of --password-file.
    local pw="" how=link
    if [[ -n "$password_file" ]]; then
        [[ -f "$password_file" ]] || die "No such file: $password_file"
        pw=$(head -n 1 "$password_file")
        [[ -z "$(password_problem "$pw")" ]] || die "That password is too weak: $(password_problem "$pw")."
    elif ((!yes)) && have_terminal; then
        section "Admin password"
        choose how "How do you want to sign in?" password \
            "password|set an admin password now (recommended)" \
            "link|only the one-time sign-in link for now (set a password later: kariz-manager panel password)"
        [[ "$how" != password ]] || ask_password pw
    fi
    if [[ -n "$pw" ]]; then
        apply_password pw || die "The password could not be set."
        pw=""
        ok "The admin password is set."
    fi
    panel_show "$(panel_host "$host")" "$fingerprint"
    echo
    info "Next: open the address above and sign in. Servers, Add server shows the command that connects another server."
}

# ---- The panel's certificate (Let's Encrypt) ----
#
# The panel is always served over a certificate the browser trusts: for a domain name, or
# for the server's own public IP address (Let's Encrypt issues those for 6 days at a time).
# Both are renewed by a timer, and the panel loads the new one without a restart.

CERTBOT_VENV=/opt/kariz-certbot
RENEW_SERVICE=/etc/systemd/system/kariz-cert-renew.service
RENEW_TIMER=/etc/systemd/system/kariz-cert-renew.timer
# IP address certificates need certbot 5.4 or later, newer than most distributions carry.
CERTBOT_MIN=5.4.0

# Who listens on TCP port $1, one process per line: "unit comm pid" (unit is - when the
# process is not a systemd service).
port_users() {
    local pids pid unit comm
    pids=$({ ss -H -ltnp "sport = :$1" 2>/dev/null || true; } | { grep -o 'pid=[0-9]*' || true; } | sort -u)
    for pid in $pids; do
        pid=${pid#pid=}
        unit=$({ sed -n 's#.*/\([^/]*\.service\)$#\1#p' "/proc/$pid/cgroup" 2>/dev/null || true; } | head -n 1)
        comm=$(cat "/proc/$pid/comm" 2>/dev/null || echo "?")
        printf '%s %s %s\n' "${unit:--}" "$comm" "$pid"
    done
}

# What certbot runs around a request: `pre` stops the services that hold port 80 (Let's
# Encrypt must reach it), `post` starts them again, `deploy` makes the panel load the new
# certificate. The same three run at every renewal, so it keeps working by itself.
cert_hook() {
    local unit comm pid stop=""
    case ${1:-} in
        pre)
            while read -r unit comm pid; do
                [[ -n "${pid:-}" ]] || continue
                if [[ "$unit" == - || "$comm" == docker-proxy ]]; then
                    warn "Port 80 is used by $comm (pid $pid), which this script cannot stop and start again."
                    exit 1
                fi
                [[ " $stop " == *" $unit "* ]] || stop="$stop $unit"
            done < <(port_users 80)
            : >"$ACME_STOPPED"
            for unit in $stop; do
                info "Stopping $unit for a moment (port 80)"
                systemctl stop "$unit"
                echo "$unit" >>"$ACME_STOPPED"
            done
            ;;
        post)
            if [[ -f "$ACME_STOPPED" ]]; then
                while read -r unit; do
                    [[ -n "$unit" ]] || continue
                    info "Starting $unit again"
                    systemctl start "$unit" || warn "Could not start $unit: start it yourself."
                done <"$ACME_STOPPED"
                rm -f "$ACME_STOPPED"
            fi
            ;;
        deploy) systemctl kill -s HUP kariz-panel 2>/dev/null || true ;;
        *) die "cert-hook: pre | post | deploy" ;;
    esac
}

# The absolute path of a certificate or key file of your own. The panel service has a
# private /tmp, so a file there would be invisible to it.
own_file() {
    local f
    f=$(realpath "$1") || die "No such file: $1"
    case $f in
        /tmp/* | /var/tmp/*) die "$f is in /tmp, which the panel service does not see: put it somewhere else (like /etc/kariz-panel/)." ;;
    esac
    printf '%s' "$f"
}

# Sets (or, with no arguments, clears) the panel's own certificate in its settings.
panel_set_cert() {
    local tmp
    tmp=$(mktemp)
    { grep -v -e '^cert_file *=' -e '^key_file *=' "$PANEL_CONF" || true; } >"$tmp"
    if [[ $# -eq 2 ]]; then
        printf 'cert_file = "%s"\nkey_file = "%s"\n' "$1" "$2" >>"$tmp"
    fi
    install -m 0600 "$tmp" "$PANEL_CONF"
    rm -f "$tmp"
}

# Whether the certbot at $1 is new enough.
certbot_ok() {
    local v
    v=$({ "$1" --version 2>&1 || true; } | sed -n 's/^certbot \([0-9][0-9.]*\).*/\1/p')
    [[ -n "$v" ]] && ! version_lt "$v" "$CERTBOT_MIN"
}

# The certbot to use (its path in CERTBOT): the system's if it is new enough, else one of
# our own in a virtualenv, installed with pip.
ensure_certbot() {
    local c
    for c in "$CERTBOT_VENV/bin/certbot" "$(command -v certbot || true)"; do
        if [[ -n "$c" && -x "$c" ]] && certbot_ok "$c"; then
            CERTBOT=$c
            return 0
        fi
    done
    info "This needs certbot $CERTBOT_MIN or later; installing it in $CERTBOT_VENV (python, pip)."
    # Try first: many systems have python with venv already. Where the venv module is a
    # separate package (Debian, Ubuntu), the failure is what tells us so.
    if ! { command -v python3 >/dev/null && rm -rf "$CERTBOT_VENV" && python3 -m venv "$CERTBOT_VENV"; }; then
        info "Installing python with venv and pip."
        if command -v apt-get >/dev/null; then
            apt-get install -y --no-install-recommends python3 python3-venv
        elif command -v dnf >/dev/null; then
            dnf install -y --setopt=install_weak_deps=False python3 python3-pip
        elif command -v yum >/dev/null; then
            yum install -y python3 python3-pip
        elif command -v apk >/dev/null; then
            apk add python3 py3-pip
        else
            die "Install python3 (with venv) yourself, then run this again."
        fi
        rm -rf "$CERTBOT_VENV"
        python3 -m venv "$CERTBOT_VENV" || die "Could not make a python virtualenv in $CERTBOT_VENV (see above)."
    fi
    "$CERTBOT_VENV/bin/pip" install --quiet --upgrade pip certbot ||
        die "pip could not install certbot."
    certbot_ok "$CERTBOT_VENV/bin/certbot" ||
        die "The certbot that got installed is older than $CERTBOT_MIN: update python or install certbot yourself."
    CERTBOT=$CERTBOT_VENV/bin/certbot
}

# Whether $1 is a public IPv4 address: the kind Let's Encrypt can certify.
public_ip4() {
    local a b
    [[ "$1" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || return 1
    a=${BASH_REMATCH[1]} b=${BASH_REMATCH[2]}
    ((a < 256 && b < 256)) || return 1
    ((a == 10 || a == 127 || a == 0 || a >= 224)) && return 1
    ((a == 172 && b >= 16 && b <= 31)) && return 1
    ((a == 192 && b == 168)) && return 1
    ((a == 169 && b == 254)) && return 1
    ((a == 100 && b >= 64 && b <= 127)) && return 1
    return 0
}

# certbot's name for the certificate of one identity (a domain or an IP address).
cert_name() { printf 'kariz-panel-%s' "$(printf '%s' "$1" | tr -c 'a-zA-Z0-9\n' '-')"; }

# The timer that renews the certificate: twice a day, and certbot renews only when it is
# due (an IP address certificate lasts 6 days, so about every 2 to 3 days).
install_renew_timer() {
    cat >"$RENEW_SERVICE" <<EOF
[Unit]
Description=Renew the Kariz panel certificate
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$CERTBOT renew --non-interactive --quiet
EOF
    cat >"$RENEW_TIMER" <<'EOF'
[Unit]
Description=Renew the Kariz panel certificate

[Timer]
OnCalendar=*-*-* 00,12:00:00
RandomizedDelaySec=15min
Persistent=true

[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    systemctl enable --now kariz-cert-renew.timer >/dev/null
}

# The timer that runs `panel heal`: a minute after boot, then every 10 minutes. It only looks
# at the server's addresses, and asks Let's Encrypt for nothing unless the address changed.
install_heal_timer() {
    cat >"$HEAL_SERVICE" <<EOF
[Unit]
Description=Give the Kariz panel a certificate for this server's new IP address
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$MANAGER panel heal
EOF
    cat >"$HEAL_TIMER" <<'EOF'
[Unit]
Description=Give the Kariz panel a certificate for this server's new IP address

[Timer]
OnBootSec=1min
OnUnitActiveSec=10min

[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    systemctl enable --now kariz-panel-heal.timer >/dev/null
}

# A panel with a Let's Encrypt certificate that was set up before `panel heal` existed gets
# its timer. Quiet, and nothing when it is there already.
ensure_heal_timer() {
    [[ "$EUID" -eq 0 && -f "$PANEL_CONF" && -s "$PANEL_DOMAIN" && ! -f "$HEAL_TIMER" ]] || return 0
    [[ -x "$MANAGER" ]] || return 0
    install_heal_timer 2>/dev/null || true
}

# Stops and starts nothing; only says what holds port 80 and asks whether it may be stopped
# for a moment. Returns 1 when it may not.
port80_agreed() {
    local yes=$1 users unit comm pid
    users=$(port_users 80)
    [[ -n "$users" ]] || return 0
    echo
    warn "Port 80 is in use right now:"
    while read -r unit comm pid; do
        printf '      %s (%s, pid %s)\n' "$comm" "${unit/#-/not a service}" "$pid" >&2
    done <<<"$users"
    info "Let's Encrypt has to reach port 80. I can stop it for the few seconds this takes,"
    info "and start it again right after. The same happens each time the certificate is renewed."
    ((yes)) || confirm "Stop it for a moment and start it again afterwards?" y
}

# Gets the certificate for `$1` (a domain, or an IP address with `$2` = ip); the directory
# of its files is left in CERT_LIVE. Not run in $(...): it asks questions.
get_cert() {
    local identity=$1 kind=$2 email=$3 yes=$4
    local name mail=() target=()
    name=$(cert_name "$identity")
    port80_agreed "$yes" || die "Free port 80 (or let me stop it) and run this again."
    ensure_certbot
    [[ -x "$MANAGER" ]] || install_manager
    [[ -x "$MANAGER" ]] || die "The certificate hooks need $MANAGER."
    mail=(--register-unsafely-without-email)
    [[ -z "$email" ]] || mail=(--email "$email")
    if [[ "$kind" == ip ]]; then
        target=(--ip-address "$identity" --preferred-profile shortlived)
    else
        target=(-d "$identity")
    fi
    info "Asking Let's Encrypt for $identity"
    "$CERTBOT" certonly --standalone --preferred-challenges http "${target[@]}" \
        --cert-name "$name" --non-interactive --agree-tos "${mail[@]}" --reuse-key \
        --pre-hook "$MANAGER panel cert-hook pre" \
        --post-hook "$MANAGER panel cert-hook post" \
        --deploy-hook "$MANAGER panel cert-hook deploy" ||
        die "Let's Encrypt did not give a certificate (see above; DNS for a domain, and port 80 reachable from the internet, are the usual reasons)."
    install_renew_timer
    CERT_LIVE=/etc/letsencrypt/live/$name
}

# Asks which it is, a domain or this server's IP address; sets CERT_KIND and CERT_IDENTITY.
# $4: the kind offered first (domain by default).
choose_identity() {
    local domain=$1 ip=$2 yes=$3 first=${4:-domain}
    CERT_KIND="" CERT_IDENTITY=""
    if [[ -n "$domain" ]]; then
        CERT_KIND=domain CERT_IDENTITY=$domain
    elif [[ -n "$ip" ]]; then
        CERT_KIND=ip CERT_IDENTITY=$ip
    else
        local pick
        choose pick "How will you open the panel?" "$first" \
            "domain|I have a domain name that points at this server" \
            "ip|only this server's IP address (a 6-day certificate, renewed by itself)"
        CERT_KIND=$pick
    fi
    if [[ "$CERT_KIND" == domain ]]; then
        [[ -n "$CERT_IDENTITY" ]] || ask CERT_IDENTITY "Domain name (like panel.example.com)"
        [[ "$CERT_IDENTITY" =~ ^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$ ]] ||
            die "That is not a domain name: $CERT_IDENTITY"
        local resolved mine
        resolved=$({ getent ahostsv4 "$CERT_IDENTITY" 2>/dev/null || true; } | awk 'NR==1{print $1}')
        mine=$(own_ip4)
        if [[ -z "$resolved" ]]; then
            warn "$CERT_IDENTITY does not resolve yet: add its DNS record (an A record to ${mine:-this server}) first."
            ((yes)) || confirm "Try anyway?" || return 1
        elif [[ -n "$mine" && "$resolved" != "$mine" ]]; then
            warn "$CERT_IDENTITY points at $resolved, but this server is $mine."
            ((yes)) || confirm "Try anyway?" || return 1
        fi
    else
        [[ -n "$CERT_IDENTITY" ]] || CERT_IDENTITY=$(own_ip4)
        if [[ -z "${ip:-}" ]] && ((!yes)); then
            ask CERT_IDENTITY "This server's public IP address" "$CERT_IDENTITY"
        fi
        public_ip4 "$CERT_IDENTITY" ||
            die "$CERT_IDENTITY is not a public IPv4 address: Let's Encrypt cannot certify it. Use a domain, or the address the internet reaches this server at (--ip ADDRESS)."
    fi
}

# `panel cert`: gets a certificate and makes the panel use it. Run again to change the
# domain or the address.
panel_cert() {
    need_root
    need_systemd
    [[ -f "$PANEL_CONF" ]] || die "The panel is not installed: kariz-manager panel install"
    local domain="" ip="" email="" yes=0 cert="" key=""
    while [[ $# -gt 0 ]]; do
        case $1 in
            --domain) domain=${2:-} && shift 2 ;;
            --ip) ip=${2:-} && shift 2 ;;
            --email) email=${2:-} && shift 2 ;;
            --cert-file) cert=${2:-} && shift 2 ;;
            --key-file) key=${2:-} && shift 2 ;;
            --yes) yes=1 && shift ;;
            *) die "panel cert: [--domain D | --ip ADDRESS] [--email E] [--yes] | --cert-file F --key-file K" ;;
        esac
    done
    if [[ -n "$cert$key" ]]; then
        # A certificate of your own (not renewed by Kariz).
        [[ -f "$cert" && -f "$key" ]] || die "--cert-file and --key-file go together, and both must be files."
        panel_set_cert "$(own_file "$cert")" "$(own_file "$key")"
        rm -f "$PANEL_DOMAIN"
        systemctl restart kariz-panel
        ok "The panel uses your certificate now. Kariz does not renew it: send the panel a SIGHUP after you do (systemctl kill -s HUP kariz-panel)."
        return 0
    fi
    local first=domain
    [[ -n "$domain$ip" ]] || cert_situation first
    choose_identity "$domain" "$ip" "$yes" "$first" || return 0
    if [[ -z "$email" ]] && ((!yes)); then
        ask email "Email for expiry notices (optional, Enter to skip)" ""
    fi
    switch_cert "$CERT_IDENTITY" "$CERT_KIND" "$email" "$yes"
    ok "The panel has a trusted certificate for $CERT_IDENTITY; it renews by itself."
    panel_show "$CERT_IDENTITY"
}

# Says what the panel's certificate is for and whether that still fits this server: its IP
# address changed, or the domain points somewhere else. Sets the variable named $1 to the kind
# to offer first (ip when the certificate is for an IP address).
cert_situation() {
    local _first=domain old new resolved mine
    old=$(panel_identity)
    if [[ -z "$old" ]]; then
        [[ -z "$(panel_setting cert_file)" ]] || info "The panel uses a certificate of your own ($(panel_setting cert_file))."
    elif public_ip4 "$old"; then
        _first=ip
        if new=$(panel_new_ip); then
            warn "The panel's certificate is for $old, but this server's IP address is $new now."
            info "Choose ip and $new below (this is also done by itself within 10 minutes)."
        else
            info "The panel's certificate is for the IP address $old."
        fi
    else
        info "The panel's certificate is for $old."
        resolved=$({ getent ahostsv4 "$old" 2>/dev/null || true; } | awk 'NR==1{print $1}')
        mine=$(own_ip4)
        if [[ -n "$resolved" && -n "$mine" && "$resolved" != "$mine" ]] && ! ip_is_here "$resolved"; then
            warn "$old points at $resolved, not at this server ($mine): change its DNS record, or choose another domain or the IP address."
        fi
    fi
    printf -v "$1" '%s' "$_first"
}

# Gets the certificate for $1 (kind $2: domain or ip), makes the panel use it and removes the
# one it had before. $3: email (may be empty), $4: 1 to ask nothing.
switch_cert() {
    local identity=$1 kind=$2 email=$3 yes=$4 old=""
    get_cert "$identity" "$kind" "$email" "$yes"
    if [[ -s "$PANEL_DOMAIN" ]]; then old=$(cert_name "$(head -n 1 "$PANEL_DOMAIN")"); fi
    panel_set_cert "$CERT_LIVE/fullchain.pem" "$CERT_LIVE/privkey.pem"
    printf '%s\n' "$identity" >"$PANEL_DOMAIN"
    systemctl restart kariz-panel
    sleep 2
    systemctl is-active --quiet kariz-panel ||
        die "The panel did not start with the new certificate: journalctl -u kariz-panel -n 50"
    # The certificate of what it was before is not needed any more (and must not be renewed).
    if [[ -n "$old" && "$old" != "$(cert_name "$identity")" ]]; then
        "$CERTBOT" delete --cert-name "$old" --non-interactive >/dev/null 2>&1 || true
    fi
    install_heal_timer
}

# `panel heal`, run by its timer: when this server's IP address changed (a new one from the
# provider, after the old one was filtered) and the panel's certificate was for the old one,
# gets one for the new address and switches the panel to it, so the panel opens at the new
# address with no browser warning and nothing to do by hand. A request that failed (port 80
# closed, say) is tried again an hour later, not every 10 minutes: Let's Encrypt limits failed
# attempts. Behind NAT the public address cannot be seen from the server: run `panel cert`.
panel_heal() {
    need_root
    local new old now last=()
    new=$(panel_new_ip) || return 0
    old=$(panel_identity)
    now=$(date +%s)
    if [[ -s "$HEAL_FAILED" ]]; then
        read -r -a last <"$HEAL_FAILED" || true
        if [[ "${last[0]:-}" == "$new" && "${last[1]:-0}" =~ ^[0-9]+$ ]] && ((now - last[1] < 3600)); then
            return 0
        fi
    fi
    info "This server's IP address is $new now; the panel's certificate is for $old. Getting one for $new."
    if (switch_cert "$new" ip "" 1); then
        rm -f "$HEAL_FAILED"
        ok "The panel has a certificate for $new: open https://$new:$(panel_setting listen | sed 's/.*://')/$(panel_setting path)/"
    else
        mkdir -p "$PANEL_DATA"
        printf '%s %s\n' "$new" "$now" >"$HEAL_FAILED"
        warn "No certificate for $new yet (see above); trying again in an hour. By hand: kariz-manager panel cert --ip $new"
        return 1
    fi
}

# `tunnel-cert`: a Let's Encrypt certificate for a wss tunnel, with the same machinery as the
# panel's (port 80 is freed for a moment, the renewal timer does the rest). The web panel runs
# it on the server a tunnel listens on; it prints the files as `cert=` and `key=` lines.
cmd_tunnel_cert() {
    need_root
    need_systemd
    local domain="" ip="" email=""
    while [[ $# -gt 0 ]]; do
        case $1 in
            --domain) domain=${2:-} && shift 2 ;;
            --ip) ip=${2:-} && shift 2 ;;
            --email) email=${2:-} && shift 2 ;;
            *) die "tunnel-cert: --domain D | --ip ADDRESS [--email E]" ;;
        esac
    done
    [[ -n "$domain$ip" ]] || die "tunnel-cert: --domain D | --ip ADDRESS [--email E]"
    choose_identity "$domain" "$ip" 1 || die "Cancelled."
    get_cert "$CERT_IDENTITY" "$CERT_KIND" "$email" 1
    printf 'cert=%s/fullchain.pem
key=%s/privkey.pem
' "$CERT_LIVE" "$CERT_LIVE"
}

cmd_panel() {
    local action=${1:-}
    shift || true
    case $action in
        install) panel_install "$@" ;;
        name)
            need_root
            [[ -f "$PANEL_CONF" ]] || die "The panel is not installed: kariz-manager panel install"
            local new=${1:-}
            [[ -n "$new" ]] || ask_server_name new
            valid_server_name "$new" || die "The name is letters, digits, - _ . and at most 40 characters."
            "$PANEL_BIN" init -c "$PANEL_CONF" --data-dir "$PANEL_DATA" --name "$new" >/dev/null
            ok "This server is called $new in the panel."
            ;;
        link)
            need_root
            [[ -f "$PANEL_CONF" ]] || die "The panel is not installed: kariz-manager panel install"
            local host=""
            if [[ ${1:-} == --host ]]; then
                host=${2:-}
            fi
            printf '%s\n' "$(url "$("$PANEL_BIN" login-link -c "$PANEL_CONF" --host "$(panel_host "$host")")")"
            ;;
        password)
            need_root
            [[ -f "$PANEL_CONF" ]] || die "The panel is not installed: kariz-manager panel install"
            if (($# == 0)); then
                # A password of your own, asked twice; --random makes one and shows it, --stdin reads it.
                local pw=""
                ask_password pw
                apply_password pw || die "The password could not be set."
                ok "The admin password is set; every session is signed out."
            else
                if [[ $1 == --random ]]; then
                    "$PANEL_BIN" reset-password -c "$PANEL_CONF"
                else
                    "$PANEL_BIN" reset-password -c "$PANEL_CONF" "$@"
                fi
            fi
            ;;
        status)
            need_systemd
            systemctl status kariz-panel --no-pager || true
            if [[ -f "$PANEL_CONF" ]]; then
                panel_show "$(panel_host "")"
            fi
            ;;
        logs) journalctl -u kariz-panel -n 100 -f ;;
        cert) panel_cert "$@" ;;
        cert-hook) cert_hook "$@" ;;
        heal) panel_heal ;;
        heal-setup)
            need_root
            ensure_heal_timer
            ;;
        uninstall) panel_uninstall "$@" ;;
        *) die "panel: install [--port N] [--domain D | --ip A] [--name NAME] | name [NAME] | link | password [--stdin | --random] | cert [--domain D | --ip A] | heal | status | logs | uninstall [--yes]" ;;
    esac
}

panel_uninstall() {
    need_root
    local yes="" keep=0 a
    for a in "$@"; do
        case $a in
            --yes) yes=--yes ;;
            --keep-data) keep=1 ;;
        esac
    done
    if [[ "$yes" != --yes ]]; then
        confirm "Stop the web panel and remove it?" || return 0
    fi
    systemctl disable --now kariz-panel 2>/dev/null || true
    systemctl disable --now kariz-panel-heal.timer 2>/dev/null || true
    rm -f "$HEAL_SERVICE" "$HEAL_TIMER"
    if [[ -s "$PANEL_DOMAIN" ]]; then
        # Its Let's Encrypt certificate is not renewed any more.
        systemctl disable --now kariz-cert-renew.timer 2>/dev/null || true
        rm -f "$RENEW_SERVICE" "$RENEW_TIMER"
        local c
        for c in "$CERTBOT_VENV/bin/certbot" "$(command -v certbot || true)"; do
            [[ -n "$c" && -x "$c" ]] || continue
            "$c" delete --cert-name "$(cert_name "$(head -n 1 "$PANEL_DOMAIN")")" --non-interactive >/dev/null 2>&1 || true
        done
        rm -f "$PANEL_DOMAIN"
    fi
    rm -f "$PANEL_UNIT"
    systemctl daemon-reload
    if [[ ! -f "$AGENT_CONF" ]]; then
        rm -f "$PANEL_BIN"
    fi
    if ((!keep)) && { [[ "$yes" == --yes ]] || confirm "Also delete the panel's database, certificate and settings (the servers it knows)?"; }; then
        rm -rf "$PANEL_DATA" "$PANEL_CONF"
    fi
    ok "The web panel is removed."
}

# Whether this server already has an agent: its settings, or its service running.
has_agent() {
    [[ -f "$AGENT_CONF" ]] || systemctl is-active --quiet kariz-agent 2>/dev/null
}

# Connects this server to a panel: `kariz-manager --agent CODE`. A server that has an agent
# already is switched to the new panel: the old agent is removed and the new one takes its
# place (asked first, unless --yes).
agent_join() {
    need_root
    need_systemd
    local code=${1:-} version=() yes=0
    shift || true
    while [[ $# -gt 0 ]]; do
        case $1 in
            --version) version=(--version "$2") && shift 2 ;;
            --yes | -y) yes=1 && shift ;;
            *) die "agent: unknown option $1" ;;
        esac
    done
    [[ "$code" == kz1_* ]] || die "That is not a join code (it starts with kz1_). Copy it whole from the panel: Servers, Add server."
    if has_agent; then
        echo
        warn "This server already has a Kariz agent (it is connected to a panel)."
        info "The new code replaces it: the old agent is removed, and the new one takes its place."
        info "The old panel keeps listing this server as offline until you remove it there."
        if ((!yes)); then
            confirm "Replace the old agent with the new one?" y ||
                die "Nothing changed. Run it again with --yes to replace the old agent without asking."
        fi
        systemctl disable --now kariz-agent 2>/dev/null || true
        rm -f "$AGENT_CONF" "$PANEL_DIR/link-transport"
        ok "The old agent is removed."
    fi
    if [[ ! -x "$PANEL_BIN" ]]; then
        cmd_install "${version[@]}"
    elif ((${#version[@]} == 0)) && update_available; then
        # An agent program from an older release may not understand what the panel sends.
        warn "Kariz $LATEST is out, and this server has an older one ($BEHIND): updating it first."
        cmd_install
    fi
    [[ -x "$PANEL_BIN" ]] ||
        die "This Kariz release has no agent. Install 0.8 or later: kariz-manager update, then --agent CODE"
    mkdir -p "$PANEL_DIR"
    chmod 700 "$PANEL_DIR"
    "$PANEL_BIN" agent --join "$code" --no-run -c "$AGENT_CONF"
    install_panel_units
    systemctl enable kariz-agent >/dev/null 2>&1
    # A restart, not just a start: an agent that was running must not keep its old settings.
    systemctl restart kariz-agent
    sleep 2
    systemctl is-active --quiet kariz-agent ||
        die "The agent did not start: journalctl -u kariz-agent -n 50"
    # A server the panel connects to (reverse): its agent listens instead of dialing.
    local listen
    listen=$(sed -n 's/^listen = "\(.*\)"$/\1/p' "$AGENT_CONF" | head -n 1)
    if [[ -n "$listen" ]]; then
        local lport=${listen##*:}
        ok "This server is ready: its agent waits for the panel on port $lport."
        info "Open TCP and UDP $lport and $((lport + 1)) to the panel's address; the panel connects within seconds."
    else
        ok "This server is connected: it shows up in the panel under Servers."
    fi
    info "Follow it with: kariz-manager agent logs"
}

cmd_agent() {
    local action=${1:-}
    case $action in
        kz1_*) agent_join "$@" ;;
        join) shift && agent_join "$@" ;;
        status)
            need_systemd
            systemctl status kariz-agent --no-pager
            ;;
        logs) journalctl -u kariz-agent -n 100 -f ;;
        remove)
            need_root
            agent_remove
            ok "The agent is removed. Remove the server in the panel too (Servers, Remove). Its tunnels keep running."
            ;;
        *) die "agent: CODE | join CODE | status | logs | remove" ;;
    esac
}

# ---- Status ----

# What runs on this server, in a few lines.
cmd_status() {
    [[ -n "$IN_SCREEN" ]] || banner
    server_line
    echo
    if [[ ! -x "$BIN" ]]; then
        warn "Kariz is not installed yet: run kariz-manager install."
        return 0
    fi
    status_rows
    if [[ -f "$PANEL_CONF" ]]; then
        panel_show "$(panel_host "")"
    fi
    if update_available; then
        echo
        warn "Kariz $LATEST is out. Here: $BEHIND. Update: kariz-manager update"
    fi
}

# ---- Menu ----

# The first time on a server: Kariz itself is installed at once, and what else this server
# is for is asked: nothing (tunnels are made from a panel elsewhere), the web panel here, or
# a connection to a panel that exists.
first_run() {
    banner
    server_line
    section "Welcome"
    info "Kariz is not installed on this server yet: installing the core now."
    cmd_install
    section "What else should this server do?"
    local what code
    choose what "Pick one (you can add the others later from this menu)" core \
        "core|only the Kariz core: tunnels are made from a web panel on another server" \
        "panel|also install the web panel here (servers, tunnels and charts in a browser)" \
        "agent|connect this server to a web panel that exists already (needs its join code)"
    mkdir -p "$CONF_DIR"
    : >"$PANEL_ASKED"
    case $what in
        panel) panel_install ;;
        agent)
            ask code "Join code (starts with kz1_)"
            agent_join "$code"
            ;;
        *) ok "Done: the Kariz core is installed. Open the menu again with: kariz-manager" ;;
    esac
}

# One row per line: "id|number|label|hint", "#Section", or "" for a gap. The labels and the
# hints are plain ASCII (no "|"), so their length is their width on the screen.
MENU_ROWS=(
    "#KARIZ"
    "install|1|Install or update Kariz|Download the newest release, check it and install it."
    "status|2|Status and addresses|What runs here, this server's addresses and the panel's address."
    ""
    "#WEB PANEL"
    "panel|3|Install the web panel here|The panel: servers, tunnels and charts in a browser, over HTTPS."
    "link|4|Login link|A one-time login link for the panel (works once, for 60 minutes)."
    "password|5|Admin password|Set a new admin password for the panel."
    "cert|6|New IP, domain or certificate|The server's IP or domain changed, or a new certificate: get one from Let's Encrypt."
    "premove|7|Remove the web panel|Stop and remove the panel. Asks first."
    ""
    "#AGENT"
    "agent|8|Connect to a panel|Paste a panel's join code: this server then shows up in that panel."
    "aremove|9|Remove the agent|Disconnect from the panel; its tunnels keep running. Asks first."
    ""
    "#SYSTEM"
    "logs|10|Live logs|Follow the panel's or the agent's log. Ctrl+C comes back here."
    "uninstall|11|Uninstall Kariz|Remove what Kariz installed on this server. Asks first."
    "exit|0|Exit|Close the menu. Run kariz-manager to open it again."
)
# The items whose number is drawn in red.
MENU_DANGER=" premove aremove uninstall "

MENU_SEL=1     # index in MENU_ROWS of the highlighted item
MENU_TOP=0     # the first row on the screen when the list scrolls
MENU_CHOICE="" # the id of the item that was chosen
MENU_STATUS="" # the status lines, rebuilt each time the menu is shown
MENU_SERVER_LINE=""
MENU_RESIZED=0
MENU_HEAD=() # the logo or the title box, and the status lines, for the current size

menu_is_item() {
    local row=${MENU_ROWS[$1]}
    [[ -n "$row" && "$row" != \#* ]]
}

# menu_move <-1|1>: the highlight goes to the previous or the next item, round the ends.
menu_move() {
    local n=${#MENU_ROWS[@]} i=$MENU_SEL step
    for ((step = 0; step < n; step++)); do
        i=$(((i + $1 + n) % n))
        if menu_is_item "$i"; then
            MENU_SEL=$i
            return 0
        fi
    done
}

# menu_jump <number>: highlights the item with that number; 1 if there is none.
menu_jump() {
    local i row num
    for i in "${!MENU_ROWS[@]}"; do
        menu_is_item "$i" || continue
        row=${MENU_ROWS[i]#*|}
        num=${row%%|*}
        if [[ "$num" == "$1" ]]; then
            MENU_SEL=$i
            return 0
        fi
    done
    return 1
}

# Whether some number starts with $1 and is longer (1 is, with 10 and 11).
menu_has_longer() {
    local i row num
    for i in "${!MENU_ROWS[@]}"; do
        menu_is_item "$i" || continue
        row=${MENU_ROWS[i]#*|}
        num=${row%%|*}
        [[ "$num" == "$1"?* ]] && return 0
    done
    return 1
}

# One line of the status: a dot (green when systemd says "active"), a name and its detail.
state_row() {
    local mark='○' colour=$C_GRAY
    if [[ "$1" == active ]]; then
        mark='●' colour=$C_GREEN
    fi
    printf '  %s%s%s %-10s %s\n' "$colour" "$mark" "$C_RESET" "$2" "$3"
}

# What runs here: the core, the web panel and the agent. $1 = short: the menu's version, with
# the panel's address, and without the commands that would change things.
status_rows() {
    local short=${1:-} running state listen path tip=""
    if [[ -x "$BIN" ]]; then
        running=$(systemctl list-units --type=service --state=active --plain --no-legend 'kariz@*' 2>/dev/null | wc -l)
        state_row active "core" "$("$BIN" --version)  ${C_DIM}·  $((running + 0)) tunnel service(s) running here${C_RESET}"
    else
        state_row inactive "core" "${C_YELLOW}not installed${C_RESET}${C_DIM}: choose 1${C_RESET}"
    fi
    state=$(systemctl is-active kariz-panel 2>/dev/null || true)
    if [[ "$state" == active ]]; then
        if [[ -n "$short" && -f "$PANEL_CONF" ]]; then
            listen=$(panel_setting listen)
            path=$(panel_setting path)
            state_row active "web panel" "$(url "https://$(panel_host ""):${listen##*:}/$path/")"
        else
            state_row active "web panel" "${C_GREEN}running${C_RESET}"
        fi
    elif [[ -f "$PANEL_CONF" ]]; then
        [[ -n "$short" ]] || tip=" ${C_DIM}(journalctl -u kariz-panel)${C_RESET}"
        state_row inactive "web panel" "${C_YELLOW}installed, not running${C_RESET}$tip"
    else
        [[ -n "$short" ]] || tip=" ${C_DIM}(kariz-manager panel install)${C_RESET}"
        state_row inactive "web panel" "${C_DIM}not installed${C_RESET}$tip"
    fi
    # The server's IP address changed and the panel's certificate is for the old one: `panel
    # heal` fixes it by itself, and this says so until it has.
    local new
    if new=$(panel_new_ip); then
        tip="choose 6"
        [[ -n "$short" ]] || tip="kariz-manager panel cert --ip $new"
        state_row inactive "certificate" "${C_YELLOW}for $(panel_identity), but this server is $new now${C_RESET}${C_DIM}: fixed by itself soon, or $tip${C_RESET}"
    fi
    tip=""
    state=$(systemctl is-active kariz-agent 2>/dev/null || true)
    if [[ "$state" == active ]]; then
        state_row active "agent" "${C_GREEN}connected to a panel${C_RESET}"
    elif [[ -f "$AGENT_CONF" ]]; then
        [[ -n "$short" ]] || tip=" ${C_DIM}(journalctl -u kariz-agent)${C_RESET}"
        state_row inactive "agent" "${C_YELLOW}set up, not running${C_RESET}$tip"
    else
        [[ -n "$short" ]] || tip=" ${C_DIM}(kariz-manager --agent CODE)${C_RESET}"
        state_row inactive "agent" "${C_DIM}not set up${C_RESET}$tip"
    fi
}

menu_status_lines() {
    printf '%s\n' "$MENU_SERVER_LINE"
    status_rows short
}

# The part above the list for the current size: the big logo when all of it fits, the title
# box when not.
menu_prepare() {
    local -a lines=()
    mapfile -t lines <<<"$MENU_STATUS"
    if ((UI_ROWS >= 10 + ${#lines[@]} + 1 + ${#MENU_ROWS[@]} + 4 && UI_COLS >= 56)); then
        mapfile -t MENU_HEAD < <(banner)
    else
        mapfile -t MENU_HEAD < <(title_box)
    fi
    MENU_HEAD+=("" "${lines[@]}" "")
}

# menu_draw [typed digits]: the whole menu, in one write, from the top left corner.
menu_draw() {
    local digits=${1:-} w n list_h cap top i row id num label hint title pad colour fill frame=""
    local -a lines=()
    w=$(box_width)
    n=${#MENU_ROWS[@]}
    lines=("${MENU_HEAD[@]}")

    # The list gets the rows that are left; it scrolls, with ▲ and ▼, when they are too few.
    list_h=$((UI_ROWS - ${#MENU_HEAD[@]} - 4))
    ((list_h < 5)) && list_h=5
    if ((n <= list_h)); then
        top=0
        cap=$n
    else
        cap=$((list_h - 2))
        top=$MENU_TOP
        ((MENU_SEL < top)) && top=$MENU_SEL
        ((MENU_SEL >= top + cap)) && top=$((MENU_SEL - cap + 1))
        # The title of a section stays in sight above its first item.
        if ((top > 0 && top == MENU_SEL)) && [[ "${MENU_ROWS[top - 1]}" == \#* ]]; then
            top=$((top - 1))
        fi
        ((top > n - cap)) && top=$((n - cap))
        ((top < 0)) && top=0
        MENU_TOP=$top
        if ((top > 0)); then
            lines+=("  ${C_DIM}${C_GRAY}▲ more${C_RESET}")
        else
            lines+=("")
        fi
    fi

    for ((i = top; i < top + cap && i < n; i++)); do
        row=${MENU_ROWS[i]}
        if [[ -z "$row" ]]; then
            lines+=("")
        elif [[ "$row" == \#* ]]; then
            title=${row#\#}
            pad=$((w - ${#title} - 1))
            ((pad < 1)) && pad=1
            printf -v fill '%*s' "$pad" ''
            lines+=("  ${C_BOLD}${C_PURPLE}${title}${C_RESET} ${C_DIM}${C_AQUA}${fill// /─}${C_RESET}")
        else
            IFS='|' read -r id num label hint <<<"$row"
            colour=$C_TEAL
            [[ "$MENU_DANGER" == *" ${id} "* ]] && colour=$C_RED
            [[ "$id" == exit ]] && colour=$C_GRAY
            ((${#num} < 2)) && num=" ${num}"
            if ((i == MENU_SEL)); then
                # "  ❯ ", then the bar: " NN  label", as wide as the box.
                pad=$((w - 7 - ${#label}))
                ((pad < 1)) && pad=1
                printf -v fill '%*s' "$pad" ''
                lines+=("  ${C_BOLD}${C_TEAL}❯${C_RESET} ${C_SEL}${C_BOLD}${colour} ${num}${C_RESET}${C_SEL}${C_BOLD}  ${label}${fill}${C_RESET}")
            else
                lines+=("     ${colour}${num}${C_RESET}  ${label}")
            fi
        fi
    done

    if ((n > list_h)); then
        if ((top + cap < n)); then
            lines+=("  ${C_DIM}${C_GRAY}▼ more${C_RESET}")
        else
            lines+=("")
        fi
    fi

    IFS='|' read -r _ _ _ hint <<<"${MENU_ROWS[MENU_SEL]}"
    printf -v fill '%*s' "$w" ''
    lines+=("  ${C_DIM}${C_AQUA}${fill// /─}${C_RESET}")
    lines+=("  ${C_TEAL}›${C_RESET} ${hint}")
    if [[ -n "$digits" ]]; then
        lines+=("  ${C_DIM}${C_GRAY}↑/↓ move · Enter open · q quit${C_RESET}   ${C_BOLD}${C_YELLOW}#${digits}${C_RESET}")
    else
        lines+=("  ${C_DIM}${C_GRAY}↑/↓ move · Enter open · a number jumps · q quit${C_RESET}")
    fi

    for row in "${lines[@]}"; do
        frame+="${row}"$'\e[K\n'
    done
    printf '\e[H%s\e[J' "$frame"
}

# The user picks an item; its id goes to MENU_CHOICE.
menu_select() {
    local digits="" last_digit=0 now status=0 _

    if ! ui_interactive; then
        menu_select_plain
        return
    fi

    ui_term_size
    menu_prepare
    # No cursor, no line wrap (each row stays one line), no echo of the keys.
    printf '\e[?25l\e[?7l\e[H\e[2J'
    stty -echo <&"$IN_FD" 2>/dev/null || true
    local redraw=1
    while true; do
        # Drawn again only when something changed: a key, a resize, forgotten digits.
        if ((redraw)); then
            menu_draw "$digits"
            redraw=0
        fi
        status=0
        read_key || status=$?
        if ((status == 1)); then
            MENU_CHOICE="exit"
            break
        fi
        now=${EPOCHREALTIME:-}
        now=${now//[!0-9]/}
        [[ -n "$now" ]] || now=$((SECONDS * 1000000))
        if ((status == 2)); then
            if ((MENU_RESIZED)); then
                MENU_RESIZED=0
                ui_term_size
                menu_prepare
                printf '\e[H\e[2J'
                redraw=1
            fi
            # Half-typed digits are forgotten after a pause.
            if [[ -n "$digits" ]] && ((now - last_digit > 1500000)); then
                digits=""
                redraw=1
            fi
            continue
        fi
        redraw=1
        case "$UI_KEY" in
            up | k) menu_move -1 ;;
            down | j | $'\t') menu_move 1 ;;
            home)
                MENU_SEL=0
                menu_move 1
                ;;
            end) MENU_SEL=$((${#MENU_ROWS[@]} - 1)) ;;
            pgup) for _ in 1 2 3 4 5; do menu_move -1; done ;;
            pgdn) for _ in 1 2 3 4 5; do menu_move 1; done ;;
            [0-9])
                # "1" and then "0" within a moment reaches item 10.
                if [[ -n "$digits" ]] && ((now - last_digit < 1500000)) && menu_jump "${digits}${UI_KEY}"; then
                    digits+="$UI_KEY"
                else
                    digits=$UI_KEY
                    menu_jump "$digits" || digits=""
                fi
                last_digit=$now
                # Nothing longer can follow (the 5 in 1-11, or 10): the buffer is dropped.
                if [[ -n "$digits" ]] && ! menu_has_longer "$digits"; then
                    digits=""
                fi
                ;;
            backspace) digits="" ;;
            enter | ' ')
                IFS='|' read -r MENU_CHOICE _ <<<"${MENU_ROWS[MENU_SEL]}"
                break
                ;;
            q | Q | esc)
                MENU_CHOICE="exit"
                break
                ;;
        esac
    done
    ui_restore_terminal
}

# The menu as numbers and lines, for input that is not a terminal.
menu_select_plain() {
    local row id num label answer
    banner
    printf '%s\n\n' "$MENU_STATUS"
    for row in "${MENU_ROWS[@]}"; do
        if [[ "$row" == \#* ]]; then
            printf '  %s%s%s\n' "$C_PURPLE" "${row#\#}" "$C_RESET"
        elif [[ -n "$row" ]]; then
            IFS='|' read -r id num label _ <<<"$row"
            printf '   %s%2s%s) %s\n' "$C_TEAL" "$num" "$C_RESET" "$label"
        fi
    done
    echo
    ask answer "Choose"
    MENU_CHOICE=""
    case $answer in
        0 | q) MENU_CHOICE="exit" ;;
        "") ;;
        *)
            if menu_jump "$answer"; then
                IFS='|' read -r MENU_CHOICE _ <<<"${MENU_ROWS[MENU_SEL]}"
            else
                warn "Choose a number from the list (0 leaves)."
            fi
            ;;
    esac
}

menu_goodbye() {
    ui_restore_terminal
    if [[ -t 1 ]]; then
        printf '\e[H\e[2J'
    fi
    printf '\n  %sKariz manager closed. Run %s%skariz-manager%s%s to open the menu again.%s\n\n' \
        "$C_TEAL" "$C_RESET" "$C_BOLD" "$C_RESET" "$C_TEAL" "$C_RESET"
    exit 0
}

# Ctrl+C at the menu itself leaves the manager. During a screen (which runs in a subshell,
# and so ends on it) it comes back to the menu at once.
MENU_BUSY=0 INTERRUPTED=0 IN_SCREEN="" OFFERED=0 MANAGER_SUM=""
on_interrupt() {
    if ((MENU_BUSY)); then
        INTERRUPTED=1
    else
        menu_goodbye
    fi
}

# One screen of the menu: cleared, the title on top, the action, and "press any key" before
# the menu is drawn over it. The action runs in a subshell, so an error or Ctrl+C in it
# returns to the menu.
run_screen() {
    MENU_BUSY=1 INTERRUPTED=0 IN_SCREEN=1
    ui_restore_terminal
    if ui_interactive; then
        screen_header
    fi
    ("$@") || true
    ui_restore_terminal
    if ((INTERRUPTED)); then
        printf '\n  %s‹ Back to the menu%s\n' "$C_DIM$C_GRAY" "$C_RESET"
        ui_interactive && sleep 0.4
    else
        (pause) || true
    fi
    MENU_BUSY=0 IN_SCREEN=""
}

screen_install() {
    if [[ -x "$BIN" ]]; then
        cmd_update
    else
        cmd_install
    fi
}

screen_agent() {
    local code
    ask code "Join code (starts with kz1_)"
    agent_join "$code"
}

screen_agent_remove() {
    has_agent || {
        warn "This server has no agent."
        return 0
    }
    confirm "Disconnect this server from its panel? (its tunnels keep running)" || return 0
    cmd_agent remove
}

screen_logs() {
    local which
    choose which "Which log?" panel \
        "panel|the web panel" \
        "agent|the agent (this server's link to a panel)"
    info "Following the $which's log: Ctrl+C comes back to the menu."
    journalctl -u "kariz-$which" -n 100 -f
}

menu() {
    need_root
    need_systemd
    open_input
    set +e
    trap on_interrupt INT
    trap 'MENU_RESIZED=1' WINCH
    trap ui_restore_terminal EXIT
    MANAGER_SUM=$(manager_sum)
    ensure_heal_timer
    if [[ ! -x "$BIN" ]]; then
        # An action that fails ends it, as in the menu; the menu opens after it.
        (first_run) || true
        OFFERED=1
    else
        offer_update
        offer_panel
    fi
    # The menu clears the screen: what was printed before it (the panel's address and login
    # link, an update) stays until a key is pressed.
    if ((OFFERED)) && ui_interactive; then
        (pause) || true
    fi
    # Looked up once: the addresses can take a moment to find behind NAT.
    MENU_SERVER_LINE=$(server_line)
    MENU_SEL=1
    while true; do
        reload_if_replaced
        MENU_STATUS=$(menu_status_lines)
        menu_select
        case $MENU_CHOICE in
            install) run_screen screen_install ;;
            status) run_screen cmd_status ;;
            panel) run_screen panel_install ;;
            link) run_screen cmd_panel link ;;
            password) run_screen cmd_panel password ;;
            cert) run_screen cmd_panel cert ;;
            premove) run_screen cmd_panel uninstall ;;
            agent) run_screen screen_agent ;;
            aremove) run_screen screen_agent_remove ;;
            logs) run_screen screen_logs ;;
            uninstall) run_screen cmd_uninstall ;;
            exit) menu_goodbye ;;
            *) ;;
        esac
    done
}

usage() {
    banner
    cat <<EOF
  Usage: kariz-manager [command]      (no command: the menu)

  Tunnels, servers, private networks and updates of other servers are made in the web
  panel (docs/panel.md). This script installs Kariz and the panel on a server.

  install [--version vX.Y.Z] [--binary PATH]   install Kariz (latest release by default)
          [--archive FILE] [--offline]         offline: from a release .tar.gz on disk, or a
                                               kariz-*-ARCH-linux.tar.gz copied next to this script
  update  [--version vX.Y.Z]                   update Kariz and restart what runs
  uninstall [--yes]                            also deletes the configs with --yes
  panel install [--port N] [--domain D | --ip ADDRESS] [--email E] [--name NAME] [--yes]
                                               [--password-file F: its first line is the admin password]
                                               the web panel on this server, with a Let's
                                               Encrypt certificate for the domain or IP address
  panel cert [--domain D | --ip ADDRESS]       change its domain or address (renewal is automatic)
  panel heal                                   a certificate for this server's new IP address,
                                               if it changed (a timer runs this every 10 minutes)
  panel cert --cert-file F --key-file K        use a certificate of your own instead
  panel link | password [--stdin] | status | logs | uninstall [--yes]
  --agent CODE [--version V] [--yes]           connect this server to a panel (an agent that is
                                               here already is replaced by the new one)
  agent status | logs | remove
  status                                       what runs here, and this server's addresses
  tunnel-cert --domain D | --ip A [--email E]  a Let's Encrypt certificate for a wss tunnel (the
                                               panel runs this on the server the tunnel listens on)

  Set GITHUB_TOKEN if GitHub limits your downloads.
EOF
}

main() {
    case ${1:-} in
        help | -h | --help | tunnel-cert) ;;
        *) sync_manager ;;
    esac
    case ${1:-} in
        "") menu ;;
        install) shift && cmd_install "$@" ;;
        update) shift && cmd_update "$@" ;;
        uninstall) cmd_uninstall "${2:-}" ;;
        panel) shift && cmd_panel "$@" ;;
        agent) shift && cmd_agent "$@" ;;
        --agent) shift && agent_join "$@" ;;
        status) cmd_status ;;
        tunnel-cert) shift && cmd_tunnel_cert "$@" ;;
        help | -h | --help) usage ;;
        *) usage && exit 1 ;;
    esac
}

# Not when sourced (the tests load the functions). Piped into bash, there is no source
# file at all.
if [[ "${BASH_SOURCE[0]:-$0}" == "$0" ]]; then
    main "$@"
fi
