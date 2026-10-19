#!/usr/bin/env bash
# Sigelith Hourglass (Klepsydra) - instalacja fazy 0 na serwerze produkcyjnym (AlmaLinux, systemd).
#
# Pliki leza na serwerze w kopii repo, pod tymi samymi sciezkami co w repo:
#   deploy/*               ten skrypt, hourglass_sync.py, jednostki systemd
#   deploy/dist/hourglass  prover na Linuksa - tryb BINARNY; suma w dist/hourglass.sha256
#   prover/cavp/*.rsp      wektory NIST CAVP
# Uruchamiac jako root:
#   bash deploy/install.sh check      suma, autotest, NIST, pomiar - niczego nie instaluje
#   bash deploy/install.sh install    uzytkownik, pliki, uslugi; rusza tylko synchronizacja wejsc
#   bash deploy/install.sh start N    genesis (RAZ - Klepsydra nigdy nie startuje od zera) i prover
#   bash deploy/install.sh upgrade    nowy plik provera: stop, podmiana, start - stan zostaje
#   bash deploy/install.sh status     uslugi, stan, ostatnie odcinki, metryki, dziennik
#   bash deploy/install.sh move-data  jednorazowo: dane z /srv/hourglass/data do katalogu ponizej
#
# Program: /usr/local/bin/hourglass i /usr/local/lib/hourglass/ (wlasnosc root, domyslne etykiety
# SELinux tych katalogow). Dane: /srv/docker_data/beattime/hourglass (wlasnosc hourglass) - jak
# pozostale dane projektu, objete nocna kopia zapasowa serwera. HOURGLASS.md D13, D16, 3.8.
# Po odtworzeniu z kopii prover rusza WYLACZNIE od ostatniego opublikowanego rekordu - nigdy ze
# starszego stanu (deploy/README.md, "Backups and restore").
set -euo pipefail

SRC="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
CAVP_SRC="$SRC/../prover/cavp"
BIN=/usr/local/bin/hourglass
LIB=/usr/local/lib/hourglass
DATA=/srv/docker_data/beattime/hourglass
OLD_DATA=/srv/hourglass/data      # do 2026-10-19; tylko dla move-data
UNITS="hourglass-p0.service hourglass-sync.service hourglass-sync.timer"
CAVP_FILES="SHA256ShortMsg.rsp SHA256LongMsg.rsp SHA256Monte.rsp"
# parametry fazy 0 (SPEC.md par. 6, HOURGLASS.md D8)
T=256
LAMBDA=100
K=20

die() { echo "BLAD: $*" >&2; exit 1; }
need_root() { [ "$(id -u)" = 0 ] || die "uruchom jako root"; }
prover_active() { systemctl is-active --quiet hourglass-p0.service; }

# plik tekstowy z LF niezaleznie od sposobu przeniesienia na serwer; podmiana atomowa
put_text() {
    sed 's/\r$//' "$1" > "$2.tmp"
    chmod 644 "$2.tmp"
    mv -f "$2.tmp" "$2"
}

check_sum() {
    local want have
    [ -f "$SRC/dist/hourglass" ] || die "brak $SRC/dist/hourglass - wgraj go w trybie BINARNYM"
    want="$(tr -d '\r' < "$SRC/dist/hourglass.sha256" | cut -c1-64)"
    have="$(sha256sum "$SRC/dist/hourglass" | cut -c1-64)"
    [ "$want" = "$have" ] || die "dist/hourglass ma inna sume SHA-256 niz dist/hourglass.sha256 - wgraj go ponownie w trybie BINARNYM"
    echo "== plik provera: SHA-256 zgodna ($have)"
}

copy_files() {
    check_sum
    install -m 755 "$SRC/dist/hourglass" "$BIN"
    install -d -m 755 "$LIB" "$LIB/cavp"
    put_text "$SRC/hourglass_sync.py" "$LIB/hourglass_sync.py"
    for f in $CAVP_FILES; do put_text "$CAVP_SRC/$f" "$LIB/cavp/$f"; done
    for u in $UNITS; do put_text "$SRC/$u" "/etc/systemd/system/$u"; done
    systemctl daemon-reload
}

case "${1:-}" in
check)
    need_root
    check_sum
    TMP="$(mktemp -d)"
    trap 'rm -rf "$TMP"' EXIT
    install -m 755 "$SRC/dist/hourglass" "$TMP/hourglass"
    echo "== system: $(uname -m), $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ *//'), $(nproc) rdzenie"
    echo "== $(stat -fc %T /sys/fs/cgroup), $(systemctl --version 2>/dev/null | head -1 || true)"
    "$TMP/hourglass" selftest
    "$TMP/hourglass" cavp "$CAVP_SRC"
    echo "== pomiar na jednym rdzeniu, niski priorytet (ok. 1 minuty):"
    nice -n 19 "$TMP/hourglass" bench-sha --mb 256
    nice -n 19 "$TMP/hourglass" bench --n 24 --backend best
    echo "== $(python3 --version 2>&1 || true); chrony: $(chronyc -c tracking 2>/dev/null | cut -d, -f2,5 || true)"
    echo "== CHECK OK"
    ;;
install)
    need_root
    prover_active && die "prover liczy - nowy plik provera: install.sh upgrade"
    copy_files
    id hourglass >/dev/null 2>&1 || useradd --system --user-group --home-dir "$DATA" --shell /sbin/nologin hourglass
    install -d -o hourglass -g hourglass -m 750 "$DATA"
    systemctl enable --now hourglass-sync.timer
    systemctl start hourglass-sync.service
    [ -s "$DATA/inputs.txt" ] || die "synchronizacja nie zapisala $DATA/inputs.txt - zobacz: journalctl -u hourglass-sync -n 20"
    echo "== wejscia do ziarna ($DATA/inputs.txt):"
    cat "$DATA/inputs.txt"
    echo "== INSTALL OK - prover jeszcze nie liczy; start: bash $SRC/install.sh start N"
    ;;
start)
    need_root
    N="${2:-}"
    { [[ "$N" =~ ^[0-9]+$ ]] && [ "$N" -ge 20 ] && [ "$N" -le 40 ]; } || die "podaj n (20..40) - glebokosc odcinka, np. 31"
    if [ ! -x "$BIN" ] || [ ! -d "$DATA" ]; then die "najpierw: install.sh install"; fi
    if [ -e "$DATA/genesis.json" ] || [ -e "$DATA/genesis.txt" ] || [ -e "$DATA/state.txt" ]; then
        die "genesis juz istnieje - Klepsydra nigdy nie startuje od zera (HOURGLASS.md D7)"
    fi
    systemctl start hourglass-sync.service
    echo "== genesis: pomiar rozruchowy 20 s, potem zapis"
    runuser -u hourglass -- "$BIN" genesis --dir "$DATA" --n "$N" --t "$T" --lambda "$LAMBDA" --k "$K" --bench-seconds 20
    systemctl enable --now hourglass-p0.service
    systemctl start hourglass-sync.service      # stempel genesis.json
    echo "== genesis.json:"
    cat "$DATA/genesis.json"; echo
    if [ -s "$DATA/genesis.receipt.json" ]; then echo "== stempel genesis: zapisany"; else echo "== stempel genesis: jeszcze nie - synchronizacja ponowi za minute"; fi
    systemctl is-active hourglass-p0.service
    echo "== START OK"
    ;;
upgrade)
    need_root
    check_sum >/dev/null      # zla suma = prover nawet nie zostaje zatrzymany
    was_active=0
    if prover_active; then was_active=1; fi
    systemctl stop hourglass-p0.service
    copy_files
    if [ "$was_active" = 1 ]; then systemctl start hourglass-p0.service; fi
    "$BIN" selftest
    echo "== UPGRADE OK (prover: $(systemctl is-active hourglass-p0.service || true))"
    ;;
move-data)
    # Jednorazowo (2026-10-19): dane z /srv/hourglass/data do katalogu danych projektu, objetego
    # nocna kopia zapasowa. Najpierw wszystkie sprawdzenia - przy pierwszym problemie nic nie zmieniamy.
    need_root
    [ -d "$OLD_DATA" ] || die "brak $OLD_DATA - dane sa juz przeniesione albo nigdy tam nie byly; nic nie zmieniam"
    [ ! -e "$DATA" ] || die "$DATA juz istnieje - nic nie zmieniam"
    parent="$(dirname "$DATA")"
    [ -d "$parent" ] || die "brak $parent - nic nie zmieniam"
    runuser -u hourglass -- test -x "$parent" || die "uzytkownik hourglass nie moze wejsc do $parent (uprawnienia) - nic nie zmieniam"
    [ "$(stat -c %d "$OLD_DATA")" = "$(stat -c %d "$parent")" ] || die "inny system plikow - przeniesienie nie byloby atomowe; nic nie zmieniam"
    check_sum >/dev/null
    was_active=0
    if prover_active; then was_active=1; fi
    systemctl stop hourglass-sync.timer hourglass-p0.service
    systemctl stop hourglass-sync.service || true
    mv "$OLD_DATA" "$DATA"
    copy_files                              # jednostki z nowa sciezka
    usermod -d "$DATA" hourglass
    rmdir /srv/hourglass 2>/dev/null || true
    systemctl start hourglass-sync.timer
    if [ "$was_active" = 1 ]; then systemctl start hourglass-p0.service; fi
    echo "== dane: $DATA"
    grep -E '^(j|active|next_leaf)=' "$DATA/state.txt" || true
    ls -1 "$DATA"
    echo "== MOVE OK (prover: $(systemctl is-active hourglass-p0.service || true), synchronizacja: $(systemctl is-active hourglass-sync.timer || true))"
    ;;
status)
    systemctl --no-pager --lines=0 status hourglass-p0.service hourglass-sync.timer || true
    echo "== stan:"
    grep -E '^(j|active|next_leaf|last_save_utc)=' "$DATA/state.txt" 2>/dev/null || echo "(brak - genesis jeszcze nie bylo)"
    echo "== ostatnie pliki odcinkow:"
    ls -1 "$DATA/segments" 2>/dev/null | tail -n 6 || true
    echo "== metryki (utc,j,next_leaf,nodes_per_s,loadavg1,steal_permille,ptb_offset_us):"
    m="$(ls -1 "$DATA"/metrics/metrics-*.csv 2>/dev/null | tail -n 1 || true)"
    if [ -n "$m" ]; then tail -n 3 "$m"; fi
    echo "== dziennik:"
    journalctl --no-pager -n 6 -u hourglass-p0.service -u hourglass-sync.service || true
    ;;
*)
    sed -n '2,20p' "$0"
    exit 2
    ;;
esac
