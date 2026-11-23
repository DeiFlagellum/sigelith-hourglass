#!/usr/bin/env bash
# Sigelith Hourglass (Klepsydra) - instalacja na serwerze produkcyjnym (AlmaLinux, systemd): faza 0 i v1.
#
# Pliki leza na serwerze w kopii repo, pod tymi samymi sciezkami co w repo:
#   deploy/*               ten skrypt, hourglass_sync.py, jednostki systemd
#   deploy/dist/hourglass  prover na Linuksa - tryb BINARNY; suma w dist/hourglass.sha256
#   prover/cavp/*.rsp      wektory NIST CAVP
# Uruchamiac jako root:
#   bash deploy/install.sh check       suma, autotest, NIST, pomiar - niczego nie instaluje
#   bash deploy/install.sh upgrade     nowy plik provera: stop, podmiana, start - stan zostaje (p0 i v1)
# faza 0 (p0):
#   bash deploy/install.sh install     uzytkownik, pliki, uslugi; rusza tylko synchronizacja wejsc
#   bash deploy/install.sh start N     genesis (RAZ - Klepsydra nigdy nie startuje od zera) i prover
#   bash deploy/install.sh status      uslugi, stan, ostatnie odcinki, metryki, dziennik
#   bash deploy/install.sh move-data   jednorazowo: dane z /srv/hourglass/data do katalogu ponizej
#   bash deploy/install.sh stop-p0     przejscie na v1: prover p0 wylaczony na stale, ostatnie stemple
# v1 (SPEC.md v1; HOURGLASS.md pkt 8, D5, D17):
#   bash deploy/install.sh install-v1  pliki, katalog v1, synchronizacja wejsc v1 (bez stempli)
#   bash deploy/install.sh start-v1    genesis v1 (RAZ; operator i predkosc odniesienia) i prover v1
#   bash deploy/install.sh status-v1   uslugi, stan, ostatnie odcinki, metryki, dziennik v1
#
# Program: /usr/local/bin/hourglass i /usr/local/lib/hourglass/ (wlasnosc root, domyslne etykiety
# SELinux tych katalogow). Dane (wlasnosc hourglass): p0 /srv/docker_data/beattime/hourglass, v1
# /srv/docker_data/beattime/hourglass-v1 - jak pozostale dane projektu, objete nocna kopia zapasowa
# serwera. HOURGLASS.md D13, D16, 3.8. v1: prover zapisuje rekordy BEZ podpisu; podpisuje je i stempluje
# serwer Sigelith przy publikacji (apps/tsa/hourglass.py), a kontenery strony widza katalog v1 tylko
# do odczytu. Po odtworzeniu z kopii prover rusza WYLACZNIE od ostatniego opublikowanego rekordu -
# nigdy ze starszego stanu (deploy/README.md, "Backups and restore").
set -euo pipefail

SRC="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
CAVP_SRC="$SRC/../prover/cavp"
BIN=/usr/local/bin/hourglass
LIB=/usr/local/lib/hourglass
DATA=/srv/docker_data/beattime/hourglass
DATA_V1=/srv/docker_data/beattime/hourglass-v1
OLD_DATA=/srv/hourglass/data      # do 2026-10-19; tylko dla move-data
UNITS="hourglass-p0.service hourglass-sync.service hourglass-sync.timer hourglass-v1.service hourglass-v1-sync.service hourglass-v1-sync.timer"
CAVP_FILES="SHA256ShortMsg.rsp SHA256LongMsg.rsp SHA256Monte.rsp"
# parametry fazy 0 i v1 (SPEC.md par. 6, HOURGLASS.md D8, O2, O4)
T=256
LAMBDA=100
K=20
# v1: operator zegara, wspolna predkosc odniesienia i glebokosc odcinka (SPEC.md par. 7, 10; D17, O2)
OPERATOR=sigelith.org
S_REF=1308141
N_V1=32

die() { echo "BLAD: $*" >&2; exit 1; }
need_root() { [ "$(id -u)" = 0 ] || die "uruchom jako root"; }
p0_active() { systemctl is-active --quiet hourglass-p0.service; }
v1_active() { systemctl is-active --quiet hourglass-v1.service; }
v1_exists() { [ -e "$DATA_V1/genesis.json" ] || [ -e "$DATA_V1/genesis.txt" ] || [ -e "$DATA_V1/state.txt" ]; }

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

# katalog danych uzytkownika hourglass (takze gdy istnieje, np. zalozony przez Dockera przy montowaniu)
data_dir() {
    id hourglass >/dev/null 2>&1 || useradd --system --user-group --home-dir "$1" --shell /sbin/nologin hourglass
    install -d -m 750 "$1"
    chown hourglass:hourglass "$1"
    chmod 750 "$1"
}

# rekordy p0 bez kwitu stempla (plik <nazwa>.receipt.json obok)
p0_unstamped() {
    local f
    for f in "$DATA"/genesis.json "$DATA"/segments/[0-9]*.json; do
        [ -e "$f" ] || continue
        case "$f" in *.receipt.json) continue ;; esac
        [ -e "${f%.json}.receipt.json" ] || echo "$f"
    done
}

show_status() {   # katalog, usluga provera, timer synchronizacji, usluga synchronizacji
    systemctl --no-pager --lines=0 status "$2" "$3" || true
    echo "== stan:"
    grep -E '^(j|active|next_leaf|last_save_utc)=' "$1/state.txt" 2>/dev/null || echo "(brak - genesis jeszcze nie bylo)"
    echo "== ostatnie pliki odcinkow:"
    ls -1 "$1/segments" 2>/dev/null | tail -n 6 || true
    echo "== metryki (utc,j,next_leaf,nodes_per_s,loadavg1,steal_permille,ptb_offset_us):"
    m="$(ls -1 "$1"/metrics/metrics-*.csv 2>/dev/null | tail -n 1 || true)"
    if [ -n "$m" ]; then tail -n 3 "$m"; fi
    echo "== dziennik:"
    journalctl --no-pager -n 6 -u "$2" -u "$4" || true
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
    p0_active && die "prover liczy - nowy plik provera: install.sh upgrade"
    v1_exists && die "faza 0 zakonczona (jest genesis v1) - dla v1: install.sh install-v1 albo upgrade"
    copy_files
    data_dir "$DATA"
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
    was_p0=0
    was_v1=0
    if p0_active; then was_p0=1; systemctl stop hourglass-p0.service; fi
    if v1_active; then was_v1=1; systemctl stop hourglass-v1.service; fi
    copy_files
    if [ "$was_p0" = 1 ]; then systemctl start hourglass-p0.service; fi
    if [ "$was_v1" = 1 ]; then systemctl start hourglass-v1.service; fi
    "$BIN" selftest
    echo "== UPGRADE OK (prover p0: $(systemctl is-active hourglass-p0.service || true), v1: $(systemctl is-active hourglass-v1.service || true))"
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
    if p0_active; then was_active=1; fi
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
stop-p0)
    # Przejscie na v1 (HOURGLASS.md pkt 12): ciag p0 konczy sie w chwili startu v1. Prover p0 zostaje
    # wylaczony na stale (po restarcie serwera tez nie wstanie); genesis, rekordy, dowody i kwity
    # zostaja na miejscu i sa publiczne. Odcinek liczony w chwili zatrzymania nie bedzie rekordem.
    need_root
    [ -s "$DATA/genesis.json" ] || die "brak genesis p0 w $DATA - nic do zatrzymania"
    systemctl disable --now hourglass-p0.service
    # ostatnie stemple rekordow p0 (synchronizacja stempluje do 5 plikow na przebieg)
    for _ in 1 2 3 4 5 6; do
        [ -z "$(p0_unstamped)" ] && break
        systemctl start hourglass-sync.service || true
    done
    systemctl disable --now hourglass-sync.timer
    left="$(p0_unstamped | wc -l)"
    last="$(ls -1 "$DATA/segments" 2>/dev/null | grep -E '^[0-9]+\.json$' | tail -n 1 || true)"
    echo "== p0: ostatni rekord ${last:-brak}; rekordy bez stempla: $left"
    [ "$left" = 0 ] || echo "UWAGA: reszta stempli: systemctl start hourglass-sync.service (powtarzac, az bedzie 0)"
    echo "== STOP-P0 OK (prover p0: $(systemctl is-active hourglass-p0.service || true), synchronizacja p0: $(systemctl is-active hourglass-sync.timer || true); dane: $DATA)"
    ;;
install-v1)
    need_root
    v1_active && die "prover v1 liczy - nowy plik provera: install.sh upgrade"
    copy_files
    data_dir "$DATA_V1"
    systemctl enable --now hourglass-v1-sync.timer
    systemctl start hourglass-v1-sync.service
    [ -s "$DATA_V1/inputs.txt" ] || die "synchronizacja v1 nie zapisala $DATA_V1/inputs.txt - zobacz: journalctl -u hourglass-v1-sync -n 20"
    echo "== wejscia do ziarna v1 ($DATA_V1/inputs.txt):"
    cat "$DATA_V1/inputs.txt"
    echo "== INSTALL-V1 OK - prover v1 jeszcze nie liczy; start: bash $SRC/install.sh start-v1 (najpierw stop-p0)"
    ;;
start-v1)
    need_root
    N="${2:-$N_V1}"
    { [[ "$N" =~ ^[0-9]+$ ]] && [ "$N" -ge 20 ] && [ "$N" -le 40 ]; } || die "n poza zakresem 20..40 (v1: $N_V1, HOURGLASS.md O2)"
    if [ ! -x "$BIN" ] || [ ! -d "$DATA_V1" ]; then die "najpierw: install.sh install-v1"; fi
    p0_active && die "prover p0 jeszcze liczy - najpierw: install.sh stop-p0 (p0 konczy sie w chwili startu v1)"
    v1_exists && die "genesis v1 juz istnieje - Klepsydra nigdy nie startuje od zera (HOURGLASS.md D7)"
    systemctl start hourglass-v1-sync.service       # najnowsze wejscia do genesis
    echo "== genesis v1: operator $OPERATOR, s_ref $S_REF wezlow/s, k $K, n $N, t $T, lambda $LAMBDA; pomiar rozruchowy 20 s"
    runuser -u hourglass -- "$BIN" genesis --dir "$DATA_V1" --tag v1 --operator "$OPERATOR" --s-ref "$S_REF" \
        --n "$N" --t "$T" --lambda "$LAMBDA" --k "$K" --bench-seconds 20
    systemctl enable --now hourglass-v1.service
    root="$(grep -E '^root=' "$DATA_V1/genesis.txt" | cut -d= -f2)"
    echo "== genesis.json:"
    cat "$DATA_V1/genesis.json"; echo
    echo "== prover v1: $(systemctl is-active hourglass-v1.service || true)"
    echo "== korzen genesis v1 (phi_0) - do .env strony:"
    echo "HOURGLASS_V1_EXPECT_GENESIS=$root"
    echo "== START-V1 OK - genesis i rekordy podpisze, ostempluje i opublikuje serwer (apps/tsa/hourglass.py)"
    ;;
status)
    show_status "$DATA" hourglass-p0.service hourglass-sync.timer hourglass-sync.service
    ;;
status-v1)
    show_status "$DATA_V1" hourglass-v1.service hourglass-v1-sync.timer hourglass-v1-sync.service
    ;;
*)
    sed -n '2,/^set -euo pipefail/{/^set -euo pipefail/!p}' "$0"
    exit 2
    ;;
esac
