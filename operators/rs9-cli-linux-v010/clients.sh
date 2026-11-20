#!/usr/bin/env bash
set -euo pipefail

root=/admitted/packages/rs9
product=release-starport-9
primary=7D03EE84F8C7025FD2F3D772BF89DF6643C2F1AF
work=$(mktemp -d /tmp/rs9-client.XXXXXXXX)

probe_installed() {
    test "$(rs9 --version)" = "0.1.0"
    rs9 doctor >/dev/null
}

case "$1" in
    apt)
        chmod 0755 "$work"
        printf 'deb [signed-by=%s/keys/rs9-signing.gpg] file:%s/apt stable main\n' "$root" "$root" > "$work/source.list"
        args=(-o "Dir::Etc::sourcelist=$work/source.list" -o 'Dir::Etc::sourceparts=-')
        apt-get "${args[@]}" update
        apt-get "${args[@]}" -y --no-install-recommends install "$product=0.1.0-1"
        probe_installed
        apt-get "${args[@]}" -y purge "$product"
        cp -R "$root/apt" "$work/tampered"
        grep -q '^Origin:' "$work/tampered/dists/stable/InRelease"
        sed -i 's/^Origin:.*/Origin: tampered/' "$work/tampered/dists/stable/InRelease"
        printf 'deb [signed-by=%s/keys/rs9-signing.gpg] file:%s/tampered stable main\n' "$root" "$work" > "$work/source.list"
        if apt-get "${args[@]}" update >"$work/negative" 2>&1; then
            exit 1
        fi
        grep -Eiq 'signature|clearsigned' "$work/negative"
        ;;
    rpm)
        cat > "$work/rs9.repo" <<EOF
[rs9]
name=Release Starport 9
baseurl=file://$root/rpm
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=file://$root/keys/rs9-signing.asc
EOF
        args=(--setopt="reposdir=$work" --setopt="cachedir=$work/cache")
        dnf5 "${args[@]}" -y install "$product-0.1.0-1"
        probe_installed
        dnf5 "${args[@]}" -y remove "$product"
        cp "$root/rpm/repodata/repomd.xml" "$work/tampered.xml"
        printf 'tampered\n' >> "$work/tampered.xml"
        if gpgv --keyring "$root/keys/rs9-signing.gpg" "$root/rpm/repodata/repomd.xml.asc" "$work/tampered.xml"; then
            exit 1
        fi
        ;;
    pacman)
        test "$(uname -m)" = x86_64
        pacman-key --gpgdir "$work/keyring" --init
        pacman-key --gpgdir "$work/keyring" --add "$root/keys/rs9-signing.gpg"
        pacman-key --gpgdir "$work/keyring" --lsign-key "$primary"
        cat > "$work/pacman.conf" <<EOF
[options]
Architecture = x86_64
GPGDir = $work/keyring
SigLevel = PackageRequired DatabaseRequired
LocalFileSigLevel = Required
[rs9]
Server = file://$root/pacman/x86_64
EOF
        pacman --config "$work/pacman.conf" -Sy --noconfirm "$product"
        probe_installed
        pacman --config "$work/pacman.conf" -R --noconfirm "$product"
        cp -R "$root/pacman/x86_64" "$work/tampered"
        printf 'tampered\n' >> "$work/tampered/rs9.db"
        sed -i "s|file://$root/pacman/x86_64|file://$work/tampered|" "$work/pacman.conf"
        mkdir "$work/negative-db"
        if pacman --config "$work/pacman.conf" --dbpath "$work/negative-db" -Sy --noconfirm >"$work/negative" 2>&1; then
            exit 1
        fi
        grep -Eiq '(invalid|corrupted).*PGP signature|signature.*(invalid|corrupted)' "$work/negative"
        ;;
    *) exit 2 ;;
esac

hash -r
if command -v rs9 >/dev/null; then
    exit 1
fi
printf 'RS9_LINUX_CLIENT_PASSED %s\n' "$1"
