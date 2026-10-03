# RS9 shadow candidate; publication and license acceptance deferred.
%global debug_package %{nil}
%global __strip /bin/true
%undefine __brp_mangle_shebangs
%global __os_install_post %{nil}
Name: theme-forge-nebular-fusion
Version: 0.6.1
Release: 1%{?dist}
Summary: Evidence-bound Theme Forge integration workbench
License: AGPL-3.0-or-later
URL: https://github.com/Knowledge-Forge-AI/theme-forge-nebular-fusion
ExclusiveArch: aarch64 x86_64
%ifarch aarch64
Source0: https://github.com/Knowledge-Forge-AI/theme-forge-nebular-fusion/releases/download/v0.6.1/theme-forge-nebular-fusion-v0.6.1-aarch64-unknown-linux-gnu.tar.gz
Requires: bash
Requires: cairo
Requires: cairo-gobject
Requires: dbus-libs
Requires: gdk-pixbuf2
Requires: glib2
Requires: glibc >= 2.34
Requires: gtk3
Requires: hicolor-icon-theme
Requires: javascriptcoregtk4.1
Requires: libgcc
Requires: libsoup3
Requires: libstdc++
Requires: nodejs >= 22
Requires: pango
Requires: webkit2gtk4.1
%global raw_sha256 5d59a1dfb6b5cec5edced1b098eba7b79e4f77a0dd2a0ab815caa8992b17497f
%endif
%ifarch x86_64
Source0: https://github.com/Knowledge-Forge-AI/theme-forge-nebular-fusion/releases/download/v0.6.1/theme-forge-nebular-fusion-v0.6.1-x86_64-unknown-linux-gnu.tar.gz
Requires: bash
Requires: cairo
Requires: dbus-libs
Requires: gdk-pixbuf2
Requires: glib2
Requires: glibc >= 2.34
Requires: gtk3
Requires: hicolor-icon-theme
Requires: javascriptcoregtk4.1
Requires: libgcc
Requires: libsoup3
Requires: libstdc++
Requires: nodejs >= 22
Requires: webkit2gtk4.1
%global raw_sha256 d6060f74d6e55ec3a096ac01a1ebadc8b8b1d89a9a51475cd52207b465ca434d
%endif
Source1: theme-forge-nebular-fusion.desktop
Source2: https://raw.githubusercontent.com/Knowledge-Forge-AI/theme-forge-nebular-fusion/49e2c4919b6b4ec9bd4ed5d7e7ced90921e00f5e/src-tauri/icons/icon.png

%description
Evidence-bound Theme Forge integration workbench

%prep
printf '%s  %s\n' '%{raw_sha256}' '%{SOURCE0}' | sha256sum -c -
printf '%s  %s\n' 'f859eb821441c21873220eb03af148229f9c456a0a1a33537d6d30a0f6b33401' '%{SOURCE1}' | sha256sum -c -
printf '%s  %s\n' '2d65e8c69a675b6c939ac11757c6a47a123f63b3f83b6d58305aaf7231aca160' '%{SOURCE2}' | sha256sum -c -
%setup -q -c -n %{name}-%{version}

%build
# Precompiled; no payload transformations.

%install
mkdir -p '%{buildroot}/usr/lib/theme-forge-nebular-fusion' '%{buildroot}/usr/bin'
cp -a theme-forge-nebular-fusion/. '%{buildroot}/usr/lib/theme-forge-nebular-fusion/'
ln -s '/usr/lib/theme-forge-nebular-fusion/bin/tfnf' '%{buildroot}/usr/bin/tfnf'
install -Dm644 '%{SOURCE1}' '%{buildroot}/usr/share/applications/theme-forge-nebular-fusion.desktop'
install -Dm644 '%{SOURCE2}' '%{buildroot}/usr/share/icons/hicolor/256x256/apps/theme-forge-nebular-fusion.png'

%files
%license theme-forge-nebular-fusion/LICENSE
%license theme-forge-nebular-fusion/NOTICE
/usr/lib/theme-forge-nebular-fusion
/usr/bin/tfnf
/usr/share/applications/theme-forge-nebular-fusion.desktop
/usr/share/icons/hicolor/256x256/apps/theme-forge-nebular-fusion.png
