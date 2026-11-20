FROM archlinux@sha256:b21322c663be387c0ed9cbc7bbbfe18e41633ad4e7b7c77cfad45f128be20040 AS arch
FROM fedora@sha256:f01112b9a1f1d0504ad962d9adfa401425033f8ab067e0a821904ebdde5b8ca5
RUN dnf5 -y --setopt=install_weak_deps=0 install rpm-sign createrepo_c python3 gnupg2 bsdtar gettext gzip tar && dnf5 clean all
COPY --from=arch /usr/bin/repo-add /usr/bin/repo-add
COPY --from=arch /usr/share/makepkg /usr/share/makepkg
COPY --from=arch /etc/makepkg.conf /etc/makepkg.conf
RUN rpm --version && test -x /usr/bin/rpmsign && test -x /usr/bin/createrepo_c && repo-add --version
RUN bash -o pipefail -c "rpm -qa --qf '%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\\n' | LC_ALL=C sort | sha256sum -c <(printf '%s  -\\n' 27414973c976abe9ab17582477b8b1a6598679a7162ce3c5e1ed94072310722a)"
