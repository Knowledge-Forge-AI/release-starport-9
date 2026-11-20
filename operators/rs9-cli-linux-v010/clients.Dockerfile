FROM debian@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc AS apt-client
RUN apt-get update && apt-get install -y --no-install-recommends python3

FROM fedora@sha256:f01112b9a1f1d0504ad962d9adfa401425033f8ab067e0a821904ebdde5b8ca5 AS rpm-client
RUN dnf5 -y --setopt=install_weak_deps=0 install python3 && dnf5 clean all

FROM archlinux@sha256:d4594bb2300cba11f41c2f27923eb56f63d9988909c402f9c95517d1e362c899 AS pacman-client
RUN pacman -Syu --noconfirm python
