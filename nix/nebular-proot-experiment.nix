{ lib, stdenvNoCC, runCommand, writeShellScript, writeText, buildEnv, closureInfo,
  makeFontsConf, python3, stdenv, pkgs }:
{ product, capture, nixpkgsRev }:
# Candidate-only, experimental. A guest-only PRoot root for the unmodified
# Nebular release payload on Linux. This is an execution-compatibility
# hypothesis, not an isolation boundary or an application qualification, and it
# leaves the production recipe (nebular.nix) and its gates untouched.
let
  pin = {
    version = "5.4.0";
    rev = "0921fdb3e13e40fe25fbc52b89661a9d6d32ac68";
    recipeBlob = "02766094fbf82ab7ee4425a14d480f061cbcdadc";
    recipeFile = "pkgs/by-name/pr/proot/package.nix";
    sourceHash = "sha256-Z9Y7ccWp5KEVuo9xfHcgo58XqYVdFo7ck1jH7cnT2KA=";
  };
  proot = pkgs.proot;
  # The recipe's recursive fixed-output source hash, normalized to SRI.
  recipeSourceHash =
    let
      src = proot.src;
      hash = src.outputHash or null;
      algo = src.outputHashAlgo or null;
    in
      if hash == null then null
      else if algo == null || algo == "" then hash
      else builtins.convertHash { inherit hash; hashAlgo = algo; toHashFormat = "sri"; };
  recipePath = pkgs.path + "/${pin.recipeFile}";

  system = stdenv.hostPlatform.system;
  loaderName = if stdenv.hostPlatform.isAarch64 then "ld-linux-aarch64.so.1" else "ld-linux-x86-64.so.2";
  foreignInterpreter = if stdenv.hostPlatform.isAarch64 then "/lib/ld-linux-aarch64.so.1" else "/lib64/ld-linux-x86-64.so.2";
  loaderPath = "${pkgs.glibc}/lib/${loaderName}";

  payload = stdenvNoCC.mkDerivation {
    pname = "${product.pname}-payload";
    inherit (product) version;
    src = capture + "/payloads/${product.pname}";
    dontConfigure = true;
    dontBuild = true;
    dontFixup = true;
    installPhase = ''
      mkdir -p "$out"
      cp -a ./. "$out/"
    '';
  };

  # Same library set as the production FHS harness, minus the host-side proot.
  libraryPackages = with pkgs; [
    glibc gtk3 webkitgtk_4_1 glib cairo pango gdk-pixbuf libsoup_3 atk dbus
    openssl zlib stdenv.cc.cc.lib nodejs_22 python3 binutils xvfb-run dbus
    xorg.libX11 xorg.libXcomposite xorg.libXdamage xorg.libXext xorg.libXfixes
    xorg.libXrandr xorg.libXrender xorg.libXtst xorg.libxcb
  ];
  libraryPath = lib.makeLibraryPath libraryPackages;

  # Executables the released verifier, smoke and WebKit helpers resolve by name.
  guestPackages = libraryPackages ++ (with pkgs; [
    bash coreutils findutils gnugrep gnused gawk glibc.bin bubblewrap xdg-dbus-proxy
  ]);
  guestEnv = buildEnv {
    name = "rs9-nebular-proot-guest-env";
    paths = guestPackages;
    pathsToLink = [ "/bin" ];
    ignoreCollisions = false;
  };

  fontsConf = makeFontsConf { fontDirectories = [ pkgs.dejavu_fonts ]; };
  gioModules = "${pkgs.glib-networking}/lib/gio/modules";
  pixbufCache = "${pkgs.gdk-pixbuf}/lib/gdk-pixbuf-2.0/2.10.0/loaders.cache";
  dataDirs = lib.concatStringsSep ":" [
    "${pkgs.gsettings-desktop-schemas}/share/gsettings-schemas/${pkgs.gsettings-desktop-schemas.name}"
    "${pkgs.gtk3}/share/gsettings-schemas/${pkgs.gtk3.name}"
    "${pkgs.shared-mime-info}/share"
    "${pkgs.adwaita-icon-theme}/share"
  ];

  launcher = writeShellScript "rs9-nebular-proot-launch" ''
    export PYTHONPATH="${capture}/runtime"
    exec "${python3}/bin/python3" "${capture}/runtime/launch.py" "${payload}/payload.tar.gz" "$@"
  '';

  # Only these store paths are bound into the guest; the host store is not.
  closure = closureInfo {
    rootPaths = libraryPackages ++ [
      guestEnv launcher pkgs.glibc pkgs.glibc.bin pkgs.coreutils pkgs.bash
      fontsConf pkgs.glib-networking pkgs.gdk-pixbuf pkgs.gsettings-desktop-schemas
      pkgs.gtk3 pkgs.shared-mime-info pkgs.adwaita-icon-theme pkgs.dejavu_fonts
    ];
  };

  # Fixed placeholders only. Identity files (passwd, group) and /tmp are bound
  # per run by the hosted runner; nothing else of the host is visible.
  guestRoot = runCommand "rs9-nebular-proot-guest-root" { } ''
    mkdir -p "$out"/{bin,usr/bin,etc,tmp,dev,proc,run,var/tmp,nix/store,lib,lib64}
    ln -s ${pkgs.bash}/bin/sh "$out/bin/sh"
    ln -s ${pkgs.coreutils}/bin/env "$out/usr/bin/env"
    ln -s ${loaderPath} "$out${foreignInterpreter}"
    : > "$out/etc/passwd"
    : > "$out/etc/group"
    printf '%s\n' 'passwd: files' 'group: files' 'hosts: files' > "$out/etc/nsswitch.conf"
    printf '%s\n' '127.0.0.1 localhost' '::1 localhost' > "$out/etc/hosts"
  '';

  runtimeFacts = writeText "rs9-nebular-proot-facts.json" (builtins.toJSON {
    schema = "rs9.nix-proot-facts.v2";
    inherit system;
    proot = "${proot}/bin/proot";
    proot_version = proot.version;
    proot_nixpkgs_rev = nixpkgsRev;
    proot_recipe_blob = pin.recipeBlob;
    proot_recipe_file = "${recipePath}";
    proot_source_hash = recipeSourceHash;
    guest_root = "${guestRoot}";
    guest_env = "${guestEnv}";
    guest_path = "${guestEnv}/bin";
    guest_environment = {
      PATH = "${guestEnv}/bin";
      LD_LIBRARY_PATH = libraryPath;
      FONTCONFIG_FILE = "${fontsConf}";
      GIO_EXTRA_MODULES = gioModules;
      GDK_PIXBUF_MODULE_FILE = pixbufCache;
      XDG_DATA_DIRS = dataDirs;
    };
    closure_paths_file = "${closure}/store-paths";
    loader = loaderPath;
    foreign_interpreter = foreignInterpreter;
    glibc_lib = "${pkgs.glibc}/lib";
    library_path = libraryPath;
    env = "${pkgs.coreutils}/bin/env";
    sh = "${pkgs.bash}/bin/sh";
    python = "${python3}/bin/python3";
    node = "${pkgs.nodejs_22}/bin/node";
    readelf = "${pkgs.binutils}/bin/readelf";
    ldd = "${pkgs.glibc.bin}/bin/ldd";
    xvfb_run = "${pkgs.xvfb-run}/bin/xvfb-run";
    dbus_run_session = "${pkgs.dbus}/bin/dbus-run-session";
    bwrap = "${pkgs.bubblewrap}/bin/bwrap";
    launcher = "${launcher}";
  });
in
assert product.authenticated && product.kind == "materialized-desktop";
assert stdenv.hostPlatform.isLinux;
assert builtins.elem system [ "x86_64-linux" "aarch64-linux" ];
assert nixpkgsRev == pin.rev;
assert proot.version == pin.version;
assert recipeSourceHash == pin.sourceHash;
assert builtins.pathExists recipePath;
runCommand "${product.pname}-proot" {
  passthru = { inherit payload guestRoot guestEnv launcher closure runtimeFacts; proot = proot; };
} ''
  mkdir -p "$out"
  ln -s ${payload} "$out/payload"
  ln -s ${guestRoot} "$out/guest-root"
  ln -s ${guestEnv} "$out/guest-env"
  ln -s ${launcher} "$out/launcher"
  ln -s ${closure} "$out/closure"
  ln -s ${runtimeFacts} "$out/facts.json"
''
