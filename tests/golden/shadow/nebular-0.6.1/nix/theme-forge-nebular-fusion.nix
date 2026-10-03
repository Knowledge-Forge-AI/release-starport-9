# RS9 shadow candidate; publication and license acceptance deferred.
{ lib, stdenvNoCC, fetchurl, buildFHSEnv }:
let
  system = stdenvNoCC.hostPlatform.system;
  sources = {
    "aarch64-darwin" = { url = "https://github.com/Knowledge-Forge-AI/theme-forge-nebular-fusion/releases/download/v0.6.1/theme-forge-nebular-fusion-v0.6.1-aarch64-apple-darwin.app.tar.gz"; sha256 = "e5ab9c5ce5dd7fb02274b11b223db9db7ac1f3b2167334ee2f322abd3c8ec4be"; root = "Theme Forge Nebular Fusion.app"; launcher = "Contents/Resources/bin/tfnf"; };
    "aarch64-linux" = { url = "https://github.com/Knowledge-Forge-AI/theme-forge-nebular-fusion/releases/download/v0.6.1/theme-forge-nebular-fusion-v0.6.1-aarch64-unknown-linux-gnu.tar.gz"; sha256 = "5d59a1dfb6b5cec5edced1b098eba7b79e4f77a0dd2a0ab815caa8992b17497f"; root = "theme-forge-nebular-fusion"; launcher = "bin/tfnf"; };
    "x86_64-linux" = { url = "https://github.com/Knowledge-Forge-AI/theme-forge-nebular-fusion/releases/download/v0.6.1/theme-forge-nebular-fusion-v0.6.1-x86_64-unknown-linux-gnu.tar.gz"; sha256 = "d6060f74d6e55ec3a096ac01a1ebadc8b8b1d89a9a51475cd52207b465ca434d"; root = "theme-forge-nebular-fusion"; launcher = "bin/tfnf"; };
  };
  selected = sources.${system} or (throw "Unsupported shadow system");
  rawArchive = fetchurl { inherit (selected) url sha256; };
  isDarwin = stdenvNoCC.hostPlatform.isDarwin;
  meta = {
    description = "Evidence-bound Theme Forge integration workbench";
    homepage = "https://github.com/Knowledge-Forge-AI/theme-forge-nebular-fusion";
    license = lib.licenses.agpl3Plus;
    mainProgram = "tfnf";
    platforms = [ "aarch64-darwin" "aarch64-linux" "x86_64-linux" ];
    sourceProvenance = [ lib.sourceTypes.binaryNativeCode ];
  };
  payload = stdenvNoCC.mkDerivation {
    pname = "theme-forge-nebular-fusion-payload";
    version = "0.6.1";
    src = rawArchive;
    sourceRoot = ".";
    dontConfigure = true; dontBuild = true; dontFixup = true;
    installPhase = if isDarwin then ''
      mkdir -p "$out/Applications" "$out/bin"
      cp -a "${selected.root}" "$out/Applications/"
      ln -s "$out/Applications/${selected.root}/${selected.launcher}" "$out/bin/tfnf"
    '' else ''
      mkdir -p "$out/lib/theme-forge-nebular-fusion"
      cp -a "${selected.root}/." "$out/lib/theme-forge-nebular-fusion/"
    '';
    inherit meta;
  };
  icon = fetchurl { url = "https://raw.githubusercontent.com/Knowledge-Forge-AI/theme-forge-nebular-fusion/49e2c4919b6b4ec9bd4ed5d7e7ced90921e00f5e/src-tauri/icons/icon.png"; sha256 = "2d65e8c69a675b6c939ac11757c6a47a123f63b3f83b6d58305aaf7231aca160"; };
  packages = {
    "aarch64-linux" = pkgs: [ pkgs.bash pkgs.cairo pkgs.dbus pkgs.gdk-pixbuf pkgs.glib pkgs.glibc pkgs.gtk3 pkgs.libsoup_3 pkgs.nodejs_22 pkgs.pango pkgs.stdenv.cc.cc.lib pkgs.webkitgtk_4_1 ];
    "x86_64-linux" = pkgs: [ pkgs.bash pkgs.cairo pkgs.dbus pkgs.gdk-pixbuf pkgs.glib pkgs.glibc pkgs.gtk3 pkgs.libsoup_3 pkgs.nodejs_22 pkgs.stdenv.cc.cc.lib pkgs.webkitgtk_4_1 ];
  };
in if isDarwin then payload else buildFHSEnv {
  name = "tfnf";
  targetPkgs = packages.${system};
  runScript = "${payload}/lib/theme-forge-nebular-fusion/${selected.launcher}";
  extraInstallCommands = ''
    mkdir -p "$out/share/applications" "$out/share/icons/hicolor/256x256/apps"
    cp ${./theme-forge-nebular-fusion.desktop} "$out/share/applications/theme-forge-nebular-fusion.desktop"
    cp ${icon} "$out/share/icons/hicolor/256x256/apps/theme-forge-nebular-fusion.png"
  '';
  passthru = { inherit payload; };
  inherit meta;
}
