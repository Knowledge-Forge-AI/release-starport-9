{ lib, stdenvNoCC, runCommand, writeShellScript, buildFHSEnv, python3,
  stdenv }:
{ product, capture }:
assert product.authenticated && product.kind == "materialized-desktop";
let
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
  runtime = buildFHSEnv {
    name = "rs9-nebular-fhs";
    targetPkgs = pkgs: with pkgs; [
      glibc gtk3 webkitgtk_4_1 glib cairo pango gdk-pixbuf libsoup_3 atk dbus
      openssl zlib stdenv.cc.cc.lib nodejs_22 python3 binutils xvfb-run dbus
      xorg.libX11 xorg.libXcomposite xorg.libXdamage xorg.libXext xorg.libXfixes
      xorg.libXrandr xorg.libXrender xorg.libXtst xorg.libxcb
    ];
    runScript = writeShellScript "rs9-runtime" ''
      exec "$@"
    '';
  };
  launcher = writeShellScript "rs9-nebular-launch" ''
    export PYTHONPATH="${capture}/runtime"
    exec "${python3}/bin/python3" "${capture}/runtime/launch.py" "${payload}/payload.tar.gz" "$@"
  '';
in runCommand product.pname { passthru = { inherit payload runtime; }; } ''
  mkdir -p "$out/bin"
  ${if stdenv.isDarwin then
    ''
      ln -s ${launcher} "$out/bin/tfnf"
    ''
  else
    ''
      cat > "$out/bin/tfnf" <<EOF
      #!${stdenv.shell}
      exec ${runtime}/bin/rs9-nebular-fhs ${launcher} "\$@"
      EOF
      chmod +x "$out/bin/tfnf"
    ''
  }
  ln -s ${payload} "$out/payload"
''
