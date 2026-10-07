{ lib, stdenvNoCC, runCommand, writeShellScript, writeText, buildFHSEnv, python3,
  stdenv, pkgs }:
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
  # Both this harness and the rendered shadow remain userns-dependent and
  # unqualified on restricted Linux hosts. Loader facts are diagnostic only.
  runtimePackages = pkgs: with pkgs; [
      glibc gtk3 webkitgtk_4_1 glib cairo pango gdk-pixbuf libsoup_3 atk dbus
      openssl zlib stdenv.cc.cc.lib nodejs_22 python3 binutils xvfb-run dbus
      xorg.libX11 xorg.libXcomposite xorg.libXdamage xorg.libXext xorg.libXfixes
      xorg.libXrandr xorg.libXrender xorg.libXtst xorg.libxcb
    ];
  runtimeFacts = writeText "rs9-nebular-loader-facts.json" (builtins.toJSON {
    loader = "${pkgs.glibc}/lib/${if stdenv.hostPlatform.isAarch64 then "ld-linux-aarch64.so.1" else "ld-linux-x86-64.so.2"}";
    glibc_lib = "${pkgs.glibc}/lib";
    library_path = lib.makeLibraryPath (runtimePackages pkgs);
    python = "${python3}/bin/python3";
    node = "${pkgs.nodejs_22}/bin/node";
    readelf = "${pkgs.binutils}/bin/readelf";
  });
  runtime = buildFHSEnv {
    name = "rs9-nebular-fhs";
    targetPkgs = runtimePackages;
    runScript = writeShellScript "rs9-runtime" ''
      exec "$@"
    '';
  };
  launcher = writeShellScript "rs9-nebular-launch" ''
    export PYTHONPATH="${capture}/runtime"
    exec "${python3}/bin/python3" "${capture}/runtime/launch.py" "${payload}/payload.tar.gz" "$@"
  '';
in runCommand product.pname { passthru = { inherit payload runtime runtimeFacts; }; } ''
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
