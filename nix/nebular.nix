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
  # Diagnostic metadata only. Roots are existing public Nix outputs already in
  # runtimePackages; no package, path, provider, or environment is added here.
  guiDiscovery = {
    schema = "rs9.nix-fhs-gui-discovery.v1";
    roots = {
      glib = "${pkgs.glib}";
      gtk = "${pkgs.gtk3}";
      webkit = "${pkgs.webkitgtk_4_1}";
      pixbuf = "${pkgs.gdk-pixbuf}";
    };
    # The realized runtime package roots are the sealed symlink target set;
    # discovery rejects normalized link target strings outside this set.
    # Physical intermediate-component sealing is not claimed by this diagnostic.
    closure_roots = lib.unique (map (package: "${package}") (runtimePackages pkgs));
    max_entries = 4096;
    max_bytes = 64 * 1024 * 1024;
    max_file_bytes = 4 * 1024 * 1024;
    max_symlink_hops = 16;
    categories = [ "helper" "libexec" "gio-module" "gsettings-schema"
                   "pixbuf-loader" "font" "data" ];
  };
  runtimeFacts = writeText "rs9-nebular-loader-facts.json" (builtins.toJSON {
    loader = "${pkgs.glibc}/lib/${if stdenv.hostPlatform.isAarch64 then "ld-linux-aarch64.so.1" else "ld-linux-x86-64.so.2"}";
    glibc_lib = "${pkgs.glibc}/lib";
    library_path = lib.makeLibraryPath (runtimePackages pkgs);
    python = "${python3}/bin/python3";
    node = "${pkgs.nodejs_22}/bin/node";
    readelf = "${pkgs.binutils}/bin/readelf";
    dbus_run_session = "${pkgs.dbus}/bin/dbus-run-session";
    dbus_daemon = "${pkgs.dbus}/bin/dbus-daemon";
    dbus_session_config = "${pkgs.dbus}/share/dbus-1/session.conf";
    gui_discovery = guiDiscovery;
  });
  # Proposed current-generation Linux graphics userspace (unactivated). Empty
  # unless prepare_input set source_generation on a current Linux lane AND the
  # capture matches the in-tree current catalog coordinates and archive digest.
  currentCatalog = builtins.fromJSON
    (builtins.readFile ./theme-forge-current-202610-products.json);
  currentRow = currentCatalog.products.${product.pname} or { };
  currentAsset = (currentRow.assets or { }).${stdenv.hostPlatform.system} or null;
  currentLinuxGraphics =
    stdenv.hostPlatform.isLinux
    && (product ? source_generation)
    && product.source_generation == currentCatalog.generation
    && currentAsset != null
    && product.version == (currentRow.version or null)
    && (product.commit or null) == (currentRow.commit or null)
    && (product.asset_sha256 or null) == currentAsset.sha256
    && builtins.hashFile "sha256"
         (capture + "/payloads/${product.pname}/payload.tar.gz") == currentAsset.sha256;
  # Existing-pin Mesa runtime output and libglvnd only; explicit outputs exclude
  # opencl/spirv2dxil/cross_tools/debug/dev. includeClosures remains false.
  currentGraphicsPackages = pkgs:
    lib.optionals currentLinuxGraphics [ pkgs.mesa.out pkgs.libglvnd.out ];
  runtime = buildFHSEnv {
    name = "rs9-nebular-fhs";
    targetPkgs = pkgs: runtimePackages pkgs ++ currentGraphicsPackages pkgs;
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
