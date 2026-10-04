{ lib, stdenvNoCC, makeWrapper, nodejs_22 }:
{ product, capture }:
assert product.authenticated && product.kind == "node-cli";
stdenvNoCC.mkDerivation {
  pname = product.pname;
  inherit (product) version;
  src = capture + "/payloads/${product.pname}";
  nativeBuildInputs = [ makeWrapper ];
  dontConfigure = true;
  dontBuild = true;
  dontFixup = true;
  installPhase = ''
    mkdir -p "$out/lib/node_modules/${product.pname}" "$out/bin"
    cp -a ./. "$out/lib/node_modules/${product.pname}/"
    ${lib.concatMapStringsSep "\n" (cmd: ''
      entrypoint="$out/lib/node_modules/${product.pname}/${product.command_paths.${cmd}}"
      test -f "$entrypoint"
      makeWrapper "${nodejs_22}/bin/node" "$out/bin/${cmd}" --add-flags "$entrypoint"
    '') product.commands}
  '';
  meta.license = lib.licenses.agpl3Plus;
}
