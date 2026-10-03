# Candidate Node wrappers consume authenticated generated inputs.
# The root flake does not expose these candidates before separate qualification.
{ lib, stdenvNoCC, fetchurl, makeWrapper, nodejs_22 }:
{ product }:
assert product ? command_paths;
if product.pname == "theme-forge-stellar-burst" then
  throw "RS9 Burst candidate withheld: lock-bound offline dependency staging is not integrated"
else
stdenvNoCC.mkDerivation {
  pname = product.pname;
  inherit (product) version;
  src = fetchurl { inherit (product.asset) url sha256; };
  nativeBuildInputs = [ makeWrapper ];
  sourceRoot = ".";
  dontConfigure = true;
  dontBuild = true;
  dontFixup = true;
  installPhase = ''
    mkdir -p "$out/lib/node_modules/${product.pname}" "$out/bin"
    cp -a ${product.asset.root}/. "$out/lib/node_modules/${product.pname}/"
    ${lib.concatMapStringsSep "\n" (cmd: ''
      entrypoint="$out/lib/node_modules/${product.pname}/${product.command_paths.${cmd}}"
      test -f "$entrypoint"
      makeWrapper "${nodejs_22}/bin/node" "$out/bin/${cmd}" --add-flags "$entrypoint"
    '') product.commands}
  '';
  meta = {
    description = product.summary;
    homepage = "https://github.com/${product.repository}";
    license = lib.licenses.agpl3Plus;
    mainProgram = builtins.head product.commands;
    platforms = product.platforms;
  };
}
