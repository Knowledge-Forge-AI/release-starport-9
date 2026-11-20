{ fetchurl, lib, python311Packages }:

python311Packages.buildPythonApplication rec {
  pname = "release-starport-9";
  version = "0.1.0";
  format = "wheel";

  src = fetchurl {
    url = "https://github.com/Knowledge-Forge-AI/release-starport-9/releases/download/v${version}/release_starport_9-${version}-py3-none-any.whl";
    sha256 = "8eca005afde7134e0dcb0e817b58f9b0e1ffe12a1e8697ba9a67123b28f84b57";
  };

  doInstallCheck = true;
  installCheckPhase = ''
    runHook preInstallCheck
    test "$("$out/bin/rs9" --version)" = "${version}"
    "$out/bin/rs9" doctor
    runHook postInstallCheck
  '';

  meta = {
    description = "Release Starport 9 CLI for release contracts and publication planning";
    homepage = "https://github.com/Knowledge-Forge-AI/release-starport-9";
    license = lib.licenses.agpl3Plus;
    mainProgram = "rs9";
    platforms = [ "aarch64-darwin" "x86_64-linux" "aarch64-linux" ];
  };
}
