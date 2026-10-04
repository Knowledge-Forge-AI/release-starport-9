{
  description = "RS9 non-production authenticated candidate builds";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/0921fdb3e13e40fe25fbc52b89661a9d6d32ac68";
  inputs.rs9-capture = { url = "path:./nix/empty-capture"; flake = false; };
  outputs = { self, nixpkgs ? throw "Pinned nixpkgs required", rs9-capture ? ./nix/empty-capture }:
    let
      systems = [ "aarch64-darwin" "x86_64-linux" "aarch64-linux" ];
      perSystem = f: nixpkgs.lib.genAttrs systems f;
      products = let data = builtins.fromJSON (builtins.readFile (rs9-capture + "/products.json"));
        in assert builtins.length (builtins.attrNames data) == 4; data;
      build = system:
        let pkgs = import nixpkgs { inherit system; };
        in pkgs.lib.mapAttrs (name: product:
          if product.kind == "node-cli"
          then pkgs.callPackage ./nix/node-cli.nix {} { inherit product; capture = rs9-capture; }
          else pkgs.callPackage ./nix/nebular.nix {} { inherit product; capture = rs9-capture; }
        ) products;
    in {
      candidates = perSystem build;
      checks = perSystem (system: build system);
      qualification = { productionEnabled = false; publicationOutputsExposed = false; };
    };
}
