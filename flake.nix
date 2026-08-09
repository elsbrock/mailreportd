{
  description = "DMARC and SMTP TLS report ingest daemon";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        packages.default = pkgs.callPackage ./default.nix { };
        packages.mailreportd = self.packages.${system}.default;

        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            go
            gopls
            go-tools
          ];
        };
      });
}
