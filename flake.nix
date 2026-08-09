{
  description = "DMARC and SMTP TLS report ingest daemon";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    let
      # System-independent outputs. The module defaults its package to this
      # flake's build for the host's system, so a consumer only has to import
      # the module and set `enable`.
      systemIndependent = {
        overlays.default = final: prev: {
          mailreportd = final.callPackage ./default.nix { };
        };

        nixosModules.default = { config, lib, pkgs, ... }: {
          imports = [ ./module.nix ];
          config = lib.mkIf config.services.mailreportd.enable {
            services.mailreportd.package =
              lib.mkDefault self.packages.${pkgs.stdenv.hostPlatform.system}.default;
          };
        };

        nixosModules.mailreportd = systemIndependent.nixosModules.default;
      };
    in
    systemIndependent // flake-utils.lib.eachDefaultSystem (system:
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
