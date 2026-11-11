{
  description = "p2p-auth - Application-agnostic libp2p authentication, PSK adoption, and ZKP Verifiable Credential appliance";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    flake-utils.lib.eachSystem [
      "x86_64-linux"
      "aarch64-linux"
      "aarch64-darwin"
    ] (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
        };
      in
      {
        packages = {
          p2p-auth-server = pkgs.buildGoModule {
            pname = "p2p-auth-server";
            version = "1.0.0";
            src = ./.;
            subPackages = [ "cmd/p2p-auth-server" ];
            vendorHash = null;
          };

          p2p-auth-verifier = pkgs.buildGoModule {
            pname = "p2p-auth-verifier";
            version = "1.0.0";
            src = ./.;
            subPackages = [ "cmd/p2p-auth-verifier" ];
            vendorHash = null;
          };

          p2p-auth-client = pkgs.buildGoModule {
            pname = "p2p-auth-client";
            version = "1.0.0";
            src = ./.;
            subPackages = [ "cmd/p2p-auth-client" ];
            vendorHash = null;
          };

          default = self.packages.${system}.p2p-auth-server;
        };
      }
    );
}
