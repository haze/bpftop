{
  inputs = {
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    utils.url = "github:numtide/flake-utils";
    nixpkgs.url = "nixpkgs/nixos-unstable";
  };

  outputs = {
    self,
    fenix,
    utils,
    nixpkgs,
  }:
    utils.lib.eachDefaultSystem (system: let
      overlays = [fenix.overlays.default];
      pkgs = import nixpkgs {
        inherit system overlays;
      };
    in {
      devShells.default = pkgs.mkShell {
        buildInputs = [
          (pkgs.fenix.complete.withComponents [
            "cargo"
            "clippy"
            "rust-src"
            "rustc"
            "rustfmt"
          ])
          pkgs.rust-analyzer-nightly
          pkgs.libiconv
          pkgs.libbpf
        ];
      };
    });
}
