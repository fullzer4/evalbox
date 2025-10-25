{
  description = "Run untrusted Python code safely with native Linux isolation";

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
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            # Python toolchain
            python311
            uv

            # Rust toolchain
            rustc
            cargo
            rustfmt
            clippy

            # Development tools
            ruff

            # Testing tools
            isolate
          ];
        };
      }
    );
}
