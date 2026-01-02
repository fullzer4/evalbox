{
  description = "Run untrusted Python code safely with native Linux isolation";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs = inputs@{ self, nixpkgs, flake-utils, rust-overlay }:
    let
      nixosModules.default = import ./nix/module.nix;
    in
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { inherit system overlays; };
        lib = import ./nix/lib.nix { inherit pkgs; };
        packages = import ./nix/packages.nix { inherit pkgs lib; };
        
        # Rust toolchain
        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "rust-src" "rust-analyzer" ];
        };
      in
      {
        packages = {
          default = packages.leeward-all;
          cli = packages.leeward-cli;
          daemon = packages.leeward-daemon;
          ffi = packages.leeward-ffi;
        };

        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            rustToolchain
            cargo-watch
            pkg-config
            libseccomp
            mold
            clang
            llvmPackages.bintools
            python3
          ];

          shellHook = ''
            export LIBSECCOMP_LINK_TYPE="dylib"
            export LIBSECCOMP_LIB_PATH="${pkgs.libseccomp}/lib"
            export PKG_CONFIG_PATH="${pkgs.libseccomp}/lib/pkgconfig"
            export LEEWARD_SOCKET="$PWD/.leeward.sock"
            export RUST_SRC_PATH="${rustToolchain}/lib/rustlib/src/rust/library"

            echo "🚀 Leeward Development Environment"
            echo ""
            echo "Comandos:"
            echo "  cargo build --release    - Compila o projeto"
            echo "  ./target/release/leeward-daemon  - Inicia o daemon"
            echo "  ./target/release/leeward exec 'print(1)'  - Executa código"
            echo ""
            echo "Para cgroups (opcional), rode com:"
            echo "  sudo ./target/release/leeward-daemon"
          '';
        };
      }
    ) // { inherit nixosModules; };
}