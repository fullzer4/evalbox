{
  description = "Run untrusted Python code safely with native Linux isolation";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };

        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "rust-src" "rust-analyzer" "clippy" "rustfmt" ];
          targets = [ "x86_64-unknown-linux-gnu" "aarch64-unknown-linux-gnu" ];
        };
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            rustToolchain
            cargo-watch
            cargo-edit
            cargo-expand
            cargo-outdated

            clang
            lld
            mold

            pkg-config
            gnumake
            cmake

            libseccomp

            gdb
            strace
          ];

          shellHook = ''
            export CARGO_HOME="$PWD/.cargo-home"
            export RUSTFLAGS="-C link-arg=-fuse-ld=mold"
            export LIBSECCOMP_LINK_TYPE="dylib"
            export LIBSECCOMP_LIB_PATH="${pkgs.libseccomp}/lib"
          '';

          PKG_CONFIG_PATH = "${pkgs.libseccomp}/lib/pkgconfig";
        };
      }
    );
}