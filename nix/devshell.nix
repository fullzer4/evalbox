{ ... }:
{
  perSystem = { pkgs, toolchainWithExtensions, ... }: {
    devShells.default = pkgs.mkShell {
      name = "evalbox-dev";
      buildInputs = with pkgs; [
        toolchainWithExtensions
        pkg-config
        gcc
        python3
        go
      ];
      RUST_SRC_PATH = "${toolchainWithExtensions}/lib/rustlib/src/rust/library";
      RUST_BACKTRACE = "1";
    };
  };
}
