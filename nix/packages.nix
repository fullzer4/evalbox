{ ... }:
{
  perSystem = { pkgs, craneLib, toolchainWithExtensions, src, commonArgs, cargoArtifacts, ... }: {
    packages = {
      default = craneLib.buildPackage (commonArgs // {
        inherit cargoArtifacts;
      });

      test-all = pkgs.writeShellApplication {
        name = "evalbox-test-all";
        runtimeInputs = [ toolchainWithExtensions pkgs.pkg-config pkgs.gcc ];
        text = ''
          cargo test --lib

          cargo build -p evalbox-sandbox

          cargo test -p evalbox-sandbox --test security_tests --ignored -- --test-threads=1
        '';
      };
    };

    checks = {
      clippy = craneLib.cargoClippy {
        inherit src cargoArtifacts;
        pname = "evalbox-clippy";
        cargoClippyExtraArgs = "--all-targets -- -D warnings";
      };
      fmt = craneLib.cargoFmt {
        inherit src;
        pname = "evalbox-fmt";
      };
      test = craneLib.cargoTest {
        inherit src cargoArtifacts;
        pname = "evalbox-test";
        cargoTestExtraArgs = "--lib";
      };
      doc = craneLib.cargoDoc {
        inherit src cargoArtifacts;
        pname = "evalbox-doc";
        RUSTDOCFLAGS = "-D warnings";
      };
    };
  };
}
