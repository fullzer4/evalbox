{ ... }:
{
  perSystem = { pkgs, craneLib, src, commonArgs, cargoArtifacts, ... }:
    let
      srcWithPayloads = pkgs.lib.cleanSourceWith {
        src = ./..;
        filter = path: type:
          (craneLib.filterCargoSources path type)
          || (builtins.match ".*\\.c$" path != null);
      };
    in {
    packages = {
      default = craneLib.buildPackage (commonArgs // {
        inherit cargoArtifacts;
      });

      security-test-bin = craneLib.mkCargoDerivation (commonArgs // {
        inherit cargoArtifacts;
        src = srcWithPayloads;
        pnameSuffix = "-security-tests";
        doCheck = false;
        nativeBuildInputs = (commonArgs.nativeBuildInputs or []) ++ [ pkgs.jq pkgs.gcc ];
        buildPhaseCargoCommand = ''
          cargo test -p evalbox-sandbox --test security_tests \
            --no-run --release --message-format=json 2>/dev/null \
            | jq -r 'select(.executable != null) | .executable' \
            > /tmp/test-bins.txt
        '';
        installPhaseCommand = ''
          mkdir -p $out/bin/payloads
          while IFS= read -r bin; do
            [ -f "$bin" ] && cp "$bin" $out/bin/
          done < /tmp/test-bins.txt
          for dir in target/release/build/evalbox-sandbox-*/out/payloads; do
            [ -d "$dir" ] && cp "$dir"/* $out/bin/payloads/
          done
        '';
      });
    };

    checks = {
      clippy = craneLib.cargoClippy (commonArgs // {
        inherit cargoArtifacts;
        cargoClippyExtraArgs = "--all-targets -- -D warnings";
      });
      fmt = craneLib.cargoFmt { inherit src; };
      test = craneLib.cargoTest (commonArgs // {
        inherit cargoArtifacts;
        cargoTestExtraArgs = "--lib";
      });
      doc = craneLib.cargoDoc (commonArgs // {
        inherit cargoArtifacts;
        RUSTDOCFLAGS = "-D warnings";
      });
    };
  };
}
