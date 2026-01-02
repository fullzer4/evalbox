{ pkgs, lib }:

let
  version = lib.cargoVersion ../Cargo.toml;
  buildDeps = lib.buildDeps;
  src = pkgs.lib.cleanSource ../.;

  # Python with commonly needed packages for sandboxed execution
  pythonEnv = pkgs.python3.withPackages (ps: with ps; [
    # Base packages users might expect
  ]);

  # Runtime dependencies that need to be available in the sandbox
  runtimeDeps = [
    pythonEnv
    pkgs.coreutils
    pkgs.bash
  ];

  # Paths to bind-mount into sandbox (read-only)
  sandboxPaths = pkgs.lib.concatMapStringsSep ":" (p: "${p}") runtimeDeps;

  rustBuild = {
    inherit version src;
    cargoLock.lockFile = ../Cargo.lock;
    nativeBuildInputs = with pkgs; [ clang mold ] ++ buildDeps;
    buildInputs = buildDeps;
    RUSTFLAGS = "-C link-arg=-fuse-ld=mold";
  };

  leeward-cli-unwrapped = pkgs.rustPlatform.buildRustPackage (rustBuild // {
    pname = "leeward-cli";
    cargoBuildFlags = [ "-p" "leeward-cli" ];
    cargoTestFlags = [ "-p" "leeward-cli" ];
  });

  leeward-daemon-unwrapped = pkgs.rustPlatform.buildRustPackage (rustBuild // {
    pname = "leeward-daemon";
    cargoBuildFlags = [ "-p" "leeward-daemon" ];
    cargoTestFlags = [ "-p" "leeward-daemon" ];
  });

  # Wrapped daemon with all runtime dependencies in PATH
  leeward-daemon = pkgs.stdenv.mkDerivation {
    pname = "leeward-daemon";
    inherit version;

    nativeBuildInputs = [ pkgs.makeWrapper ];

    # No source, just wrapping
    dontUnpack = true;

    installPhase = ''
      runHook preInstall

      mkdir -p $out/bin $out/share/leeward

      # Create wrapper with proper environment
      makeWrapper ${leeward-daemon-unwrapped}/bin/leeward-daemon $out/bin/leeward-daemon \
        --prefix PATH : "${pkgs.lib.makeBinPath runtimeDeps}" \
        --set LEEWARD_PYTHON_PATH "${pythonEnv}/bin/python3" \
        --set LEEWARD_SANDBOX_PATHS "${sandboxPaths}"

      # Symlink the unwrapped binary for debugging
      ln -s ${leeward-daemon-unwrapped}/bin/leeward-daemon $out/bin/leeward-daemon-unwrapped

      runHook postInstall
    '';

    meta = with pkgs.lib; {
      description = "Leeward sandbox daemon with pre-configured Python environment";
      homepage = "https://github.com/vektia/leeward";
      license = licenses.asl20;
      platforms = platforms.linux;
    };
  };

  # Wrapped CLI
  leeward-cli = pkgs.stdenv.mkDerivation {
    pname = "leeward-cli";
    inherit version;

    nativeBuildInputs = [ pkgs.makeWrapper ];
    dontUnpack = true;

    installPhase = ''
      runHook preInstall

      mkdir -p $out/bin

      makeWrapper ${leeward-cli-unwrapped}/bin/leeward $out/bin/leeward \
        --prefix PATH : "${pkgs.lib.makeBinPath runtimeDeps}"

      runHook postInstall
    '';

    meta = with pkgs.lib; {
      description = "Leeward CLI";
      homepage = "https://github.com/vektia/leeward";
      license = licenses.asl20;
      platforms = platforms.linux;
    };
  };

  leeward-ffi = pkgs.rustPlatform.buildRustPackage (rustBuild // {
    pname = "leeward-ffi";
    cargoBuildFlags = [ "-p" "leeward-ffi" ];
    cargoTestFlags = [ "-p" "leeward-ffi" ];
    nativeBuildInputs = with pkgs; [ clang mold cbindgen ] ++ buildDeps;

    postInstall = ''
      mkdir -p $out/lib $out/include
      cp target/release/libleeward.so $out/lib/ 2>/dev/null || true
      cp target/release/libleeward.a $out/lib/ 2>/dev/null || true
      if [ -f include/leeward.h ]; then
        cp include/leeward.h $out/include/
      fi
    '';
  });

in
{
  inherit leeward-cli leeward-daemon leeward-ffi;
  inherit leeward-cli-unwrapped leeward-daemon-unwrapped;
  inherit pythonEnv runtimeDeps;

  leeward-all = pkgs.symlinkJoin {
    name = "leeward-${version}";
    paths = [ leeward-cli leeward-daemon leeward-ffi ];
    meta = with pkgs.lib; {
      description = "Complete leeward sandbox suite";
      homepage = "https://github.com/vektia/leeward";
      license = licenses.asl20;
      platforms = platforms.linux;
    };
  };
}