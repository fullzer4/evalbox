{ pkgs, config, ... }:

{
  packages = with pkgs; [
    cargo-watch
    pkg-config
    libseccomp
    mold
  ];

  languages.rust.enable = true;

  env = {
    LIBSECCOMP_LINK_TYPE = "dylib";
    LIBSECCOMP_LIB_PATH = "${pkgs.libseccomp}/lib";
    PKG_CONFIG_PATH = "${pkgs.libseccomp}/lib/pkgconfig";
    LEEWARD_SOCKET = "${config.env.DEVENV_STATE}/leeward.sock";
  };
}