{ config, lib, pkgs, ... }:

with lib;

let
  cfg = config.services.leeward;

  leewardLib = import ./lib.nix { inherit pkgs; };
  leewardPkgs = import ./packages.nix { inherit pkgs; lib = leewardLib; };
in {
  options.services.leeward = {
    enable = mkEnableOption "leeward sandbox daemon";

    package = mkOption {
      type = types.package;
      default = leewardPkgs.leeward-daemon;
      description = "The leeward package to use.";
    };

    socketPath = mkOption {
      type = types.str;
      default = "/run/leeward/leeward.sock";
      description = "Path to the Unix socket.";
    };

    numWorkers = mkOption {
      type = types.int;
      default = 4;
      description = "Number of worker processes in the pool.";
    };

    recycleAfter = mkOption {
      type = types.int;
      default = 100;
      description = "Recycle workers after this many executions.";
    };

    memoryLimit = mkOption {
      type = types.str;
      default = "256M";
      description = "Memory limit per worker (e.g., 256M, 1G).";
    };

    cpuQuota = mkOption {
      type = types.str;
      default = "100%";
      description = "CPU quota for workers (e.g., 100%, 200% for 2 cores).";
    };

    user = mkOption {
      type = types.str;
      default = "leeward";
      description = "User to run the daemon as.";
    };

    group = mkOption {
      type = types.str;
      default = "leeward";
      description = "Group for socket access.";
    };
  };

  config = mkIf cfg.enable {
    # Kernel parameters for sandbox features
    boot.kernel.sysctl = {
      "kernel.unprivileged_userns_clone" = 1;
    };

    systemd.services.leeward = {
      description = "Leeward sandbox daemon";
      documentation = [ "https://github.com/vektia/leeward" ];
      after = [ "network.target" ];
      wantedBy = [ "multi-user.target" ];

      environment = {
        LEEWARD_SOCKET = cfg.socketPath;
        LEEWARD_WORKERS = toString cfg.numWorkers;
        LEEWARD_RECYCLE_AFTER = toString cfg.recycleAfter;
      };

      serviceConfig = {
        Type = "simple";
        ExecStart = "${cfg.package}/bin/leeward-daemon";
        Restart = "on-failure";
        RestartSec = "5s";

        # Run as dedicated user
        User = cfg.user;
        Group = cfg.group;

        # Cgroup delegation - CRITICAL for sandbox to create worker cgroups
        Delegate = "cpu cpuset io memory pids";

        # Security hardening
        NoNewPrivileges = false;  # Need for user namespaces
        PrivateTmp = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        ReadWritePaths = [ "/run/leeward" ];

        # Capabilities needed for namespaces and cgroups
        AmbientCapabilities = [
          "CAP_SYS_ADMIN"      # For mount namespaces
          "CAP_SETUID"         # For user namespaces  
          "CAP_SETGID"         # For user namespaces
          "CAP_NET_ADMIN"      # For network namespaces
          "CAP_SYS_PTRACE"     # For seccomp user notifications
        ];
        CapabilityBoundingSet = [
          "CAP_SYS_ADMIN"
          "CAP_SETUID"
          "CAP_SETGID"
          "CAP_NET_ADMIN"
          "CAP_SYS_PTRACE"
        ];

        # Runtime directory
        RuntimeDirectory = "leeward";
        RuntimeDirectoryMode = "0755";

        # Resource limits for the daemon itself
        MemoryMax = "2G";
        TasksMax = "256";

        # Logging
        StandardOutput = "journal";
        StandardError = "journal";
        SyslogIdentifier = "leeward-daemon";
      };
    };

    # Create dedicated user and group
    users.users.${cfg.user} = {
      isSystemUser = true;
      group = cfg.group;
      description = "Leeward sandbox daemon user";
    };

    users.groups.${cfg.group} = {};

    # Ensure runtime directory permissions
    systemd.tmpfiles.rules = [
      "d /run/leeward 0755 ${cfg.user} ${cfg.group} - -"
    ];

    # Add CLI to system packages
    environment.systemPackages = [ leewardPkgs.leeward-cli ];
  };
}
