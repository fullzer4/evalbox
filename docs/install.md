# Installation Guide

## Quick Start (No root required)

leeward works without root, but with reduced isolation (no cgroups resource limits).

```bash
# Build
cargo build --release

# Run daemon
./target/release/leeward-daemon &

# Execute code
./target/release/leeward exec "print('hello')"
```

## Full Setup (with cgroups v2)

For complete isolation with memory/CPU limits (like Docker), you need cgroups v2 configured.

### 1. Verify cgroups v2 is enabled

```bash
# Check if cgroups v2 is mounted
mount | grep cgroup2

# Should show something like:
# cgroup2 on /sys/fs/cgroup type cgroup2 (rw,nosuid,nodev,noexec,relatime)
```

If not mounted, add to kernel boot parameters:
```
systemd.unified_cgroup_hierarchy=1
```

### 2. Enable cgroup delegation for your user

#### Option A: Systemd user service (recommended)

Create `/etc/systemd/system/user@.service.d/delegate.conf`:
```ini
[Service]
Delegate=cpu cpuset io memory pids
```

Then reload:
```bash
sudo systemctl daemon-reload
```

#### Option B: Run with systemd-run

```bash
systemd-run --user --scope -p Delegate=yes ./target/release/leeward-daemon
```

#### Option C: Configure user cgroup delegation

```bash
# Add your user to systemd cgroup delegation
sudo mkdir -p /etc/systemd/system/user@$(id -u).service.d/
sudo tee /etc/systemd/system/user@$(id -u).service.d/delegate.conf << 'EOF'
[Service]
Delegate=cpu cpuset io memory pids
EOF

sudo systemctl daemon-reload
sudo systemctl restart user@$(id -u).service
```

### 3. Verify delegation

```bash
# Check your user's cgroup
cat /sys/fs/cgroup/user.slice/user-$(id -u).slice/cgroup.controllers
# Should show: cpuset cpu io memory pids
```

### 4. Run leeward with full isolation

```bash
# As root (simplest, for testing)
sudo ./target/release/leeward-daemon

# Or as user with delegation configured
./target/release/leeward-daemon
```

## Distribution-Specific Setup

### NixOS

Add to your `configuration.nix`:

```nix
{ config, pkgs, ... }:
{
  # Enable cgroups v2 (default on modern NixOS)
  boot.kernelParams = [ "systemd.unified_cgroup_hierarchy=1" ];
  
  # Enable user namespaces
  boot.kernel.sysctl."kernel.unprivileged_userns_clone" = 1;
  
  # Import leeward module
  imports = [ 
    (builtins.fetchTarball "https://github.com/vektia/leeward/archive/main.tar.gz" + "/nix/module.nix")
  ];
  
  services.leeward = {
    enable = true;
    # Optional: configure workers, memory limits, etc.
    workers = 4;
  };
}
```

### Ubuntu/Debian

```bash
# Enable cgroups v2 (if not already)
sudo sed -i 's/GRUB_CMDLINE_LINUX=""/GRUB_CMDLINE_LINUX="systemd.unified_cgroup_hierarchy=1"/' /etc/default/grub
sudo update-grub
sudo reboot

# Enable user namespaces
echo 'kernel.unprivileged_userns_clone=1' | sudo tee /etc/sysctl.d/99-userns.conf
sudo sysctl --system

# Setup cgroup delegation
sudo mkdir -p /etc/systemd/system/user@.service.d/
sudo tee /etc/systemd/system/user@.service.d/delegate.conf << 'EOF'
[Service]
Delegate=cpu cpuset io memory pids
EOF
sudo systemctl daemon-reload
```

### Fedora/RHEL

```bash
# cgroups v2 is default on Fedora 31+

# Enable user namespaces (if disabled)
sudo sysctl -w kernel.unprivileged_userns_clone=1
echo 'kernel.unprivileged_userns_clone=1' | sudo tee /etc/sysctl.d/99-userns.conf

# Setup cgroup delegation
sudo mkdir -p /etc/systemd/system/user@.service.d/
sudo tee /etc/systemd/system/user@.service.d/delegate.conf << 'EOF'
[Service]
Delegate=cpu cpuset io memory pids
EOF
sudo systemctl daemon-reload
```

### Arch Linux

```bash
# cgroups v2 is default

# Enable cgroup delegation
sudo mkdir -p /etc/systemd/system/user@.service.d/
sudo tee /etc/systemd/system/user@.service.d/delegate.conf << 'EOF'
[Service]
Delegate=cpu cpuset io memory pids
EOF
sudo systemctl daemon-reload
```

## Systemd Service (Production)

Create `/etc/systemd/system/leeward.service`:

```ini
[Unit]
Description=Leeward Sandbox Daemon
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/leeward-daemon
Restart=always
RestartSec=5

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

# Cgroup delegation for workers
Delegate=cpu cpuset io memory pids

# Resource limits for the daemon itself
MemoryMax=1G
CPUQuota=200%

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl enable leeward
sudo systemctl start leeward
```

## Docker/Podman (Alternative)

If you can't configure cgroups on the host, run leeward inside a privileged container:

```bash
# Docker
docker run -d --privileged --name leeward \
  -v /var/run/leeward:/var/run/leeward \
  ghcr.io/vektia/leeward:latest

# Podman (rootless with --userns=keep-id)
podman run -d --privileged --userns=keep-id --name leeward \
  -v /var/run/leeward:/var/run/leeward \
  ghcr.io/vektia/leeward:latest
```

## Troubleshooting

### "Permission denied" on cgroups

```bash
# Check if cgroups v2 is mounted
mount | grep cgroup

# Check delegation
cat /sys/fs/cgroup/user.slice/user-$(id -u).slice/cgroup.controllers

# Try running with systemd-run
systemd-run --user --scope -p Delegate=yes ./target/release/leeward-daemon
```

### "Operation not permitted" on namespaces

```bash
# Check if user namespaces are enabled
cat /proc/sys/kernel/unprivileged_userns_clone
# Should be 1

# If 0, enable:
sudo sysctl -w kernel.unprivileged_userns_clone=1
```

### Landlock not available

```bash
# Check kernel version (need >= 5.13)
uname -r

# Check if Landlock is enabled
cat /sys/kernel/security/lsm
# Should include "landlock"
```

## Verification

After setup, verify everything works:

```bash
# Start daemon
./target/release/leeward-daemon &

# Check status
./target/release/leeward status

# Execute test code
./target/release/leeward exec "import os; print(os.getpid())"

# Check isolation (should fail - no network in sandbox)
./target/release/leeward exec "import urllib.request; urllib.request.urlopen('http://google.com')"
```
