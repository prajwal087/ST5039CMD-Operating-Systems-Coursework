# Project Report

## Task 1 — Authentication Valve

### Overview

A Unix-domain socket-based authentication server that verifies client identity using a challenge-response protocol with SHA-256 hashing. The backend drops privileges after binding and uses `SO_PEERCRED` to detect PID forgeries.

### Design

**Credential Storage:** Passwords are read from `passwd.store`, hashed with SHA-256, and stored in a locked shared-memory region (`MAP_SHARED | MAP_LOCKED`). The shared memory allows the backend to access credentials without re-reading the file on each connection.

**Privilege Dropping:** After binding the socket, the backend drops to uid/gid 65534 (`nobody`) using `setresuid`/`setresgid`, then drops all capabilities via `capset`. This ensures that even if the backend is compromised, it cannot regain root privileges.

**Forgery Detection:** The backend uses `SO_PEERCRED` to obtain the client's real PID and compares it against the PID claimed in the `auth_msg`. A mismatch is treated as a forgery attempt.

**Challenge-Response:** The server generates a 32-byte random challenge per connection. The client responds with `SHA256(challenge || SHA256(password))`. The server never sees the plaintext password.

### Security Properties

- Server drops to `nobody` (uid 65534) and drops all capabilities before handling any client
- Password never transmitted in plaintext
- PID spoofing detected via kernel-provided `SO_PEERCRED`
- Shared memory locked with `mlock` to prevent swapping of credentials
- Sensitive buffers zeroed with `secure_zero` (volatile pointer to prevent compiler optimization)

---

## Task 2 — Process Sandbox (`task2/`)

### Design

The sandbox forks a child, applies `RLIMIT_AS`, `RLIMIT_NPROC`, and `RLIMIT_CORE` via `setrlimit`, then spawns three monitoring threads:

1. **Wall-clock monitor** — checks elapsed time every 50ms
2. **CPU monitor** — samples `/proc/<pid>/stat` every 250ms, computes CPU percentage from utime/stime deltas
3. **Memory monitor** — samples RSS and thread count from `/proc/<pid>/stat` and `/proc/<pid>/status` every 300ms

When a limit is exceeded, the corresponding monitor sets an atomic `term_reason` flag. The main loop detects the flag and calls `terminate_child()`, which sends SIGTERM, waits for the grace period, then sends SIGKILL if the child is still alive.

### Termination Reasons

| Flag | Cause |
|---|---|
| `TR_WALL_CLOCK` | Wall-clock time exceeded |
| `TR_CPU_LIMIT` | CPU usage exceeded threshold |
| `TR_RSS_LIMIT` | RSS exceeded threshold |
| `TR_SELF_EXIT` | Child exited on its own |
| `TR_USER_REQ` | SIGINT/SIGTERM received by sandbox |

### Security Properties

- Child receives `PR_SET_PDEATHSIG` (SIGKILL) so it dies if the sandbox is killed
- `RLIMIT_AS` prevents memory exhaustion attacks
- `RLIMIT_NPROC` limits fork bombs
- `RLIMIT_CORE` disables core dumps
- Child's stdin/stdout/stderr redirected to `/dev/null`
- Child executed with empty environment

### JSON Log Format

All monitoring events are logged to `sandbox.log` in newline-delimited JSON:

```json
{"t":1234567890.500,"ev":"child_spawned","pid":12345,"pid":12345}
{"t":1234567891.000,"ev":"cpu_sample","pid":12345,"pct":45}
{"t":1234567891.300,"ev":"mem_sample","pid":12345,"rss_kb":10240}
{"t":1234567892.000,"ev":"cpu_exceeded","pid":12345,"cpu_pct":95}
{"t":1234567892.000,"ev":"terminating","pid":12345,"reason_mask":2}
{"t":1234567892.000,"ev":"sent_sigterm","pid":12345,"":""}
{"t":1234567892.500,"ev":"sent_sigkill","pid":12345,"":""}
```

### Test Suite

The `make test` target runs four tests:

1. **Infinite loop** — verifies wall-clock enforcement (3s limit)
2. **Memory spray** — verifies RSS limit enforcement (200 MB)
3. **Evasive binary** — verifies CPU + fork limit enforcement
4. **Clean exit** — verifies `/bin/true` exits cleanly

---

## Requirements

- Linux (uses `SO_PEERCRED`, `/proc`, `signalfd`, `eventfd`, `prctl`, `capset`)
- GCC, OpenSSL dev libraries (`libssl-dev`), libcap dev (`libcap-dev`)
- `sudo` for task1 (backend privilege dropping)
