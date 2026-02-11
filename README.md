# agent-sandbox

Network sandbox for AI coding agents on macOS. Works with Goose, Claude Code, pi, or any agent.

Your agent runs with full tool access — but every outbound connection goes through a local proxy you control. The macOS kernel enforces it. No process can bypass it, no matter what the agent spawns.

## How it works

Two layers:

1. **`sandbox-exec`** (macOS kernel) — blocks all outbound network except localhost. Inherits to every child process. Cannot be removed from inside.

2. **Localhost proxy** — runs outside the sandbox, tunnels traffic out on behalf of the agent. Logs every connection. Blocks domains listed in `blocked.txt` in real time.

```
Agent (sandboxed)                   Proxy (not sandboxed)
├─ bash                             ├─ logs all connections
├─ curl https://api.anthropic.com   │   to stderr + connections.log
│  └─ goes via http_proxy ──────────┤
│     proxy checks blocked.txt      │   if domain in blocked.txt:
│     → allowed → connects          │     → 403 Forbidden
│                                   │   else:
├─ python3 socket.connect(evil)     │     → tunnel through
│  └─ tries direct connect          │
│     sandbox: EPERM ✗              │
│                                   │
├─ localhost:8080 (dev server)      │
│  └─ works (sandbox allows)        │
```

The sandbox is kernel-enforced. Even if the agent unsets its proxy env vars, the kernel still blocks direct connections. Tools that don't respect proxy vars simply fail — they can't exfiltrate.

## Quick start

```bash
git clone <this-repo>
cd agent-sandbox
chmod +x *.sh
```

### 1. Start the proxy (Terminal 1)

```bash
./start-proxy.sh
```

You'll see every connection logged in real time with colour coding.

### 2. Start your agent (Terminal 2)

Pick one:

```bash
./start-goose.sh           # Goose
./start-claude.sh          # Claude Code (auto-skips permission prompts — the sandbox IS the permission layer)
./start-pi.sh              # pi
```

That's it. Your agent works normally but all network traffic is visible and controllable.

### 3. (Optional) Block domains live

Edit `blocked.txt` while everything is running. Changes take effect immediately.

```bash
echo "evil.com" >> blocked.txt        # blocks evil.com + *.evil.com
echo "pastebin.com" >> blocked.txt    # blocks paste sites
```

Remove a line to unblock.

## What gets caught

| Agent action | Result |
|---|---|
| `curl https://...` | Goes through proxy ✓ |
| `python3 urllib/requests` | Goes through proxy ✓ |
| `node fetch(...)` | Goes through proxy ✓ (via `NODE_OPTIONS=--use-env-proxy`) |
| `git clone`, `pip install`, `cargo` | Goes through proxy ✓ |
| Raw socket / `nc` / any direct connect | Kernel blocks: `EPERM` |
| `localhost:*` | Direct, works (no proxy needed) |

Tools that respect `http_proxy` / `https_proxy` env vars → routed through proxy → logged + blockable.

Tools that don't → kernel blocks them → safe failure, no exfiltration.

## Running the tests

```bash
./test.sh
```

Runs 8 tests covering: proxy routing, sandbox enforcement, Node.js fetch, live blocking, localhost access. Takes a few seconds.

## Files

| File | Purpose |
|------|---------|
| `start-proxy.sh` | Start the proxy (terminal 1) |
| `start-goose.sh` | Start Goose sandboxed |
| `start-claude.sh` | Start Claude Code sandboxed (with `--dangerously-skip-permissions`) |
| `start-pi.sh` | Start pi sandboxed |
| `proxy.py` | CONNECT proxy with logging + live domain blocklist |
| `sandbox.sb` | macOS sandbox profile |
| `blocked.txt` | Blocked domains (edit live) |
| `test.sh` | End-to-end tests |
| `connections.log` | Traffic log (created at runtime) |

## Using with other agents

Wrap any command:

```bash
# Terminal 1
./start-proxy.sh

# Terminal 2
sandbox-exec -f sandbox.sb \
    env http_proxy=http://localhost:18080 https_proxy=http://localhost:18080 \
        HTTP_PROXY=http://localhost:18080 HTTPS_PROXY=http://localhost:18080 \
        no_proxy=localhost,127.0.0.1,::1 NO_PROXY=localhost,127.0.0.1,::1 \
        NODE_OPTIONS="--use-env-proxy" \
    your-agent-here
```

## Why `--dangerously-skip-permissions`?

Claude Code normally asks for confirmation before running shell commands. That makes sense when there's no sandbox — but here, the kernel is the permission layer. The agent can't reach the network, so there's nothing dangerous about letting it run freely. You get uninterrupted autonomous operation with network-level safety.

## Limitations

- **macOS only** — uses `sandbox-exec` (Apple kernel API, deprecated but functional)
- **No TLS inspection** — the proxy sees which domains are contacted but not request bodies. Exfiltration via POST to an allowed domain is not caught.
- **Proxy env var dependent** — most tools respect `http_proxy` natively. Node.js needs `NODE_OPTIONS=--use-env-proxy` (Node 20.18+). Tools that ignore it just fail safely.
