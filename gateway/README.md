# QChain gateway

One Nginx container, `qchain-web-gateway`: the single public entry point of the QChain API. Tailscale Funnel
forwards `https://qchain.tail4fff4b.ts.net` to it on port 8090.

| Path | Goes to |
|------|---------|
| `/api/` | the Go backend on `localhost:3000` (the `/api` prefix is stripped: `/api/health` → `/health`) |
| `/gw-health` | `ok`, the gateway's own health check |
| `/` | a 302 redirect to QPortal on Vercel (`https://qportal.vercel.app`), path kept |

QPortal used to be compiled into this image. Since November 2026 it is built and hosted by Vercel from the
[qchain-portal](https://github.com/teamqchain/qchain-portal) repository; the redirect keeps old portal links working.
QWallet (mobile) calls `/api/` directly.

## Files

| File | Purpose |
|------|---------|
| `Dockerfile` | `nginx:alpine` plus `nginx.conf`; health check on `/gw-health` |
| `nginx.conf` | the routing above |
| `docker-build.sh` | builds `qchain-web-gateway:latest` (build context: this folder) |
| `docker-run.sh` | replaces the running container (`--network host`, `--restart unless-stopped`) |
| `setup-tailscale-funnel.sh` | one-time: public HTTPS 443 → `localhost:8090` through Tailscale Funnel |

## Build, run, verify (on the VM)

```bash
bash gateway/docker-build.sh && bash gateway/docker-run.sh
curl -s http://localhost:8090/gw-health                               # → ok
curl -s http://localhost:8090/api/health                              # → {"status":"ok"} (needs the backend)
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8090/       # → 302
```

Pushing a change under `gateway/` to `main` deploys it automatically (`.github/workflows/deploy-gateway.yml`), with
a rollback to the previous image if the health check fails.

## Changing things

- **QPortal moved to another address:** change the `return 302 …` line in `nginx.conf`, push.
- **Backend port:** change `proxy_pass` in `nginx.conf` (default `127.0.0.1:3000`).
- **Gateway port:** change `listen` in `nginx.conf` and `GATEWAY_PORT` in `setup-tailscale-funnel.sh`, then re-run the
  Funnel setup.

## Notes

- The container runs with `--network host`, so `127.0.0.1:3000` is the backend on the VM itself.
- Tailscale Funnel runs as the `tailscaled` system service, so the public URL survives crashes and reboots.
- The image keeps the name `qchain-web-gateway` it had when it also served QPortal, so the CI rollback point
  (`qchain-web-gateway:previous`) stays valid across the change.
