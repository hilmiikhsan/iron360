# Iron360 — Deploy (server + Cloudflare Tunnel)

> Secrets (admin password, server/SSH password, API keys) are **never** committed.
> They are set in `.env` on the server only.

## 1. Push code to GitHub

The repo is already initialized locally (`git`, branch `main`). From `VAPT-AI/`:

```bash
git remote add origin https://github.com/hilmiikhsan/iron360.git   # once
git push -u origin main
```
(You authenticate to GitHub yourself — a token or `gh auth login`.)

## 2. On the server (<SERVER_IP>)

```bash
ssh <deploy-user>@<SERVER_IP>
sudo apt update && sudo apt install -y python3-venv git
git clone https://github.com/hilmiikhsan/iron360.git
cd iron360
python3 -m venv .venv && ./.venv/bin/pip install -r requirements.txt

# Create .env (NOT committed). Use a STRONG admin password — rotate the demo one.
cp .env.example .env
nano .env     # set IRON360_ADMIN_PASSWORD, IRON360_JWT_SECRET, ANTHROPIC_API_KEY,
              # and IRON360_ALLOWED_ORIGINS=https://<your-tunnel-domain>

# Recommended: also install the security tools the executor uses, so live mode can run them:
#   nmap nuclei httpx subfinder dnsx ffuf sqlmap
```

Run as a service:
```bash
sudo cp deploy/iron360.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now iron360
sudo systemctl status iron360        # should be active, listening on 127.0.0.1:8000
```

## 3. Cloudflare Tunnel (public demo URL, no open ports)

```bash
# Install cloudflared
curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 \
  -o /usr/local/bin/cloudflared && chmod +x /usr/local/bin/cloudflared

cloudflared tunnel login                       # opens a URL to authorize your CF account
cloudflared tunnel create iron360
# Map a hostname to the local app:
cloudflared tunnel route dns iron360 iron360.<your-domain>.com
```
`~/.cloudflared/config.yml`:
```yaml
tunnel: iron360
credentials-file: /home/<deploy-user>/.cloudflared/<tunnel-id>.json
ingress:
  - hostname: iron360.<your-domain>.com
    service: http://127.0.0.1:8000
  - service: http_status:404
```
Run it as a service:
```bash
sudo cloudflared service install
sudo systemctl enable --now cloudflared
```

**Quick demo (no DNS):** `cloudflared tunnel --url http://127.0.0.1:8000` prints a temporary
`https://<random>.trycloudflare.com` URL immediately.

## 4. After first login
- Log in, go to **Settings → Change password**, and rotate the admin password.
- Set `ANTHROPIC_API_KEY` in `.env` and `systemctl restart iron360` to switch from SIMULATION to LIVE AI.

## Security checklist
- [ ] `.env` present on server, not in git (`git check-ignore .env` → prints `.env`)
- [ ] Strong `IRON360_JWT_SECRET` set (or let it auto-generate into `data/.jwt_secret`)
- [ ] Admin password rotated from the demo value
- [ ] `IRON360_ALLOWED_ORIGINS` set to the tunnel domain only
- [ ] App bound to `127.0.0.1` (public access only via the tunnel)
