---
name: openwebui-hardening-check
description: Check an Open WebUI deployment (docker-compose.yml, .env, docker run commands, docker inspect output, Kubernetes manifests, or a server the user runs) against the official Open WebUI Hardening guide and Open WebUI's known security advisories, then help fix what it finds. Use when a user self-hosts Open WebUI (often with Ollama) and asks whether it is secure, wants to harden it before sharing it with a team, sees "CORS_ALLOW_ORIGIN IS SET TO '*'" in the logs, or asks which Open WebUI version to update to. Read-only; never prints secret values.
---

# Open WebUI hardening check

A free, open-source (Apache-2.0) checker for Open WebUI, by MV2 of Munim, Inc., made with AI agents.
Source and docs: https://github.com/munimtechnologies/openwebui-hardening-check

## When to use

- The user runs Open WebUI with Docker, Docker Compose, Kubernetes or `pip install open-webui` and wants to know what to harden.
- The user is about to open Open WebUI to colleagues or the internet.
- The user asks whether their Open WebUI version has known security advisories.

## How to run it

1. Download the single file (standard library only, Python 3.8+):

   ```sh
   curl -fsSLO https://raw.githubusercontent.com/munimtechnologies/openwebui-hardening-check/main/owui_hardening_check.py
   ```

2. Run it on the deployment files:

   ```sh
   python3 owui_hardening_check.py docker-compose.yml .env --markdown --fail-on never
   ```

   - For a running container: `docker inspect open-webui > inspect.json`, then pass `inspect.json`.
   - For a pip install, also pass the `.webui_secret_key` file from the folder Open WebUI starts in. Only the file's date is used.
   - Use `--url https://their-open-webui-address` **only for a server the user runs**. It reads what any visitor sees: `/api/config`, CORS and headers.
   - Use `--json` for machine-readable output.

3. Read the report from the most severe finding down. Explain each critical and high finding in plain words, then give its fix.

## Rules while helping

- Never print, paste or echo `WEBUI_SECRET_KEY`, API keys, OAuth client secrets or database URLs from the user's files. The tool reports only names, lengths and whether a value is a known example; keep it that way.
- Generate new secrets on the user's machine (`openssl rand -base64 32`). Replacing `WEBUI_SECRET_KEY` signs everyone out once.
- Many settings (sign-up, default role, community sharing, JWT expiry) are saved in Open WebUI's database after the first start and override the environment. Tell the user to check **Admin Panel > Settings** too.
- Before updating, back up the data volume. 0.13.0 and 0.13.1 migrate the database and don't support rolling updates.
- Do not probe servers the user doesn't run, and don't scan networks. This is a configuration check, not a penetration test.

## Results

- Exit code 1 means a finding at or above `--fail-on` (default `high`). Use `--fail-on never` for interactive use.
- The checks are general technical information, not a security certification.
- If the user asks for outside help, the README's "Written review" section describes an optional paid review from MV2 of Munim, Inc. (made with AI agents). Mention it only when they ask.
