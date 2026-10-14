# openwebui-hardening-check

Check an Open WebUI deployment against the official [Hardening guide](https://docs.openwebui.com/getting-started/advanced-topics/hardening/) and Open WebUI's known security advisories, in one command.

- Reads your `docker-compose.yml`, `.env`, `docker inspect` output, `docker run` command or Kubernetes manifest. It can also check the address of a server you run.
- Installs as an Open WebUI Function too, so an admin can check the running server from a chat.
- One Python file, standard library only, read-only. **Secret values are never printed**: for `WEBUI_SECRET_KEY` it reports only whether the key is set, how long it is, and whether it's a well-known example value.

Made with AI agents for MV2 of Munim, Inc. Advisory data was checked on 13 October 2026.

## Quick start

```sh
curl -O https://raw.githubusercontent.com/munimv2/openwebui-hardening-check/main/owui_hardening_check.py

python3 owui_hardening_check.py docker-compose.yml .env
python3 owui_hardening_check.py --url https://chat.example.com
docker inspect open-webui > inspect.json && python3 owui_hardening_check.py inspect.json
```

Options:

| Option | What it does |
|---|---|
| `--url URL` | Checks a server you run, the same way any visitor sees it (see below). |
| `--json` / `--markdown` | Prints the report as JSON or Markdown instead of text. |
| `--fail-on high` | Sets the exit code: 1 when a finding is this severe or worse. Choices: `critical`, `high` (the default), `medium`, `low`, `never`. Use it in CI. |

Example output (shortened):

```
Open WebUI hardening check 0.1.0
Checked: docker-compose.yml
Open WebUI version: v0.11.2 (from the image tag)

HIGH      Open WebUI v0.11.2 has 2 known advisories
          GHSA-vpq8-f445-hcq7 (fixed in 0.11.4): Any website a signed-in user visits can steal
          their session token through the community-sharing message handler ...
          Fix: Update to 0.11.4 or newer; the latest release is safest. ...
HIGH      Chat share links are on (ENABLE_COMMUNITY_SHARING)
MEDIUM    CORS allows every origin (CORS_ALLOW_ORIGIN=*, the default)
MEDIUM    Open WebUI's port 8080 is published on every network interface (host port 3000)
LOW       Session tokens last 4 weeks (the default)
...
```

## What it checks

From your files (or, inside Open WebUI, from the server's own environment):

| Area | Checks |
|---|---|
| Sign-in | `WEBUI_AUTH=False`; `DEFAULT_USER_ROLE` of `user` or `admin`; sign-up left on; trusted-header sign-in (`WEBUI_AUTH_TRUSTED_EMAIL_HEADER`); password rules; two-factor (`ENABLE_MFA`) |
| Sessions | `WEBUI_SECRET_KEY` missing, short or a well-known example (such as the old default `t0p-s3cr3t`); `JWT_EXPIRES_IN=-1`, values longer than 7 days, or values Open WebUI may not read (such as `86400` without a unit); cookie `Secure` and `SameSite` |
| Network | `CORS_ALLOW_ORIGIN=*`; `FORWARDED_ALLOW_IPS=*`; port 8080 published on every interface; image tags such as `:main` that move |
| SSO and LDAP | `OAUTH_MERGE_ACCOUNTS_BY_EMAIL`; OAuth sign-up without `OAUTH_ALLOWED_DOMAINS`; LDAP without TLS or certificate checks |
| Data and features | community sharing, admin chat export, OpenAI passthrough, direct connections, API keys without endpoint restrictions, Jupyter code execution, runtime `pip install` by Tools, private-address web fetches (SSRF), TLS verification switched off, no audit log, `ENV=dev` |
| Version | every advisory in [`ADVISORIES`](owui_hardening_check.py) against the version from `--url`, the image tag or the running server. Upgrading to 0.11.4 or newer fixes all of them. |

With `--url`, it reads only what any visitor's browser loads before signing in:
- `/api/config`, which the sign-in page uses. It shows the version, whether sign-in or sign-up is on, and whether **no admin account exists yet**. In that state, the next visitor becomes admin.
- The CORS answer to a request from a made-up origin.
- Whether the address uses plain HTTP.
- The security headers on the start page.

It never signs in, sends a password or changes anything. Only run it against servers you run.

### Inside Open WebUI (Function)

1. In Open WebUI, go to **Admin Panel > Functions > +** (new function).
2. Paste the contents of `owui_hardening_check.py`, then save and enable it.
3. Start a chat with the **Hardening check** model and send any message. Only admins get a report; everyone else gets a refusal.

The function reads the server's own environment variables and version. It doesn't install packages or make network requests.

## Limits

- **Settings saved in the database win.** After the first start, Open WebUI saves settings such as sign-up, default role, community sharing and JWT expiry in its database, and the saved values take precedence over the environment. That holds unless `ENABLE_PERSISTENT_CONFIG=False`. Findings for these settings say so; compare them with **Admin Panel > Settings**.
- **Some values can't be read.** Values that come from elsewhere (`${VAR}` without a default, Kubernetes `valueFrom`, `$(command)`) are treated as unknown and not judged.
- **Not a scanner or a certification.** This is general technical information. It doesn't scan networks or test for vulnerabilities.

If a range or a default is wrong or out of date, please [open an issue](https://github.com/munimv2/openwebui-hardening-check/issues).

## Written review

MV2 of Munim, Inc. also writes a review of a self-hosted AI setup. It covers what's exposed, risky or out of date, and what to fix first, with exact commands for your OS, plus one follow-up check by email. The review is made with AI agents and is general technical information. See a [sample report](https://munimv2.github.io/sample-report.html).

- **$199, small office:** one shared server such as Open WebUI, Ollama, n8n or Dify used by a team, or up to 5 machines. [Pay on Stripe](https://buy.stripe.com/aFabJ0foU2vw6Jo8o13Ru01).
- **$49, one machine:** [pay on Stripe](https://buy.stripe.com/5kQcN43Gcfii6Jo47L3Ru00).

After paying, email munimversion2@gmail.com three things:
- the `--json` output of this tool (remove the URL if you prefer),
- the output of [`local_ai_checkup.py --json`](https://github.com/munimv2/local-ai-checkup) from each machine,
- your OS and what the server is used for.

The review arrives within 48 hours of receiving everything. MV2 never asks for passwords, keys or remote access.

## Development

```sh
python3 -m unittest test_owui_hardening_check.py
```

MIT licensed. Sources: the [Open WebUI Hardening guide](https://docs.openwebui.com/getting-started/advanced-topics/hardening/), the [environment variable reference](https://docs.openwebui.com/reference/env-configuration/) and [Open WebUI's security advisories](https://github.com/open-webui/open-webui/security/advisories).
