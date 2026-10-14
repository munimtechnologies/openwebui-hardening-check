# openwebui-hardening-check

Check an Open WebUI deployment against the official [Hardening guide](https://docs.openwebui.com/getting-started/advanced-topics/hardening/) and Open WebUI's known security advisories, in one command.

- Reads your `docker-compose.yml`, `.env`, `docker inspect` output, `docker run` command or Kubernetes manifest. It can also check the address of a server you run.
- Installs as an Open WebUI Function too, so an admin can check the running server from a chat.
- Runs as a GitHub Action, so a pull request that weakens your deployment files fails before it ships.
- One Python file, standard library only, read-only. **Secret values are never printed**: for `WEBUI_SECRET_KEY` it reports only whether the key is set, how long it is, and whether it's a well-known example value.

Made with AI agents for MV2 of Munim, Inc. Advisory data was checked on 14 October 2026, including Open WebUI 0.12.0 (10 October 2026).

## Quick start

```sh
curl -O https://raw.githubusercontent.com/munimv2/openwebui-hardening-check/main/owui_hardening_check.py

python3 owui_hardening_check.py docker-compose.yml .env
python3 owui_hardening_check.py --url https://chat.example.com
docker inspect open-webui > inspect.json && python3 owui_hardening_check.py inspect.json

# pip install (`open-webui serve`): give the key file from the folder you start it in
python3 owui_hardening_check.py --url http://localhost:8080 .webui_secret_key
```

Options:

| Option | What it does |
|---|---|
| `--url URL` | Checks a server you run, the same way any visitor sees it (see below). |
| `--json` / `--markdown` | Prints the report as JSON or Markdown instead of text. |
| `--fail-on high` | Sets the exit code: 1 when a finding is this severe or worse. Choices: `critical`, `high` (the default), `medium`, `low`, `never`. Use it in CI. |

Example output (shortened):

```
Open WebUI hardening check 0.1.2
Checked: docker-compose.yml
Open WebUI version: v0.11.2 (from the image tag)

HIGH      Open WebUI v0.11.2 has 6 known advisories
          GHSA-vpq8-f445-hcq7 (fixed in 0.11.4): Any website a signed-in user visits can steal
          their session token through the community-sharing message handler ...
          GHSA-f9xp-mfmq-x6cg (fixed in 0.11.4): Any signed-in user can steal another user's
          session token with a script inside a DOCX file preview (High). ...
          Fix: Update to 0.12.0 or newer; the latest release is safest. ...
HIGH      Chat share links are on (ENABLE_COMMUNITY_SHARING)
MEDIUM    CORS allows every origin (CORS_ALLOW_ORIGIN=*, the default)
MEDIUM    Open WebUI's port 8080 is published on every network interface (host port 3000)
LOW       Session tokens last 4 weeks (the default)
...
```

## In CI (GitHub Actions)

If your deployment files (`docker-compose.yml`, an `.env` template, Kubernetes manifests) live in a repository, check them on every push and pull request:

```yaml
# .github/workflows/openwebui-hardening.yml
name: Open WebUI hardening
on: [push, pull_request]
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: munimv2/openwebui-hardening-check@v0.1.2
        with:
          files: docker-compose.yml deploy/*.yaml   # spaces or new lines; wildcards work
          fail-on: high                              # critical, high, medium, low or never
```

- The report goes to the job log and the job summary. Critical and high findings become error annotations, medium ones warnings.
- The step fails when a finding is at least as severe as `fail-on`.
- Outputs: `report` (path of the JSON report) and the counts `critical`, `high`, `medium` and `low`.
- Files that don't exist are skipped with a warning.
- `url` also works. Only use it for a server you run, and keep in mind that the job summary shows the address.

It needs Python 3, which GitHub's Linux and macOS runners have. Pin a release tag (`@v0.1.2`) and update on purpose.

## What it checks

From your files (or, inside Open WebUI, from the server's own environment):

| Area | Checks |
|---|---|
| Sign-in | `WEBUI_AUTH=False`; `DEFAULT_USER_ROLE` of `user` or `admin`; sign-up left on; trusted-header sign-in (`WEBUI_AUTH_TRUSTED_EMAIL_HEADER`); password rules; two-factor sign-in (`ENABLE_MFA`, new in 0.12.0) and the `MFA_ALLOW_OAUTH_BYPASS` / `MFA_ALLOW_TRUSTED_HEADER_BYPASS` exceptions |
| Sessions | `WEBUI_SECRET_KEY` missing, short or a well-known example (such as the old default `t0p-s3cr3t`); a `.webui_secret_key` made by `open-webui serve` before 0.12.0 (see below); `JWT_EXPIRES_IN=-1`, values longer than 7 days, or values Open WebUI may not read (such as `86400` without a unit); cookie `Secure` and `SameSite` |
| Network | `CORS_ALLOW_ORIGIN=*`, and entries that stop Open WebUI from starting or never match (see below); `FORWARDED_ALLOW_IPS=*`; port 8080 published on every interface; image tags such as `:main` that move |
| SSO and LDAP | `OAUTH_MERGE_ACCOUNTS_BY_EMAIL`; OAuth sign-up without `OAUTH_ALLOWED_DOMAINS`; LDAP without TLS or certificate checks |
| Data and features | community sharing, admin chat export, OpenAI passthrough, direct connections, API keys without endpoint restrictions, Jupyter code execution, runtime `pip install` by Tools, private-address web fetches (SSRF), TLS verification switched off, no audit log, `ENV=dev` |
| Version | every advisory in [`ADVISORIES`](owui_hardening_check.py) against the version from `--url`, the image tag or the running server, including the advisories fixed in 0.11.4 and published on 27 and 28 September 2026 (the High ones are named one by one) and the security fixes in the 0.12.0 release notes. Updating to 0.12.0 or newer fixes all of them. |

With `--url`, it reads only what any visitor's browser loads before signing in:
- `/api/config`, which the sign-in page uses. It shows the version, whether sign-in or sign-up is on, and whether **no admin account exists yet**. In that state, the next visitor becomes admin.
- The CORS answer to a request from a made-up origin.
- Whether the address uses plain HTTP.
- The security headers on the start page.

It never signs in, sends a password or changes anything. Only run it against servers you run.

### "CORS_ALLOW_ORIGIN IS SET TO '*'" in the logs

At startup Open WebUI logs `WARNING: CORS_ALLOW_ORIGIN IS SET TO '*' - NOT RECOMMENDED FOR PRODUCTION DEPLOYMENTS.` when `CORS_ALLOW_ORIGIN` isn't set. Then any website can make cross-origin requests to your server. To fix it, list the exact addresses people open Open WebUI at, separated by `;`:

```sh
CORS_ALLOW_ORIGIN=https://chat.example.com;http://localhost:3000
```

The same list decides which websocket connections are accepted, so leave out an address people use and you'll see `is not an accepted origin` in the logs. In [0.12.0's config.py](https://github.com/open-webui/open-webui/blob/v0.12.0/backend/open_webui/config.py) Open WebUI splits the value on `;` and checks each entry at startup:

| You wrote | What happens | The tool says |
|---|---|---|
| `chat.example.com` (no `https://`), `https://a.example.com;` (ends with `;`), `*;https://a.example.com`, or an empty value | Open WebUI stops at startup with `Invalid URL structure in CORS_ALLOW_ORIGIN` | medium: won't start |
| `https://chat.example.com/` (trailing slash), `https://a.example.com,https://b.example.com` (commas), `https://a.example.com; https://b.example.com` (space) | It starts, but browsers never send that origin, so requests and websockets from it fail | low: no browser sends it |

Custom schemes such as `app://` are allowed only when they're listed in `CORS_ALLOW_CUSTOM_SCHEME`.

### The secret key file of pip installs

When `WEBUI_SECRET_KEY` isn't set, `open-webui serve` writes a key to `.webui_secret_key` in the folder you start it from. Before 0.12.0 that key came from Python's `random.randbytes`, which isn't meant for secrets. [0.12.0](https://github.com/open-webui/open-webui/releases/tag/v0.12.0) switched to `secrets.token_bytes`, but it keeps a key file that already exists, so updating alone doesn't replace it. No practical attack is known, but this key signs every session token, and replacing it costs one extra sign-in for everyone.

Give the file to the tool and it looks only at the file's date, never its contents. Inside Open WebUI, the Function finds the file itself. Docker images make the key with `/dev/random` and aren't affected. To replace the key, stop Open WebUI, delete `.webui_secret_key` (or set `WEBUI_SECRET_KEY` to the output of `openssl rand -base64 32`), and start it again.

### Inside Open WebUI (Function)

1. In Open WebUI, go to **Admin Panel > Functions > +** (new function).
2. Paste the contents of `owui_hardening_check.py`, then save and enable it.
3. Start a chat with the **Hardening check** model and send any message. Only admins get a report; everyone else gets a refusal.

The function reads the server's own environment variables and version, plus the date of a pip install's `.webui_secret_key`. It doesn't install packages or make network requests.

## Limits

- **Settings saved in the database win.** After the first start, Open WebUI saves settings such as sign-up, default role, community sharing and JWT expiry in its database, and the saved values take precedence over the environment. That holds unless `ENABLE_PERSISTENT_CONFIG=False`. Findings for these settings say so; compare them with **Admin Panel > Settings**.
- **Some values can't be read.** Values that come from elsewhere (`${VAR}` without a default, Kubernetes `valueFrom`, `$(command)`) are treated as unknown and not judged.
- **Withheld advisories.** Open WebUI holds back some advisories for a short time after a release so admins can update. The tool counts the 0.12.0 fixes from the release notes until those advisories are published.
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

Also by MV2: [dify-hardening-check](https://github.com/munimv2/dify-hardening-check), the same kind of check for Dify.

Open WebUI is a trademark of its owners. This project is not affiliated with or endorsed by Open WebUI.

## Development

```sh
python3 -m unittest test_owui_hardening_check.py test_action.py
```

Apache-2.0 licensed. Sources: the [Open WebUI Hardening guide](https://docs.openwebui.com/getting-started/advanced-topics/hardening/), the [environment variable reference](https://docs.openwebui.com/reference/env-configuration/), [Open WebUI's security advisories](https://github.com/open-webui/open-webui/security/advisories), the [0.12.0 release notes](https://github.com/open-webui/open-webui/releases/tag/v0.12.0) and [0.12.0's config.py](https://github.com/open-webui/open-webui/blob/v0.12.0/backend/open_webui/config.py).
