"""
title: Open WebUI Hardening Check
author: MV2 of Munim, Inc.
author_url: https://github.com/munimv2/openwebui-hardening-check
version: 0.1.0
license: MIT
description: Checks an Open WebUI deployment against the official Hardening guide and known security advisories. Read-only, standard library only, and it never shows secret values. Made with AI agents for MV2 of Munim, Inc.
"""
# Command line:
#   python3 owui_hardening_check.py docker-compose.yml .env
#   python3 owui_hardening_check.py --url https://chat.example.com
# Inside Open WebUI: add this file under Admin Panel > Functions; admins can
# then chat with it to check the running server's own settings. (No shebang:
# Open WebUI only reads the metadata above when the file starts with it.)

import argparse
import ipaddress
import json
import os
import re
import sys
import textwrap
import urllib.error
import urllib.request
from urllib.parse import urlsplit

__version__ = "0.1.0"
DATA_DATE = "13 October 2026"
REPO = "https://github.com/munimv2/openwebui-hardening-check"
GUIDE = "https://docs.openwebui.com/getting-started/advanced-topics/hardening/"
ADVISORY_PAGE = "https://github.com/open-webui/open-webui/security/advisories"
PROBE_ORIGIN = "https://cors-check.invalid"

SEVERITIES = ["critical", "high", "medium", "low", "info"]
RANK = {s: i for i, s in enumerate(SEVERITIES)}

# Values of these settings are never printed.
SENSITIVE = re.compile(r"SECRET|KEY|PASSWORD|TOKEN|DATABASE_URL|REDIS_URL|DSN|CREDENTIAL", re.I)

# Settings Open WebUI saves to its database on first start. After that the
# saved value wins over the environment unless ENABLE_PERSISTENT_CONFIG=False.
PERSISTED = {
    "ENABLE_SIGNUP", "DEFAULT_USER_ROLE", "ENABLE_LOGIN_FORM", "ENABLE_COMMUNITY_SHARING",
    "JWT_EXPIRES_IN", "ENABLE_API_KEYS", "ENABLE_API_KEY", "ENABLE_DIRECT_CONNECTIONS",
    "ENABLE_CODE_EXECUTION", "CODE_EXECUTION_ENGINE", "ENABLE_CODE_INTERPRETER",
    "CODE_INTERPRETER_ENGINE", "ENABLE_LDAP",
}

# Values seen in old defaults, tutorials and example files.
WEAK_SECRETS = {
    "t0p-s3cr3t", "secret", "changeme", "change-me", "change_me", "your-secret-key",
    "your_secret_key", "yoursecretkey", "mysecret", "my-secret-key", "password",
    "123456", "12345678", "supersecret", "super-secret", "openwebui", "open-webui",
}

# Open WebUI advisories: [first affected or None, fixed in, ids, summary, source].
# Checked against the linked advisories on 13 October 2026.
ADVISORIES = [
    [None, "0.9.0", "CVE-2026-44721, CVE-2026-45349",
     "Stored XSS through models; a user with an API key can continue another user's chat.",
     "https://www.cve.org/CVERecord?id=CVE-2026-44721"],
    [None, "0.9.3", "CVE-2026-45317", "Request forgery through image URLs.",
     "https://www.cve.org/CVERecord?id=CVE-2026-45317"],
    [None, "0.9.6", "CVE-2026-54010", "Signed-in users can read and delete other users' files.",
     "https://www.cve.org/CVERecord?id=CVE-2026-54010"],
    [None, "0.11.0", "CVE-2026-70480", "vega/vega-lite blocks can make viewers' browsers send requests.",
     "https://www.cve.org/CVERecord?id=CVE-2026-70480"],
    ["0.6.41", "0.11.1", "CVE-2026-87016",
     "Wildcards in OAuth/SCIM subject lookups on SQLite let a user sign in as another account (High).",
     "https://github.com/advisories/GHSA-wpmr-8h3q-fwj7"],
    ["0.8.11", "0.11.1", "CVE-2026-87995",
     "Terminal port preview allows same-origin script execution and session theft (High).",
     "https://github.com/advisories/GHSA-jmc6-2wr8-h3wj"],
    ["0.6.27", "0.11.1", "CVE-2026-87011, CVE-2026-87015 and others",
     "Unauthenticated back-channel logout requests can stall the server; access-control bugs in notes, knowledge search and channels.",
     "https://github.com/advisories?query=open-webui+0.11.1"],
    ["0.7.0", "0.11.4", "GHSA-vpq8-f445-hcq7",
     "Any website a signed-in user visits can steal their session token through the community-sharing message handler (CVSS 8.1; only while community sharing is on, the default).",
     "https://github.com/open-webui/open-webui/security/advisories/GHSA-vpq8-f445-hcq7"],
    [None, "0.11.4", "GHSA-wf9m-46cp-c6h6, GHSA-qpqv-xwg8-cqpj and others",
     "javascript: links in chat messages or shared-chat citations can steal a viewer's session token; terminal-proxy access control and memory-exhaustion bugs.",
     ADVISORY_PAGE],
]
SAFE_VERSION = "0.11.4"


def parse_version(text):
    m = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", str(text or ""))
    if not m:
        return None
    return tuple(int(x or 0) for x in m.groups())


def finding(severity, title, fix, detail="", setting=None, source=GUIDE):
    if setting in PERSISTED:
        fix += (" Open WebUI stores this setting in its database after the first start, so also"
                " check it under Admin Panel > Settings.")
    return {"severity": severity, "title": title, "detail": detail, "fix": fix,
            "setting": setting, "source": source}


# ---------------------------------------------------------------- reading files

class Deployment:
    def __init__(self):
        self.env = {}      # name -> value; None when the value comes from somewhere this tool can't see
        self.images = []
        self.ports = []    # (host_ip, host_port, container_port)
        self.sources = []


def _unquote(value):
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def _clean_value(raw):
    raw = raw.strip()
    if raw and raw[0] in "\"'":
        end = raw.find(raw[0], 1)
        value = raw[1:end] if end > 0 else raw[1:]
    else:
        value = re.split(r"\s+#", raw, 1)[0].strip()
    m = re.fullmatch(r"\$\{[A-Za-z_][A-Za-z0-9_]*(?::?-(.*))?\}", value)
    if m:
        return m.group(1)          # ${VAR:-default} -> default; ${VAR} -> unknown
    if re.match(r"\$[A-Za-z_({]|`", value):
        return None                # $VAR or $(command): set somewhere else
    return value


ENV_ITEM = re.compile(r"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$")
MAP_ITEM = re.compile(r"^\s+([A-Z][A-Z0-9_]*)\s*:\s*(.*)$")
K8S_NAME = re.compile(r"^\s*(?:-\s*)?name:\s*[\"']?([A-Z][A-Z0-9_]*)[\"']?\s*$")
K8S_VALUE = re.compile(r"^\s*value:\s*(.*)$")
K8S_VALUE_FROM = re.compile(r"^\s*valueFrom:")
PORT_ITEM = re.compile(
    r"^\s*-\s*[\"']?(?:(\[[^\]]+\]|[\d.]+):)?(\d+|\$\{[A-Za-z_][A-Za-z0-9_]*:?-\d+\}):(\d+)(?:/\w+)?[\"']?\s*$")
RUN_ENV = re.compile(r"(?:^|\s)(?:-e|--env)(?:\s+|=)([\"']?)([A-Za-z_][A-Za-z0-9_]*)=(.*?)\1(?=\s|$)")
RUN_PORT = re.compile(r"(?:^|\s)(?:-p|--publish)(?:\s+|=)[\"']?(?:(\[[^\]]+\]|[\d.]+):)?(\d+):(\d+)")
IMAGE = re.compile(r"((?:ghcr\.io/)?open-?webui/open-webui(?::[A-Za-z0-9_.\-]+)?(?:@sha256:[0-9a-f]{64})?)")


def parse_text(text, name="input"):
    """Reads a .env file, docker-compose.yml, `docker inspect` JSON, a `docker run`
    command or a Kubernetes manifest."""
    dep = Deployment()
    dep.sources.append(name)
    stripped = text.lstrip()
    if stripped[:1] in "[{":
        try:
            _parse_inspect(json.loads(stripped), dep)
            return dep
        except ValueError:
            pass
    pending = None
    for line in text.splitlines():
        if line.lstrip().startswith("#"):
            continue
        item = line.strip()
        if item.startswith("- "):
            item = _unquote(item[2:])
        m = ENV_ITEM.match(item)
        if m:
            dep.env[m.group(1)] = _clean_value(m.group(2)) if m.group(2).strip() else ""
            continue
        m = K8S_NAME.match(line)
        if m:
            pending = m.group(1)
            continue
        if pending:
            m = K8S_VALUE.match(line)
            if m:
                dep.env[pending] = _clean_value(m.group(1))
                pending = None
                continue
            if K8S_VALUE_FROM.match(line):
                dep.env[pending] = None
                pending = None
                continue
        m = MAP_ITEM.match(line)
        if m:
            value = m.group(2).strip()
            dep.env[m.group(1)] = _clean_value(value) if value else None
            continue
        m = PORT_ITEM.match(line)
        if m:
            host_port = re.search(r"\d+", m.group(2).split("-")[-1]).group(0)  # ${PORT-3000} -> 3000
            dep.ports.append((m.group(1) or "", host_port, m.group(3)))
    for m in RUN_ENV.finditer(text):
        dep.env[m.group(2)] = _clean_value(m.group(3))
    for m in RUN_PORT.finditer(text):
        dep.ports.append((m.group(1) or "", m.group(2), m.group(3)))
    for m in IMAGE.finditer(text):
        if m.group(1) not in dep.images:
            dep.images.append(m.group(1))
    return dep


def _parse_inspect(data, dep):
    for c in data if isinstance(data, list) else [data]:
        if not isinstance(c, dict):
            continue
        config = c.get("Config") or {}
        for item in config.get("Env") or []:
            key, sep, value = item.partition("=")
            if sep:
                dep.env[key] = value
        image = config.get("Image")
        if image and "webui" in image and image not in dep.images:
            dep.images.append(image)
        bindings = (c.get("HostConfig") or {}).get("PortBindings") or {}
        for container_port, hosts in bindings.items():
            for h in hosts or []:
                dep.ports.append((h.get("HostIp") or "", str(h.get("HostPort") or ""),
                                  container_port.split("/")[0]))


def merge(deps):
    out = Deployment()
    for d in deps:
        out.env.update(d.env)
        out.images += [i for i in d.images if i not in out.images]
        out.ports += d.ports
        out.sources += d.sources
    return out


# ---------------------------------------------------------------- checks

def _flag(env, name, default):
    """True/False as Open WebUI reads it (only "true" in any case is true), the
    default when unset, None when the value can't be seen."""
    if name not in env:
        return default
    if env[name] is None:
        return None
    return env[name].strip().lower() == "true"


def _value(env, *names, default=""):
    for name in names:
        if name in env:
            return env[name]
    return default


def parse_duration(text):
    """Seconds for an Open WebUI duration such as 4w, 24h or 1h30m; -1 means never; None if unreadable."""
    text = (text or "").strip()
    if text == "-1":
        return -1
    parts = re.findall(r"(\d+(?:\.\d+)?)(ms|s|m|h|d|w)", text)
    if not parts or "".join(a + b for a, b in parts) != text:
        return None
    unit = {"ms": 0.001, "s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
    return sum(float(a) * unit[b] for a, b in parts)


def check_env(env, version=None, inside=False):
    """Findings for Open WebUI environment settings, following the official Hardening guide."""
    out = []
    in_vulnerable_sharing = version is not None and (0, 7, 0) <= version < (0, 11, 4)

    if _flag(env, "WEBUI_AUTH", True) is False:
        out.append(finding(
            "critical", "Sign-in is switched off (WEBUI_AUTH=False)",
            "Remove WEBUI_AUTH=False. Without sign-in, everyone who can reach Open WebUI is the admin: all chats, files, connected API keys and Functions, which run Python on the server.",
            setting="WEBUI_AUTH"))

    role = (_value(env, "DEFAULT_USER_ROLE", default="pending") or "").strip().lower()
    signup = _flag(env, "ENABLE_SIGNUP", None)
    if role == "admin":
        out.append(finding(
            "critical", "New accounts become admins (DEFAULT_USER_ROLE=admin)",
            "Set DEFAULT_USER_ROLE=pending so an admin approves each new account.",
            setting="DEFAULT_USER_ROLE"))
    elif role == "user":
        out.append(finding(
            "high" if signup else "medium", "New accounts get access without approval (DEFAULT_USER_ROLE=user)",
            "Set DEFAULT_USER_ROLE=pending, the default, so an admin approves each new account.",
            detail="With sign-up on, anyone who can reach the page can use your models, tools and connected API keys." if signup else "",
            setting="DEFAULT_USER_ROLE"))
    if signup:
        out.append(finding(
            "medium", "Sign-up is switched on (ENABLE_SIGNUP=True)",
            "Set ENABLE_SIGNUP=False after creating the accounts you need, or keep new accounts pending approval.",
            detail="Open WebUI switches sign-up off after the first admin account unless it is set explicitly.",
            setting="ENABLE_SIGNUP"))

    secret = _value(env, "WEBUI_SECRET_KEY", "WEBUI_JWT_SECRET_KEY", default=None)
    secret_file = _value(env, "WEBUI_SECRET_KEY_FILE", default=None)
    unseen = any(env.get(n, "") is None for n in ("WEBUI_SECRET_KEY", "WEBUI_JWT_SECRET_KEY", "WEBUI_SECRET_KEY_FILE"))
    if secret is not None and secret.strip().lower() in WEAK_SECRETS:
        out.append(finding(
            "critical", "WEBUI_SECRET_KEY is a well-known example value",
            "Generate a new one with `openssl rand -base64 32` and restart. Everyone will have to sign in again. Anyone who knows the key can forge a session token for any account.",
            setting="WEBUI_SECRET_KEY"))
    elif secret is not None and 0 < len(secret.strip()) < 32:
        out.append(finding(
            "low", "WEBUI_SECRET_KEY is shorter than the guide suggests (%d characters)" % len(secret.strip()),
            "The guide suggests a random 32-byte value, e.g. `openssl rand -base64 32`. It signs every session token.",
            setting="WEBUI_SECRET_KEY"))
    elif not inside and not unseen and not (secret or "").strip() and not (secret_file or "").strip():
        out.append(finding(
            "low", "WEBUI_SECRET_KEY isn't set",
            "Set it explicitly (`openssl rand -base64 32`) or point WEBUI_SECRET_KEY_FILE into the data directory. The generated key lives outside the data volume, so recreating the container signs everyone out and replicas reject each other's tokens.",
            setting="WEBUI_SECRET_KEY"))

    jwt = env.get("JWT_EXPIRES_IN", "")
    if jwt is not None:
        jwt = jwt.strip()
        seconds = parse_duration(jwt) if jwt else None
        if seconds == -1:
            out.append(finding(
                "high", "Session tokens never expire (JWT_EXPIRES_IN=-1)",
                "Set JWT_EXPIRES_IN=24h or shorter. A stolen token stays valid forever, and without Redis signing out doesn't revoke it.",
                setting="JWT_EXPIRES_IN"))
        elif jwt and seconds is None:
            out.append(finding(
                "low", "JWT_EXPIRES_IN may not be read as you expect (%r)" % jwt,
                "Use a number with a unit, such as 24h or 8h. Open WebUI reads durations like 30m, 24h, 7d or 4w.",
                setting="JWT_EXPIRES_IN"))
        elif not jwt or seconds > 7 * 86400:
            out.append(finding(
                "low", "Session tokens last %s" % (jwt or "4 weeks (the default)"),
                "The guide suggests JWT_EXPIRES_IN=8h to 24h (1h to 4h without Redis), so a stolen token stops working sooner.",
                setting="JWT_EXPIRES_IN"))

    if _flag(env, "ENABLE_COMMUNITY_SHARING", True):
        out.append(finding(
            "high" if in_vulnerable_sharing else "medium",
            "Chat share links are on (ENABLE_COMMUNITY_SHARING)",
            "Set ENABLE_COMMUNITY_SHARING=False if conversations are sensitive: any signed-in user with a share link can read the chat.",
            detail="On this version it also enables GHSA-vpq8-f445-hcq7: any website a signed-in user visits can steal their session token. Update to 0.11.4 or newer." if in_vulnerable_sharing else "",
            setting="ENABLE_COMMUNITY_SHARING"))

    cors = _value(env, "CORS_ALLOW_ORIGIN", default="*")
    if cors is not None and cors.strip() in ("*", ""):
        out.append(finding(
            "medium", "CORS allows every origin (CORS_ALLOW_ORIGIN=*, the default)",
            "Set CORS_ALLOW_ORIGIN to your exact address, e.g. https://chat.example.com (separate several with ;).",
            setting="CORS_ALLOW_ORIGIN"))

    if _flag(env, "WEBUI_SESSION_COOKIE_SECURE", False) is False:
        out.append(finding(
            "medium", "Session cookies can travel over plain HTTP (WEBUI_SESSION_COOKIE_SECURE is not true)",
            "Serve Open WebUI over HTTPS and set WEBUI_SESSION_COOKIE_SECURE=true.",
            setting="WEBUI_SESSION_COOKIE_SECURE"))
    same_site = (_value(env, "WEBUI_SESSION_COOKIE_SAME_SITE", default="lax") or "").strip().lower()
    if same_site == "none":
        out.append(finding(
            "medium", "Session cookies are sent on cross-site requests (SameSite=none)",
            "Set WEBUI_SESSION_COOKIE_SAME_SITE=strict, or lax at least.",
            setting="WEBUI_SESSION_COOKIE_SAME_SITE"))
    elif same_site == "lax" and "WEBUI_SESSION_COOKIE_SAME_SITE" not in env:
        out.append(finding(
            "low", "Session cookies use SameSite=lax (the default)",
            "Set WEBUI_SESSION_COOKIE_SAME_SITE=strict for the most protection against cross-site requests.",
            setting="WEBUI_SESSION_COOKIE_SAME_SITE"))

    forwarded = _value(env, "FORWARDED_ALLOW_IPS", default="*")
    if forwarded is not None and forwarded.strip() in ("*", ""):
        out.append(finding(
            "medium", "Any client can claim any IP address (FORWARDED_ALLOW_IPS=*, the default)",
            "Behind a reverse proxy, set FORWARDED_ALLOW_IPS to the proxy's address. Otherwise sign-in rate limits and audit-log addresses can be faked.",
            setting="FORWARDED_ALLOW_IPS"))

    if _flag(env, "ENABLE_OPENAI_API_PASSTHROUGH", False):
        out.append(finding(
            "high", "OpenAI passthrough is on (ENABLE_OPENAI_API_PASSTHROUGH=True)",
            "Set it to False. It lets any signed-in user reach any upstream endpoint with the admin's API key, past model access control.",
            setting="ENABLE_OPENAI_API_PASSTHROUGH"))

    if _flag(env, "OAUTH_MERGE_ACCOUNTS_BY_EMAIL", False):
        out.append(finding(
            "high", "OAuth accounts are merged by email (OAUTH_MERGE_ACCOUNTS_BY_EMAIL=True)",
            "Set it to False unless every provider verifies email addresses; otherwise an account can be taken over.",
            setting="OAUTH_MERGE_ACCOUNTS_BY_EMAIL"))

    oauth = any((env.get(n) or "").strip() for n in (
        "OAUTH_CLIENT_ID", "GOOGLE_CLIENT_ID", "MICROSOFT_CLIENT_ID", "GITHUB_CLIENT_ID", "OPENID_PROVIDER_URL"))
    if oauth and _flag(env, "ENABLE_OAUTH_SIGNUP", False) and not (env.get("OAUTH_ALLOWED_DOMAINS") or "").strip():
        out.append(finding(
            "high" if role in ("user", "admin") else "medium",
            "Anyone with an account at your OAuth provider can sign up",
            "Set OAUTH_ALLOWED_DOMAINS to your email domain(s).",
            setting="OAUTH_ALLOWED_DOMAINS"))

    if (env.get("WEBUI_AUTH_TRUSTED_EMAIL_HEADER") or "").strip():
        out.append(finding(
            "medium", "Trusted-header sign-in is on (WEBUI_AUTH_TRUSTED_EMAIL_HEADER)",
            "Make sure the reverse proxy removes this header from client requests and that Open WebUI can only be reached through that proxy. Otherwise anyone can send the header and sign in as any user; the guide calls this the most common misconfiguration.",
            setting="WEBUI_AUTH_TRUSTED_EMAIL_HEADER"))

    if _flag(env, "ENABLE_LDAP", False):
        if _flag(env, "LDAP_USE_TLS", False) is False:
            out.append(finding(
                "high", "LDAP passwords travel without TLS (LDAP_USE_TLS is not true)",
                "Set LDAP_USE_TLS=true and LDAP_VALIDATE_CERT=true, with LDAP_CA_CERT_FILE if your CA is private.",
                setting="LDAP_USE_TLS"))
        elif _flag(env, "LDAP_VALIDATE_CERT", True) is False:
            out.append(finding(
                "medium", "LDAP certificates aren't checked (LDAP_VALIDATE_CERT=false)",
                "Set LDAP_VALIDATE_CERT=true, with LDAP_CA_CERT_FILE if your CA is private.",
                setting="LDAP_VALIDATE_CERT"))

    for name in ("REQUESTS_VERIFY", "AIOHTTP_CLIENT_SESSION_SSL", "AIOHTTP_CLIENT_SESSION_TOOL_SERVER_SSL",
                 "ENABLE_WEB_LOADER_SSL_VERIFICATION"):
        if name in env and env[name] is not None and env[name].strip().lower() == "false":
            out.append(finding(
                "high", "TLS certificate checks are off (%s=false)" % name,
                "Remove it or set it to true. If you use a private CA, give its bundle instead of turning checks off.",
                setting=name))

    if _flag(env, "ENABLE_RAG_LOCAL_WEB_FETCH", False):
        out.append(finding(
            "medium", "Web fetches may reach private addresses (ENABLE_RAG_LOCAL_WEB_FETCH=True)",
            "Set it to False unless you need it. Users can make the server fetch internal addresses (SSRF).",
            setting="ENABLE_RAG_LOCAL_WEB_FETCH"))

    if _flag(env, "ENABLE_DIRECT_CONNECTIONS", False):
        out.append(finding(
            "medium", "Direct connections are on (ENABLE_DIRECT_CONNECTIONS=True)",
            "Set it to False unless users need their own API endpoints; their API keys get sent to the server.",
            setting="ENABLE_DIRECT_CONNECTIONS"))

    api_keys = _flag(env, "ENABLE_API_KEYS", None)
    if api_keys is None:
        api_keys = _flag(env, "ENABLE_API_KEY", False)
    restricted = _flag(env, "ENABLE_API_KEYS_ENDPOINT_RESTRICTIONS", None)
    if restricted is None:
        restricted = _flag(env, "ENABLE_API_KEY_ENDPOINT_RESTRICTIONS", False)
    if api_keys and restricted is False:
        out.append(finding(
            "medium", "API keys work on every endpoint",
            "Set ENABLE_API_KEYS_ENDPOINT_RESTRICTIONS=true and API_KEYS_ALLOWED_ENDPOINTS=/api/chat/completions,/api/v1/models (or what you need). A key carries all its creator's permissions.",
            setting="ENABLE_API_KEYS"))

    for enable, engine in (("ENABLE_CODE_EXECUTION", "CODE_EXECUTION_ENGINE"),
                           ("ENABLE_CODE_INTERPRETER", "CODE_INTERPRETER_ENGINE")):
        if _flag(env, enable, True) and (env.get(engine) or "").strip().lower() == "jupyter":
            out.append(finding(
                "medium", "Code runs through Jupyter (%s=jupyter)" % engine,
                "A Jupyter engine gives chat-generated code direct access to that server. Switch %s off if not needed, or isolate the Jupyter server." % enable,
                setting=engine))

    if _flag(env, "ENABLE_PIP_INSTALL_FRONTMATTER_REQUIREMENTS", True):
        out.append(finding(
            "low", "Tools can install Python packages at runtime",
            "Set ENABLE_PIP_INSTALL_FRONTMATTER_REQUIREMENTS=false and install what your Tools need in the image instead.",
            setting="ENABLE_PIP_INSTALL_FRONTMATTER_REQUIREMENTS"))

    if _flag(env, "ENABLE_ADMIN_EXPORT", True):
        out.append(finding(
            "low", "Admins can bulk-export every user's chats (ENABLE_ADMIN_EXPORT, the default)",
            "Set ENABLE_ADMIN_EXPORT=False if you don't need it.",
            setting="ENABLE_ADMIN_EXPORT"))

    if _flag(env, "ENABLE_PASSWORD_VALIDATION", False) is False:
        out.append(finding(
            "low", "Password strength isn't enforced",
            "Set ENABLE_PASSWORD_VALIDATION=true (and PASSWORD_VALIDATION_REGEX_PATTERN with a hint if you want your own rule).",
            setting="ENABLE_PASSWORD_VALIDATION"))

    if _flag(env, "ENABLE_MFA", False) is False:
        out.append(finding(
            "low", "Two-factor sign-in is off",
            "Set ENABLE_MFA=true, or enforce a second factor at your identity provider.",
            setting="ENABLE_MFA"))

    audit = _value(env, "AUDIT_LOG_LEVEL", default="NONE")
    if audit is not None and audit.strip().upper() in ("NONE", ""):
        out.append(finding(
            "low", "No audit log (AUDIT_LOG_LEVEL=NONE, the default)",
            "Set AUDIT_LOG_LEVEL=METADATA and ENABLE_AUDIT_LOGS_FILE=true, so you can see who did what after an incident.",
            setting="AUDIT_LOG_LEVEL"))

    if (env.get("ENV") or "").strip().lower() == "dev":
        out.append(finding(
            "medium", "Running with ENV=dev",
            "Use ENV=prod (the default). Dev mode exposes the API docs at /docs.",
            setting="ENV"))
    return out


def _tag(image):
    return image.split("@")[0].split("/")[-1].partition(":")[2]


def check_deployment(dep):
    out = []
    for image in dep.images:
        if "@sha256:" in image:
            continue
        if not parse_version(_tag(image)):
            out.append(finding(
                "low", "The image tag moves (%s)" % image,
                "Pin a release tag such as ghcr.io/open-webui/open-webui:v%s or newer, and update on purpose after reading the release notes." % SAFE_VERSION,
                source=GUIDE))
    for host_ip, host_port, container_port in dep.ports:
        if container_port == "8080" and host_ip in ("", "0.0.0.0", "[::]", "::"):
            out.append(finding(
                "critical" if _flag(dep.env, "WEBUI_AUTH", True) is False else "medium",
                "Open WebUI's port 8080 is published on every network interface (host port %s)" % host_port,
                "If only this machine or a reverse proxy on it should connect, publish it as 127.0.0.1:%s:8080. On Linux, Docker-published ports skip ufw and firewalld rules." % host_port,
                setting="ports"))
    return out


def image_version(dep):
    for image in dep.images:
        tag = _tag(image)
        v = parse_version(tag)
        if v:
            return v, tag
    return None, None


def check_version(version, label=""):
    if version is None:
        return [finding(
            "info", "Open WebUI version unknown",
            "Run the check with --url, pin a release tag in your image, or look under Settings > About.",
            source=ADVISORY_PAGE)]
    hits = []
    for first, fixed, ids, summary, source in ADVISORIES:
        if (first is None or version >= parse_version(first)) and version < parse_version(fixed):
            hits.append("%s (fixed in %s): %s %s" % (ids, fixed, summary, source))
    if not hits:
        return []
    return [finding(
        "high", "Open WebUI %s has %d known advisor%s" % (label or ".".join(map(str, version)), len(hits), "y" if len(hits) == 1 else "ies"),
        "Update to %s or newer; the latest release is safest. Then use Sign out all devices so stolen tokens stop working." % SAFE_VERSION,
        detail="\n".join(hits), source=ADVISORY_PAGE)]


# ---------------------------------------------------------------- live check of your own server

def _fetch(url, headers=None, timeout=10):
    h = {"User-Agent": "openwebui-hardening-check/" + __version__}
    h.update(headers or {})
    req = urllib.request.Request(url, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read(1000000)
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read(1000000)


def _host_kind(host):
    if host in ("localhost", "localhost.localdomain"):
        return "loopback"
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return "name"
    if ip.is_loopback:
        return "loopback"
    return "private" if ip.is_private else "public"


def check_url(url, fetch=_fetch):
    """Reads what any visitor of your server can see: /api/config (the data the
    sign-in page loads) and the response headers of the start page."""
    base = url.rstrip("/")
    parts = urlsplit(base)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("--url needs to start with http:// or https://")
    out = []
    try:
        status, headers, body = fetch(base + "/api/config", {"Origin": PROBE_ORIGIN})
    except (urllib.error.URLError, OSError) as e:
        return [finding("info", "Couldn't reach %s" % base, "Check the address, or run the check from a machine that can reach it.",
                        detail=str(getattr(e, "reason", e)), source=REPO)], None
    try:
        cfg = json.loads(body.decode("utf-8", "replace")) if status == 200 else None
    except ValueError:
        cfg = None
    if not isinstance(cfg, dict) or "features" not in cfg:
        return [finding("info", "%s/api/config didn't answer like Open WebUI (HTTP %s)" % (base, status),
                        "Give the address you open Open WebUI at in your browser.", source=REPO)], None

    features = cfg.get("features") or {}
    version = parse_version(cfg.get("version"))
    if cfg.get("onboarding"):
        out.append(finding(
            "critical", "No account exists yet: the next visitor becomes admin",
            "Open the page now and create the admin account, or take the server off the network until you do.",
            setting="onboarding"))
    if features.get("auth") is False:
        out.append(finding(
            "critical", "Sign-in is switched off: every visitor is admin",
            "Remove WEBUI_AUTH=False and restart.", setting="WEBUI_AUTH"))
    if features.get("enable_signup"):
        out.append(finding(
            "medium", "Anyone who can open the page can create an account",
            "Set ENABLE_SIGNUP=False under Admin Panel > Settings > General once your accounts exist, and keep DEFAULT_USER_ROLE=pending.",
            setting="ENABLE_SIGNUP"))
    if features.get("auth_trusted_header"):
        out.append(finding(
            "medium", "Trusted-header sign-in is on",
            "Make sure the reverse proxy strips that header from client requests and Open WebUI can't be reached any other way.",
            setting="WEBUI_AUTH_TRUSTED_EMAIL_HEADER"))
    acao = headers.get("access-control-allow-origin", "")
    if acao in ("*", PROBE_ORIGIN):
        out.append(finding(
            "medium", "The server accepts cross-origin requests from any website",
            "Set CORS_ALLOW_ORIGIN to your exact address, e.g. %s://%s." % (parts.scheme, parts.netloc),
            detail="A request with Origin: %s was answered with Access-Control-Allow-Origin: %s." % (PROBE_ORIGIN, acao),
            setting="CORS_ALLOW_ORIGIN"))

    kind = _host_kind(parts.hostname)
    if parts.scheme == "http" and kind != "loopback":
        out.append(finding(
            {"private": "low", "name": "medium", "public": "high"}[kind],
            "Passwords and session tokens cross the network unencrypted (http://)",
            "Put an HTTPS reverse proxy (Caddy, nginx) in front, set WEBUI_SESSION_COOKIE_SECURE=true, and stop publishing the plain HTTP port.",
            setting="https"))
    try:
        _, page_headers, _ = fetch(base + "/", None)
    except (urllib.error.URLError, OSError):
        page_headers = {}
    missing = []
    if parts.scheme == "https" and "strict-transport-security" not in page_headers:
        missing.append("Strict-Transport-Security (HSTS=max-age=31536000;includeSubDomains)")
    csp = page_headers.get("content-security-policy", "")
    if "x-frame-options" not in page_headers and "frame-ancestors" not in csp:
        missing.append("X-Frame-Options (XFRAME_OPTIONS=DENY)")
    if "x-content-type-options" not in page_headers:
        missing.append("X-Content-Type-Options (XCONTENT_TYPE=nosniff)")
    if "referrer-policy" not in page_headers:
        missing.append("Referrer-Policy (REFERRER_POLICY=strict-origin-when-cross-origin)")
    if page_headers and missing:
        out.append(finding(
            "low", "Security headers missing: %s" % ", ".join(m.split(" (")[0] for m in missing),
            "Set them with Open WebUI's environment variables or at your reverse proxy: %s." % "; ".join(missing),
            setting="headers"))
    return out, version


# ---------------------------------------------------------------- output

def counts(findings):
    c = {s: 0 for s in SEVERITIES}
    for f in findings:
        c[f["severity"]] += 1
    return c


def _sorted(findings):
    return sorted(findings, key=lambda f: RANK[f["severity"]])


FOOTER = ("Checks follow the official Open WebUI Hardening guide (%s) and advisories checked on %s. "
          "General technical information, not a security certification. "
          "Made with AI agents for MV2 of Munim, Inc.: %s" % (GUIDE, DATA_DATE, REPO))
REVIEW = "Want a written review of a shared Open WebUI server? See %s#written-review" % REPO


def render_text(findings, sources, version_label):
    lines = ["Open WebUI hardening check %s" % __version__,
             "Checked: %s" % ", ".join(sources),
             "Open WebUI version: %s" % (version_label or "unknown"), ""]
    if not findings:
        lines.append("No findings.")
    for f in _sorted(findings):
        lines.append("%-8s  %s" % (f["severity"].upper(), f["title"]))
        for part in [f["detail"], "Fix: " + f["fix"]]:
            for para in (part.split("\n") if part else []):
                lines += textwrap.wrap(para, 96, initial_indent=" " * 10, subsequent_indent=" " * 10)
        lines.append("")
    c = counts(findings)
    lines.append("Summary: " + ", ".join("%d %s" % (c[s], s) for s in SEVERITIES))
    lines += [""] + textwrap.wrap(FOOTER, 100) + [REVIEW]
    return "\n".join(lines)


def render_markdown(findings, sources, version_label):
    c = counts(findings)
    lines = ["## Open WebUI hardening check",
             "Version: **%s** | Checked: %s | %s" % (
                 version_label or "unknown", ", ".join(sources),
                 ", ".join("%d %s" % (c[s], s) for s in SEVERITIES if c[s]) or "no findings"), ""]
    current = None
    for f in _sorted(findings):
        if f["severity"] != current:
            current = f["severity"]
            lines += ["### " + current.capitalize(), ""]
        text = "- **%s**" % f["title"]
        if f["detail"]:
            text += " " + f["detail"].replace("\n", "; ")
        text += " *Fix:* %s ([source](%s))" % (f["fix"], f["source"])
        lines.append(text)
    lines += ["", "_%s_" % FOOTER, "", REVIEW]
    return "\n".join(lines)


def _read(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.read()


def run(files=(), url=None, read=_read, fetch=_fetch):
    """Returns (findings, sources, version label)."""
    findings, sources = [], []
    version, label = None, None
    if url:
        url_findings, version = check_url(url, fetch)
        findings += url_findings
        sources.append(url)
        if version:
            label = "%s (from %s)" % (".".join(map(str, version)), url.rstrip("/"))
    if files:
        dep = merge([parse_text(read(p), os.path.basename(p)) for p in files])
        sources += dep.sources
        if version is None:
            version, tag = image_version(dep)
            if version:
                label = "%s (from the image tag)" % tag
        findings += check_env(dep.env, version) + check_deployment(dep)
    findings += check_version(version, label.split(" ")[0] if label else "")
    return findings, sources, label


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="owui_hardening_check.py",
        description="Check an Open WebUI deployment against the official Hardening guide and known advisories. "
                    "Read-only; secret values are never printed.")
    p.add_argument("files", nargs="*", help=".env, docker-compose.yml, `docker inspect` JSON, a file with your "
                                            "`docker run` command, or a Kubernetes manifest")
    p.add_argument("--url", help="the address of an Open WebUI server you run, e.g. https://chat.example.com")
    p.add_argument("--json", action="store_true", help="print JSON")
    p.add_argument("--markdown", action="store_true", help="print Markdown")
    p.add_argument("--fail-on", choices=SEVERITIES[:4] + ["never"], default="high",
                   help="exit with 1 when a finding is this severe or worse (default: high)")
    p.add_argument("--version", action="version", version=__version__)
    args = p.parse_args(argv)
    if not args.files and not args.url:
        p.error("give at least one file or --url")
    try:
        findings, sources, label = run(args.files, args.url)
    except (OSError, ValueError) as e:
        print("error: %s" % e, file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps({"tool": "openwebui-hardening-check", "version": __version__, "data_date": DATA_DATE,
                          "checked": sources, "openwebui_version": label, "counts": counts(findings),
                          "findings": _sorted(findings)}, indent=2))
    elif args.markdown:
        print(render_markdown(findings, sources, label))
    else:
        print(render_text(findings, sources, label))
    if args.fail_on != "never" and any(RANK[f["severity"]] <= RANK[args.fail_on] for f in findings):
        return 1
    return 0


# ---------------------------------------------------------------- Open WebUI Function

def _running_version():
    try:
        from open_webui.env import VERSION
        return VERSION
    except Exception:
        return None


class Pipe:
    """Admins chat with "Hardening check" to check this server's own environment."""

    def __init__(self):
        self.name = "Hardening check"

    async def pipe(self, body: dict, __user__: dict = None) -> str:
        if not __user__ or __user__.get("role") != "admin":
            return "Only an admin can run the hardening check."
        raw = _running_version()
        version = parse_version(raw)
        findings = check_env(dict(os.environ), version, inside=True) + check_version(version, raw or "")
        return render_markdown(findings, ["this server's environment"], raw)


if __name__ == "__main__":
    sys.exit(main())
