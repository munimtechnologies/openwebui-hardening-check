import asyncio
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
import urllib.error
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import owui_hardening_check as owc  # noqa: E402


def titles(findings):
    return [f["title"] for f in findings]


def by_severity(findings, severity):
    return [f for f in findings if f["severity"] == severity]


COMPOSE = """services:
  open-webui:
    image: ghcr.io/open-webui/open-webui:${WEBUI_DOCKER_TAG-main}
    ports:
      - ${OPEN_WEBUI_PORT-3000}:8080
    environment:
      - 'OLLAMA_BASE_URL=http://ollama:11434'
      - 'WEBUI_SECRET_KEY='
  staging:
    image: ghcr.io/open-webui/open-webui:v0.11.2
    ports:
      - "127.0.0.1:3001:8080"
    environment:
      ENABLE_SIGNUP: "true"
      DEFAULT_USER_ROLE: user   # temporary
"""

DOCKER_RUN = ('docker run -d -p 3000:8080 -e WEBUI_SECRET_KEY="t0p-s3cr3t" -e "JWT_EXPIRES_IN=-1" '
              '--env ENABLE_SIGNUP=true -v open-webui:/app/backend/data ghcr.io/open-webui/open-webui:v0.12.0\n')

K8S = """        env:
          - name: WEBUI_SECRET_KEY
            valueFrom:
              secretKeyRef:
                name: owui
                key: secret
          - name: ENABLE_COMMUNITY_SHARING
            value: "False"
          - name: CORS_ALLOW_ORIGIN
            value: https://chat.example.com
"""


class ParseTests(unittest.TestCase):
    def test_env_file(self):
        text = ("# comment\nexport WEBUI_AUTH=\"False\"\nJWT_EXPIRES_IN=24h  # one day\n"
                "CORS_ALLOW_ORIGIN='https://chat.example.com'\nOLLAMA_BASE_URL=${OLLAMA_URL}\nPORT_X=${P:-3000}\n"
                "WEBUI_SECRET_KEY=$(openssl rand -base64 32)\n")
        env = owc.parse_text(text, ".env").env
        self.assertEqual(env["WEBUI_AUTH"], "False")
        self.assertEqual(env["JWT_EXPIRES_IN"], "24h")
        self.assertEqual(env["CORS_ALLOW_ORIGIN"], "https://chat.example.com")
        self.assertIsNone(env["OLLAMA_BASE_URL"])
        self.assertEqual(env["PORT_X"], "3000")
        self.assertIsNone(env["WEBUI_SECRET_KEY"])

    def test_compose(self):
        dep = owc.parse_text(COMPOSE, "docker-compose.yml")
        self.assertEqual(dep.env["OLLAMA_BASE_URL"], "http://ollama:11434")
        self.assertEqual(dep.env["WEBUI_SECRET_KEY"], "")
        self.assertEqual(dep.env["ENABLE_SIGNUP"], "true")
        self.assertEqual(dep.env["DEFAULT_USER_ROLE"], "user")
        self.assertIn(("", "3000", "8080"), dep.ports)
        self.assertIn(("127.0.0.1", "3001", "8080"), dep.ports)
        self.assertEqual(dep.images, ["ghcr.io/open-webui/open-webui", "ghcr.io/open-webui/open-webui:v0.11.2"])
        self.assertEqual(owc.image_version(dep), ((0, 11, 2), "v0.11.2"))
        found = owc.check_deployment(dep)
        self.assertEqual(len(by_severity(found, "medium")), 1)       # only the port without 127.0.0.1
        self.assertTrue(any("tag moves" in t for t in titles(found)))

    def test_docker_inspect(self):
        data = [{"Config": {"Env": ["WEBUI_AUTH=False", "PATH=/usr/bin"], "Image": "ghcr.io/open-webui/open-webui:main"},
                 "HostConfig": {"PortBindings": {"8080/tcp": [{"HostIp": "", "HostPort": "3000"}]}}},
                {"Config": {"Env": [], "Image": "ollama/ollama:latest"}, "HostConfig": {}}]
        dep = owc.parse_text(json.dumps(data), "inspect.json")
        self.assertEqual(dep.env["WEBUI_AUTH"], "False")
        self.assertEqual(dep.images, ["ghcr.io/open-webui/open-webui:main"])
        self.assertEqual(dep.ports, [("", "3000", "8080")])
        self.assertEqual(len(by_severity(owc.check_deployment(dep), "critical")), 1)

    def test_docker_run(self):
        dep = owc.parse_text(DOCKER_RUN, "run.sh")
        self.assertEqual(dep.env["WEBUI_SECRET_KEY"], "t0p-s3cr3t")
        self.assertEqual(dep.env["JWT_EXPIRES_IN"], "-1")
        self.assertEqual(dep.env["ENABLE_SIGNUP"], "true")
        self.assertEqual(dep.ports, [("", "3000", "8080")])
        self.assertEqual(dep.images, ["ghcr.io/open-webui/open-webui:v0.12.0"])

    def test_kubernetes(self):
        env = owc.parse_text(K8S, "deployment.yaml").env
        self.assertIsNone(env["WEBUI_SECRET_KEY"])
        self.assertEqual(env["ENABLE_COMMUNITY_SHARING"], "False")
        self.assertEqual(env["CORS_ALLOW_ORIGIN"], "https://chat.example.com")
        found = titles(owc.check_env(env))
        self.assertFalse(any("WEBUI_SECRET_KEY" in t for t in found))
        self.assertFalse(any("share links" in t for t in found))
        self.assertFalse(any("CORS" in t for t in found))


class EnvCheckTests(unittest.TestCase):
    def test_defaults(self):
        found = owc.check_env({})
        self.assertEqual(by_severity(found, "critical") + by_severity(found, "high"), [])
        self.assertEqual(len(by_severity(found, "medium")), 4)
        self.assertTrue(any("4 weeks" in t for t in titles(found)))
        self.assertTrue(any("isn't set" in t for t in titles(found)))

    def test_auth_off_and_roles(self):
        self.assertEqual(by_severity(owc.check_env({"WEBUI_AUTH": "False"}), "critical")[0]["setting"], "WEBUI_AUTH")
        self.assertEqual(len(by_severity(owc.check_env({"DEFAULT_USER_ROLE": "admin"}), "critical")), 1)
        found = owc.check_env({"DEFAULT_USER_ROLE": "user", "ENABLE_SIGNUP": "True"})
        self.assertEqual(titles(by_severity(found, "high")), ["New accounts get access without approval (DEFAULT_USER_ROLE=user)"])
        self.assertIn("Admin Panel", by_severity(found, "high")[0]["fix"])

    def test_booleans_read_like_open_webui(self):
        self.assertEqual(by_severity(owc.check_env({"WEBUI_AUTH": "0"}), "critical")[0]["setting"], "WEBUI_AUTH")
        self.assertEqual(by_severity(owc.check_env({"WEBUI_AUTH": "true"}), "critical"), [])

    def test_secrets_never_printed(self):
        found = owc.check_env({"WEBUI_SECRET_KEY": "changeme"})
        self.assertEqual(len(by_severity(found, "critical")), 1)
        found += owc.check_env({"WEBUI_SECRET_KEY": "abcdefgh"})
        self.assertTrue(any("8 characters" in t for t in titles(found)))
        text = json.dumps(found)
        self.assertNotIn("changeme", text)
        self.assertNotIn("abcdefgh", text)

    def test_jwt(self):
        self.assertEqual(owc.parse_duration("4w"), 4 * 604800)
        self.assertEqual(owc.parse_duration("1h30m"), 5400)
        self.assertEqual(owc.parse_duration("-1"), -1)
        self.assertIsNone(owc.parse_duration("86400"))
        self.assertEqual(by_severity(owc.check_env({"JWT_EXPIRES_IN": "-1"}), "high")[0]["setting"], "JWT_EXPIRES_IN")
        self.assertFalse(any(f["setting"] == "JWT_EXPIRES_IN" for f in owc.check_env({"JWT_EXPIRES_IN": "24h"})))
        self.assertTrue(any("may not be read" in t for t in titles(owc.check_env({"JWT_EXPIRES_IN": "86400"}))))
        self.assertFalse(any(f["setting"] == "JWT_EXPIRES_IN" for f in owc.check_env({"JWT_EXPIRES_IN": None})))

    def test_community_sharing_depends_on_version(self):
        old = [f for f in owc.check_env({}, (0, 11, 2)) if f["setting"] == "ENABLE_COMMUNITY_SHARING"]
        new = [f for f in owc.check_env({}, (0, 12, 0)) if f["setting"] == "ENABLE_COMMUNITY_SHARING"]
        self.assertEqual(old[0]["severity"], "high")
        self.assertIn("GHSA-vpq8-f445-hcq7", old[0]["detail"])
        self.assertEqual(new[0]["severity"], "medium")

    def test_risky_switches(self):
        env = {"ENABLE_OPENAI_API_PASSTHROUGH": "true", "OAUTH_MERGE_ACCOUNTS_BY_EMAIL": "true",
               "REQUESTS_VERIFY": "false", "ENABLE_LDAP": "true", "GOOGLE_CLIENT_ID": "x",
               "ENABLE_OAUTH_SIGNUP": "true", "ENABLE_API_KEYS": "true", "CODE_INTERPRETER_ENGINE": "jupyter"}
        found = owc.check_env(env)
        settings = {f["setting"] for f in by_severity(found, "high")}
        self.assertEqual(settings, {"ENABLE_OPENAI_API_PASSTHROUGH", "OAUTH_MERGE_ACCOUNTS_BY_EMAIL",
                                    "REQUESTS_VERIFY", "LDAP_USE_TLS"})
        medium = {f["setting"] for f in by_severity(found, "medium")}
        self.assertTrue({"OAUTH_ALLOWED_DOMAINS", "ENABLE_API_KEYS", "CODE_INTERPRETER_ENGINE"} <= medium)


class VersionTests(unittest.TestCase):
    def test_versions(self):
        found = owc.check_version((0, 11, 2), "v0.11.2")
        self.assertEqual(found[0]["title"], "Open WebUI v0.11.2 has 2 known advisories")
        self.assertIn("GHSA-vpq8-f445-hcq7", found[0]["detail"])
        self.assertNotIn("CVE-2026-87016", found[0]["detail"])
        self.assertEqual(owc.check_version((0, 12, 0)), [])
        self.assertEqual(owc.check_version(None)[0]["severity"], "info")
        self.assertEqual(owc.check_version((0, 6, 0))[0]["title"], "Open WebUI 0.6.0 has 5 known advisories")
        self.assertEqual(owc.parse_version("v0.11.4-cuda"), (0, 11, 4))
        self.assertIsNone(owc.parse_version("main"))


def fake_fetch(cfg, headers=None, page_headers=None, status=200):
    def fetch(url, h):
        if url.endswith("/api/config"):
            body = cfg if isinstance(cfg, bytes) else json.dumps(cfg).encode()
            return status, headers or {}, body
        return 200, page_headers or {}, b"<html></html>"
    return fetch


class UrlTests(unittest.TestCase):
    def test_open_server(self):
        cfg = {"onboarding": True, "version": "0.11.2", "features": {"auth": True, "enable_signup": True}}
        found, version = owc.check_url("http://8.8.8.8:3000/", fake_fetch(
            cfg, {"access-control-allow-origin": "*"}, {"content-type": "text/html"}))
        self.assertEqual(version, (0, 11, 2))
        self.assertEqual(len(by_severity(found, "critical")), 1)
        self.assertEqual({f["setting"] for f in by_severity(found, "high")}, {"https"})
        self.assertEqual({f["setting"] for f in by_severity(found, "medium")}, {"ENABLE_SIGNUP", "CORS_ALLOW_ORIGIN"})
        self.assertEqual([f["setting"] for f in by_severity(found, "low")], ["headers"])

    def test_hardened_server(self):
        cfg = {"version": "0.12.0", "features": {"auth": True, "enable_signup": False}}
        page = {"strict-transport-security": "max-age=31536000", "content-security-policy": "frame-ancestors 'none'",
                "x-content-type-options": "nosniff", "referrer-policy": "strict-origin-when-cross-origin"}
        found, version = owc.check_url("https://chat.example.com", fake_fetch(
            cfg, {"access-control-allow-origin": "https://chat.example.com"}, page))
        self.assertEqual(found, [])
        self.assertEqual(version, (0, 12, 0))

    def test_auth_off_and_lan(self):
        cfg = {"version": "0.12.0", "features": {"auth": False}}
        found, _ = owc.check_url("http://192.168.1.20:3000", fake_fetch(cfg))
        self.assertEqual(by_severity(found, "critical")[0]["setting"], "WEBUI_AUTH")
        self.assertEqual([f for f in found if f["setting"] == "https"][0]["severity"], "low")

    def test_unreachable_and_not_open_webui(self):
        def down(url, h):
            raise urllib.error.URLError("refused")
        found, version = owc.check_url("http://localhost:3000", down)
        self.assertEqual((found[0]["severity"], version), ("info", None))
        found, version = owc.check_url("http://localhost:3000", fake_fetch(b"not json", status=404))
        self.assertIn("didn't answer like Open WebUI", found[0]["title"])
        with self.assertRaises(ValueError):
            owc.check_url("ftp://example.com")


class CliTests(unittest.TestCase):
    def run_main(self, argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = owc.main(argv)
        return rc, out.getvalue()

    def test_json_and_exit_codes(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "run.sh")
            with open(path, "w", encoding="utf-8") as f:
                f.write(DOCKER_RUN)
            rc, out = self.run_main(["--json", path])
            self.assertEqual(rc, 1)
            self.assertNotIn("t0p-s3cr3t", out)
            data = json.loads(out)
            self.assertEqual(data["counts"]["critical"], 1)    # the example secret key
            self.assertEqual(data["counts"]["high"], 1)        # JWT_EXPIRES_IN=-1
            self.assertEqual(data["openwebui_version"], "v0.12.0 (from the image tag)")
            rc, out = self.run_main([path, "--fail-on", "never"])
            self.assertEqual(rc, 0)
            self.assertIn("CRITICAL", out)
            self.assertIn("written-review", out)
            rc, out = self.run_main(["--markdown", "--fail-on", "never", path])
            self.assertIn("### Critical", out)
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stderr(io.StringIO()):
                owc.main([])

    def test_run_with_injected_reader(self):
        findings, sources, label = owc.run(["a.env"], read=lambda p: "WEBUI_AUTH=False\n")
        self.assertEqual(sources, ["a.env"])
        self.assertIsNone(label)
        self.assertTrue(by_severity(findings, "critical"))
        self.assertTrue(by_severity(findings, "info"))


class PipeTests(unittest.TestCase):
    def test_admin_only(self):
        reply = asyncio.run(owc.Pipe().pipe({}, __user__={"role": "user"}))
        self.assertEqual(reply, "Only an admin can run the hardening check.")

    def test_admin_report(self):
        with mock.patch.dict(os.environ, {"WEBUI_AUTH": "False", "WEBUI_SECRET_KEY": "changeme"}):
            reply = asyncio.run(owc.Pipe().pipe({}, __user__={"role": "admin"}))
        self.assertIn("Sign-in is switched off", reply)
        self.assertIn("### Critical", reply)
        self.assertNotIn("changeme", reply)


if __name__ == "__main__":
    unittest.main()
