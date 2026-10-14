import io
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import github_action  # noqa: E402
import owui_hardening_check as owc  # noqa: E402

DOCKER_RUN = ('docker run -d -p 3000:8080 -e WEBUI_SECRET_KEY="t0p-s3cr3t" -e "JWT_EXPIRES_IN=-1" '
              '--env ENABLE_SIGNUP=true -v open-webui:/app/backend/data ghcr.io/open-webui/open-webui:v0.12.0\n')


def cors(env):
    return [f for f in owc.check_env(env) if f["setting"] == "CORS_ALLOW_ORIGIN"]


class CorsTests(unittest.TestCase):
    def test_entries(self):
        self.assertEqual(owc.cors_problems("https://chat.example.com;http://localhost:3000"), ([], []))
        self.assertEqual(owc.cors_problems(""), (["an empty entry"], []))
        self.assertEqual(owc.cors_problems("https://chat.example.com;"), (["an empty entry"], []))
        self.assertEqual(owc.cors_problems("chat.example.com"), (["chat.example.com"], []))
        self.assertEqual(owc.cors_problems("*;https://chat.example.com"), (["*"], []))
        self.assertEqual(owc.cors_problems("https://chat.example.com/"), ([], ["https://chat.example.com/"]))
        self.assertEqual(owc.cors_problems("https://a.example.com; https://b.example.com"), ([], ["https://b.example.com"]))
        self.assertEqual(owc.cors_problems("https://a.example.com,https://b.example.com"),
                         ([], ["https://a.example.com,https://b.example.com"]))
        self.assertEqual(owc.cors_problems("app://desktop"), (["app://desktop"], []))
        self.assertEqual(owc.cors_problems("app://desktop", "app"), ([], []))

    def test_findings(self):
        default = cors({})
        self.assertEqual([f["severity"] for f in default], ["medium"])
        self.assertIn("NOT RECOMMENDED FOR PRODUCTION DEPLOYMENTS", default[0]["detail"])
        empty = cors({"CORS_ALLOW_ORIGIN": ""})
        self.assertEqual([f["severity"] for f in empty], ["medium"])
        self.assertIn("won't start", empty[0]["title"])
        self.assertIn("config.py", empty[0]["source"])
        slash = cors({"CORS_ALLOW_ORIGIN": "https://chat.example.com/"})
        self.assertEqual([f["severity"] for f in slash], ["low"])
        self.assertIn("no browser sends (https://chat.example.com/)", slash[0]["title"])
        both = cors({"CORS_ALLOW_ORIGIN": "chat.example.com;https://chat.example.com/"})
        self.assertEqual([f["severity"] for f in both], ["medium", "low"])
        self.assertEqual(cors({"CORS_ALLOW_ORIGIN": "https://chat.example.com"}), [])
        self.assertEqual(cors({"CORS_ALLOW_ORIGIN": None}), [])
        self.assertEqual(cors({"CORS_ALLOW_ORIGIN": "app://desktop", "CORS_ALLOW_CUSTOM_SCHEME": "app"}), [])


class ExpandTests(unittest.TestCase):
    def test_paths_and_wildcards(self):
        with tempfile.TemporaryDirectory() as d:
            os.mkdir(os.path.join(d, "k8s"))
            for name in ("docker-compose.yml", ".env", os.path.join("k8s", "b.yaml"), os.path.join("k8s", "a.yaml")):
                with open(os.path.join(d, name), "w", encoding="utf-8") as f:
                    f.write("ENV=prod\n")
            files, missing = github_action.expand("docker-compose.yml .env\nk8s/*.yaml missing.env nope/*.yml k8s", root=d)
            expected = [os.path.join(d, "docker-compose.yml"), os.path.join(d, ".env"),
                        os.path.join(d, "k8s", "a.yaml"), os.path.join(d, "k8s", "b.yaml")]
            self.assertEqual([os.path.normpath(p) for p in files], [os.path.normpath(p) for p in expected])
            self.assertEqual(missing, ["missing.env", "nope/*.yml", "k8s"])
        self.assertEqual(github_action.expand(""), ([], []))

    def test_escape(self):
        self.assertEqual(github_action._escape("50% done\r\nnext"), "50%25 done%0D%0Anext")


class MainTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = self.tmp.name
        self.run_sh = os.path.join(self.d, "run.sh")
        with open(self.run_sh, "w", encoding="utf-8") as f:
            f.write(DOCKER_RUN)
        self.summary = os.path.join(self.d, "summary.md")
        self.output = os.path.join(self.d, "output.txt")

    def tearDown(self):
        self.tmp.cleanup()

    def main(self, **extra):
        environ = {"CHECK_FILES": self.run_sh + " " + os.path.join(self.d, "missing.env"), "CHECK_URL": "",
                   "GITHUB_STEP_SUMMARY": self.summary, "GITHUB_OUTPUT": self.output, "RUNNER_TEMP": self.d}
        environ.update(extra)
        out = io.StringIO()
        rc = github_action.main(environ, out)
        return rc, out.getvalue()

    def read(self, path):
        with open(path, encoding="utf-8") as f:
            return f.read()

    def test_report_annotations_and_outputs(self):
        rc, out = self.main(CHECK_FAIL_ON="high")
        self.assertEqual(rc, 1)
        self.assertIn("::warning::%s not found, skipped" % os.path.join(self.d, "missing.env"), out)
        self.assertIn("::error::CRITICAL: WEBUI_SECRET_KEY is a well-known example value", out)
        self.assertIn("::warning::MEDIUM: CORS allows every origin", out)
        self.assertIn("Open WebUI hardening check %s" % owc.__version__, out)
        summary = self.read(self.summary)
        self.assertIn("## Open WebUI hardening check", summary)
        outputs = self.read(self.output).splitlines()
        self.assertIn("critical=1", outputs)
        self.assertIn("high=1", outputs)
        report = os.path.join(self.d, github_action.REPORT_NAME)
        self.assertIn("report=%s" % report, outputs)
        data = json.loads(self.read(report))
        self.assertEqual(data["counts"]["critical"], 1)
        self.assertEqual(data["openwebui_version"], "v0.12.0 (from the image tag)")
        for text in (out, summary, self.read(report)):
            self.assertNotIn("t0p-s3cr3t", text)

    def test_fail_on(self):
        self.assertEqual(self.main(CHECK_FAIL_ON="never")[0], 0)
        self.assertEqual(self.main(CHECK_FAIL_ON="critical")[0], 1)
        self.assertEqual(self.main(CHECK_FAIL_ON="")[0], 1)          # default: high
        rc, out = self.main(CHECK_FAIL_ON="severe")
        self.assertEqual(rc, 2)
        self.assertIn("::error::fail-on must be", out)

    def test_nothing_to_check(self):
        rc, out = self.main(CHECK_FILES=os.path.join(self.d, "nope.yml"))
        self.assertEqual(rc, 2)
        self.assertIn("::error::No files to check", out)


@unittest.skipUnless(os.path.exists(os.path.join(HERE, "action.yml")), "action.yml not next to the tests")
class ActionFileTests(unittest.TestCase):
    def test_action_yml(self):
        with open(os.path.join(HERE, "action.yml"), encoding="utf-8") as f:
            text = f.read()
        self.assertIn("using: composite", text)
        self.assertIn("$GITHUB_ACTION_PATH/github_action.py", text)
        for name in ("files", "url", "fail-on"):
            self.assertIn("\n  %s:\n" % name, text)
            self.assertIn("${{ inputs.%s }}" % name, text)
        for name in ("CHECK_FILES", "CHECK_URL", "CHECK_FAIL_ON"):
            self.assertIn(name + ":", text)
        description = [line for line in text.splitlines() if line.startswith("description:")][0]
        self.assertLess(len(description.split(":", 1)[1].strip()), 125)    # GitHub Marketplace limit


if __name__ == "__main__":
    unittest.main()
