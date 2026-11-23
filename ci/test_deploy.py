"""CI deploy contract tests; all HTTP requests use disposable local fake servers."""

from contextlib import contextmanager, redirect_stderr
import copy
import importlib.util
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPHandler, ProxyHandler, Request, build_opener


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("coolify_ci_deploy", ROOT / "ci/deploy.py")
ci = importlib.util.module_from_spec(spec)
import sys
sys.modules[spec.name] = ci
spec.loader.exec_module(ci)

DIGEST = "sha256:" + "a" * 64
TOKEN = "fake-ci-token-never-output"
ENV = {"COOLIFY_URL": "https://coolify.example", "COOLIFY_API_TOKEN": TOKEN,
       "COOLIFY_APP_UUID": "app1", "IMAGE_DIGEST": DIGEST,
       "EXPECTED_IMAGE": "ghcr.io/example/finance", "DEPLOY_TIMEOUT_SECONDS": "30"}
MANIFEST = {"image": ENV["EXPECTED_IMAGE"], "routes": [{"hosts": ["finance.example"], "prefix": "/"}],
            "probes": [{"url": "https://finance.example/finance/", "status": 200},
                       {"url": "https://finance.example/api/finance/state", "status": 404}]}


class Clock:
    def __init__(self):
        self.value = 0

    def now(self):
        return self.value

    def sleep(self, seconds):
        self.value += seconds


class Scenario:
    def __init__(self):
        self.requests = []
        self.application = {"uuid": "app1", "docker_registry_image_name": ENV["EXPECTED_IMAGE"],
                            "docker_registry_image_tag": "sha-old", "status": "running:healthy"}
        self.statuses = ["in_progress", "finished"]
        self.override = None

    def route(self, method, path, body):
        if self.override:
            result = self.override(method, path, body)
            if result is not None:
                return result
        if path == "/api/v1/applications/app1":
            if method == "PATCH":
                self.application.update(body)
            return 200, self.application
        if path == "/api/v1/deploy":
            return 200, {"deployments": [{"resource_uuid": "app1", "deployment_uuid": "job1"}]}
        if path == "/api/v1/deployments/job1":
            status = self.statuses.pop(0) if len(self.statuses) > 1 else self.statuses[0]
            return 200, {"status": status, "deployment_uuid": "job1"}
        if path == "/finance/":
            return 200, {"ok": True}
        if path == "/api/finance/state":
            return 404, {"error": "private"}
        return 404, {"error": "unknown"}


class Response:
    def __init__(self, response, url):
        self.response, self.url = response, url

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.response.close()

    @property
    def status(self):
        return self.response.status

    def read(self, *args):
        return self.response.read(*args)

    def geturl(self):
        return self.url


@contextmanager
def fake_http(scenario):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.handle_request()

        def do_PATCH(self):
            self.handle_request()

        def do_POST(self):
            self.handle_request()

        def handle_request(self):
            raw = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            data = json.loads(raw) if raw else None
            scenario.requests.append((self.command, self.path, data, dict(self.headers)))
            status, result = scenario.route(self.command, self.path, data)
            self.send_response(status)
            if 300 <= status < 400:
                self.send_header("Location", "/stolen")
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(result if isinstance(result, bytes) else json.dumps(result).encode())

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    opener = build_opener(ProxyHandler({}), ci.NoRedirect(), HTTPHandler())

    class MappedOpener:
        """Test-only transport: preserve production HTTPS requests over local fake HTTP."""
        def open(self, request, timeout):
            parsed = urlsplit(request.full_url)
            mapped = Request(f"http://127.0.0.1:{server.server_port}" + parsed.path,
                             method=request.get_method(), data=request.data, headers=dict(request.header_items()))
            try:
                return Response(opener.open(mapped, timeout=timeout), request.full_url)
            except HTTPError as error:
                error.url = request.full_url
                raise

    try:
        yield MappedOpener()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(3)


class ConfigTests(unittest.TestCase):
    def config(self, env=None, manifest=None):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "coolify.json"
            path.write_text(json.dumps(MANIFEST if manifest is None else manifest))
            return ci.read_config(ENV if env is None else env, path)

    def test_requires_all_inputs_and_accepts_only_exact_digest(self):
        for key in ENV:
            if key == "DEPLOY_TIMEOUT_SECONDS":
                continue
            env = dict(ENV)
            env.pop(key)
            with self.subTest(key=key), self.assertRaises(ci.DeployError):
                self.config(env)
        for value in ["latest", "sha-abcdef0", "sha256:" + "A" * 64, "sha256:" + "a" * 63]:
            with self.subTest(value=value), self.assertRaises(ci.DeployError):
                self.config({**ENV, "IMAGE_DIGEST": value})
        config = self.config()
        self.assertEqual(config.base, "https://coolify.example/api/v1")
        self.assertEqual(config.tag, "sha256-" + "a" * 64)
        self.assertNotIn(TOKEN, repr(config))
        self.assertEqual(config.probes[0][0], "https://finance.example/finance/")

    def test_rejects_insecure_or_credential_bearing_urls_and_bad_ids(self):
        for url in ["http://coolify.example", "https://user:pass@coolify.example", "https://coolify.example?token=x",
                    "https://coolify.example/#fragment", "https://coolify.example/api/v1/../../other", "https://coolify.example\n"]:
            with self.subTest(url=url), self.assertRaises(ci.DeployError):
                self.config({**ENV, "COOLIFY_URL": url})
        for identifier in ["../secrets", "app?token=x", "app\n1", ""]:
            with self.subTest(identifier=identifier), self.assertRaises(ci.DeployError):
                self.config({**ENV, "COOLIFY_APP_UUID": identifier})

    def test_rejects_unrelated_probes_and_image_mismatch(self):
        for change in [{"image": "ghcr.io/another/app"}, {"probes": [{"url": "https://unrelated.example/", "status": 200}]},
                       {"probes": [{"url": "https://finance.example/", "status": True}]},
                       {"probes": [{"url": "http://finance.example/", "status": 200}]},
                       {"probes": [{"url": "https://finance.example/", "status": 302}]}]:
            with self.subTest(change=change), self.assertRaises(ci.DeployError):
                self.config(manifest={**MANIFEST, **change})


class DeploymentTests(unittest.TestCase):
    config = ConfigTests.config

    def execute(self, scenario, config=None):
        config = config or self.config()
        clock = Clock()
        output = []
        with fake_http(scenario) as opener:
            result = ci.deploy(config, api=ci.API(config, opener), probe_opener=opener,
                               now=clock.now, sleep=clock.sleep, emit=output.append)
        return result, output

    def test_digest_pin_completed_healthy_and_private_probe(self):
        scenario = Scenario()
        result, output = self.execute(scenario)
        self.assertEqual(result["digest"], DIGEST)
        mutations = [(m, p, b) for m, p, b, _ in scenario.requests if m != "GET"]
        self.assertEqual(mutations, [("PATCH", "/api/v1/applications/app1", {"docker_registry_image_tag": "sha256-" + "a" * 64}),
                                     ("POST", "/api/v1/deploy", {"uuid": "app1"})])
        probes = [headers for _, path, _, headers in scenario.requests if path in {"/finance/", "/api/finance/state"}]
        self.assertEqual(len(probes), 2)
        self.assertTrue(all("Authorization" not in headers and "Cookie" not in headers for headers in probes))
        api_headers = [h for _, p, _, h in scenario.requests if p.startswith("/api/v1/")]
        self.assertTrue(all(h["Authorization"] == "Bearer " + TOKEN for h in api_headers))
        self.assertNotIn(TOKEN, str(output))

    def test_wrong_image_refused_before_mutation(self):
        scenario = Scenario()
        scenario.application["docker_registry_image_name"] = "ghcr.io/wrong/application"
        with self.assertRaises(ci.DeployError):
            self.execute(scenario)
        self.assertTrue(all(m == "GET" for m, _, _, _ in scenario.requests))

    def test_failed_cancelled_and_unknown_status_are_not_success(self):
        for status in ["failed", "cancelled", "cancelled-by-user", "unknown", [], None]:
            scenario = Scenario()
            scenario.statuses = [status]
            with self.subTest(status=status), self.assertRaises(ci.DeployError):
                self.execute(scenario)
            self.assertFalse(any(path == "/finance/" for _, path, _, _ in scenario.requests))

    def test_unhealthy_and_never_finished_are_bounded(self):
        for mode in ["unhealthy", "in_progress"]:
            scenario = Scenario()
            scenario.application["status"] = "running:unhealthy" if mode == "unhealthy" else "running:healthy"
            scenario.statuses = ["finished"] if mode == "unhealthy" else ["in_progress"]
            with self.subTest(mode=mode), self.assertRaisesRegex(ci.DeployError, "Истёк"):
                self.execute(scenario)
            self.assertLess(len(scenario.requests), 20)

    def test_deploy_response_for_different_resource_is_not_accepted(self):
        scenario = Scenario()
        scenario.override = lambda method, path, body: (200, {"deployments": [{"resource_uuid": "other", "deployment_uuid": "job1"}]}) if path == "/api/v1/deploy" else None
        with self.assertRaises(ci.DeployError):
            self.execute(scenario)
        self.assertEqual(sum(m == "POST" for m, _, _, _ in scenario.requests), 1)

    def test_lost_start_response_is_never_retried_or_leaked(self):
        scenario = Scenario()
        scenario.override = lambda method, path, body: (502, {"error": TOKEN}) if path == "/api/v1/deploy" else None
        with self.assertRaises(ci.DeployError) as caught:
            self.execute(scenario)
        self.assertNotIn(TOKEN, str(caught.exception))
        self.assertIn("Не повторяй автоматически", str(caught.exception))
        self.assertEqual(sum(m == "POST" for m, _, _, _ in scenario.requests), 1)

    def test_redirect_is_not_followed_and_token_is_not_forwarded(self):
        scenario = Scenario()
        scenario.override = lambda method, path, body: (307, {"error": TOKEN})
        with self.assertRaises(ci.DeployError) as caught:
            self.execute(scenario)
        self.assertNotIn(TOKEN, str(caught.exception))
        self.assertEqual(len(scenario.requests), 1)

    def test_wrong_http_probe_and_concurrent_version_change_fail(self):
        scenario = Scenario()
        scenario.override = lambda method, path, body: (503, {"error": TOKEN}) if path == "/finance/" else None
        with self.assertRaisesRegex(ci.DeployError, "Истёк"):
            self.execute(scenario)
        scenario = Scenario()
        def change_during_probe(method, path, body):
            if path == "/finance/":
                scenario.application["docker_registry_image_tag"] = "sha-another"
            return None
        scenario.override = change_during_probe
        with self.assertRaisesRegex(ci.DeployError, "версия"):
            self.execute(scenario)

    def test_health_can_return_to_starting_while_new_container_settles(self):
        scenario = Scenario()
        seen = {"probe": False, "reads": 0}
        def changing_health(method, path, body):
            if path == "/finance/" and not seen["probe"]:
                seen["probe"] = True
                scenario.application["status"] = "running:starting"
            elif path == "/api/v1/applications/app1" and seen["probe"]:
                seen["reads"] += 1
                if seen["reads"] >= 3:
                    scenario.application["status"] = "running:healthy"
            return None
        scenario.override = changing_health
        self.execute(scenario)
        self.assertGreaterEqual(seen["reads"], 3)
        self.assertEqual(sum(m == "POST" for m, _, _, _ in scenario.requests), 1)

    def test_oversized_or_invalid_json_responses_are_not_logged(self):
        for body in [(b"x" * (ci.MAX_RESPONSE + 1)), (TOKEN + "not-json").encode()]:
            scenario = Scenario()
            scenario.override = lambda method, path, payload, value=body: (200, value)
            with self.subTest(size=len(body)), self.assertRaises(ci.DeployError) as caught:
                self.execute(scenario)
            self.assertNotIn(TOKEN, str(caught.exception))

    def test_secret_reflected_as_deployment_id_is_never_printed(self):
        scenario = Scenario()
        scenario.override = lambda method, path, body: (200, {"deployments": [{"resource_uuid": "app1", "deployment_uuid": TOKEN}]}) if path == "/api/v1/deploy" else None
        with self.assertRaises(ci.DeployError) as caught:
            self.execute(scenario)
        self.assertNotIn(TOKEN, str(caught.exception))

    def test_main_configuration_error_never_exposes_token(self):
        output = io.StringIO()
        with patch.dict(ci.os.environ, {**ENV, "COOLIFY_URL": "http://" + TOKEN}, clear=True), redirect_stderr(output):
            self.assertEqual(ci.main(["--manifest", "missing"]), 1)
        self.assertNotIn(TOKEN, output.getvalue())


if __name__ == "__main__":
    unittest.main()
