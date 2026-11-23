#!/usr/bin/env python3
"""Deploy one pre-provisioned Coolify application to a specific GHCR digest."""

import argparse
from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import re
import ssl
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener


IDENTIFIER = re.compile(r"[A-Za-z0-9_-]{1,128}")
DIGEST = re.compile(r"sha256:[a-f0-9]{64}")
IMAGE = re.compile(r"[a-z0-9.-]+/[a-z0-9_./-]+")
MAX_RESPONSE = 2 * 1024 * 1024


class DeployError(Exception):
    """An error safe to expose to CI logs; response bodies are never included."""


def https_url(raw, name, *, api=False):
    if not isinstance(raw, str) or any(ord(char) < 33 for char in raw):
        raise DeployError(name + ": ожидается HTTPS URL")
    try:
        parsed = urlsplit(raw)
        port = parsed.port
    except ValueError:
        raise DeployError(name + ": некорректный URL") from None
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None or
            parsed.password is not None or parsed.query or parsed.fragment or port == 0):
        raise DeployError(name + ": ожидается HTTPS URL без credentials, query и fragment")
    if api and parsed.path.rstrip("/") not in {"", "/api/v1"}:
        raise DeployError(name + ": допустим адрес панели или /api/v1")
    return raw.rstrip("/") if api else raw


@dataclass(frozen=True)
class Config:
    base: str
    token: str = field(repr=False)
    application: str
    digest: str
    image: str
    probes: tuple
    timeout: int = 1200

    @property
    def tag(self):
        # This is the digest syntax supported by the pinned Coolify 4.7.6.
        return "sha256-" + self.digest[7:]


def read_config(environ, manifest_path):
    required = ("COOLIFY_URL", "COOLIFY_API_TOKEN", "COOLIFY_APP_UUID", "IMAGE_DIGEST", "EXPECTED_IMAGE")
    for name in required:
        if not environ.get(name):
            raise DeployError("Не задана переменная " + name)
    base = https_url(environ["COOLIFY_URL"], "COOLIFY_URL", api=True)
    if not base.endswith("/api/v1"):
        base += "/api/v1"
    token = environ["COOLIFY_API_TOKEN"]
    if len(token) > 8192 or any(ord(char) < 33 or ord(char) > 126 for char in token):
        raise DeployError("Некорректный COOLIFY_API_TOKEN")
    application, digest, image = (environ[name] for name in ("COOLIFY_APP_UUID", "IMAGE_DIGEST", "EXPECTED_IMAGE"))
    if not IDENTIFIER.fullmatch(application):
        raise DeployError("Некорректный COOLIFY_APP_UUID")
    if not DIGEST.fullmatch(digest):
        raise DeployError("IMAGE_DIGEST должен быть sha256 и 64 hex-символа")
    if not IMAGE.fullmatch(image):
        raise DeployError("EXPECTED_IMAGE должен быть registry/repository без тега")
    try:
        timeout = int(environ.get("DEPLOY_TIMEOUT_SECONDS", "1200"))
    except ValueError:
        raise DeployError("Некорректный DEPLOY_TIMEOUT_SECONDS") from None
    if not 30 <= timeout <= 1800:
        raise DeployError("DEPLOY_TIMEOUT_SECONDS должен быть от 30 до 1800")
    probes = []
    if manifest_path is not None:
        path = Path(manifest_path)
        if not path.is_file() or path.stat().st_size > 1024 * 1024:
            raise DeployError("Не найден или слишком большой coolify.json")
        try:
            manifest = json.loads(path.read_text())
            if manifest.get("image") != image:
                raise DeployError("EXPECTED_IMAGE не совпадает с coolify.json")
            hosts = {host for route in manifest.get("routes", []) for host in route.get("hosts", [])}
            items = manifest.get("probes", [])
            if not isinstance(items, list) or len(items) > 16:
                raise ValueError()
            for item in items:
                url = https_url(item["url"], "HTTPS probe")
                status = item["status"]
                if type(status) is not int or not (200 <= status <= 299 or 400 <= status <= 499) or urlsplit(url).hostname not in hosts:
                    raise ValueError()
                probes.append((url, status))
        except (OSError, ValueError, TypeError, KeyError, AttributeError):
            raise DeployError("Некорректный coolify.json или его HTTPS probes") from None
    return Config(base, token, application, digest, image, tuple(probes), timeout)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def secure_opener():
    return build_opener(ProxyHandler({}), NoRedirect(), HTTPSHandler(context=ssl.create_default_context()))


class API:
    def __init__(self, config, opener=None):
        self.config = config
        self.opener = opener or secure_opener()

    def call(self, method, path, data=None, timeout=30):
        if not re.fullmatch(r"/[A-Za-z0-9_/-]+", path):
            raise DeployError("Некорректный путь API")
        request = Request(self.config.base + path, method=method,
                          data=None if data is None else json.dumps(data).encode(),
                          headers={"Authorization": "Bearer " + self.config.token,
                                   "Accept": "application/json", "Content-Type": "application/json"})
        try:
            with self.opener.open(request, timeout=min(30, max(0.1, timeout))) as response:
                if response.status < 200 or response.status >= 300:
                    raise DeployError("Coolify API вернул неожиданный HTTP status")
                raw = response.read(MAX_RESPONSE + 1)
                if len(raw) > MAX_RESPONSE:
                    raise DeployError("Слишком большой ответ Coolify API")
                return json.loads(raw)
        except HTTPError as error:
            code = error.code
            error.close()
            raise DeployError(f"Coolify API: {method} {path}, HTTP {code}") from None
        except (URLError, OSError, ValueError):
            raise DeployError(f"Coolify API недоступен или вернул неверный JSON: {method} {path}") from None


def check_application(application, config, *, pinned=False):
    if not isinstance(application, dict) or application.get("uuid") != config.application:
        raise DeployError("Coolify вернул другое приложение")
    if application.get("docker_registry_image_name") != config.image:
        raise DeployError("Приложение использует другой image; конфигурация не изменена")
    if pinned and application.get("docker_registry_image_tag") != config.tag:
        raise DeployError("Выбранная версия приложения изменилась; выкатка не подтверждена")


def probe(opener, url, expected, timeout):
    # Intentionally separate from API.call: no Authorization/Cookie on probes.
    request = Request(url, headers={"User-Agent": "danysik-ci-healthcheck/1"})
    try:
        with opener.open(request, timeout=min(10, max(0.1, timeout))) as response:
            return response.status == expected and response.geturl() == url
    except HTTPError as error:
        matched = error.code == expected and error.geturl() == url
        error.close()
        return matched
    except (URLError, OSError):
        return False


def deploy(config, api=None, probe_opener=None, *, now=time.monotonic, sleep=time.sleep, emit=print):
    api = api or API(config)
    probe_opener = probe_opener or secure_opener()
    deadline = now() + config.timeout

    def remaining():
        value = deadline - now()
        if value <= 0:
            raise DeployError("Истёк срок ожидания выкатки; проверь Deployments в Coolify")
        return value

    def call(method, path, data=None):
        return api.call(method, path, data, timeout=remaining())

    path = "/applications/" + config.application
    check_application(call("GET", path), config)
    # No changes to credentials, labels, routes, storage or application settings.
    call("PATCH", path, {"docker_registry_image_tag": config.tag})
    check_application(call("GET", path), config, pinned=True)
    try:
        result = call("POST", "/deploy", {"uuid": config.application})
    except DeployError:
        raise DeployError("Запрос запуска не подтверждён. Не повторяй автоматически: проверь Deployments в Coolify") from None
    try:
        deployments = result["deployments"]
        if len(deployments) != 1:
            raise ValueError()
        job = deployments[0]
        identifier = job["deployment_uuid"]
        if job["resource_uuid"] != config.application or not isinstance(identifier, str) or not IDENTIFIER.fullmatch(identifier):
            raise ValueError()
    except (KeyError, TypeError, ValueError, IndexError):
        raise DeployError("Coolify не подтвердил ID запуска нужного приложения; проверь Deployments") from None
    if config.token in identifier:
        raise DeployError("Некорректный ID выкатки Coolify")
    emit("Coolify deployment: " + identifier)
    while True:
        result = call("GET", "/deployments/" + identifier)
        if not isinstance(result, dict):
            raise DeployError("Некорректный статус выкатки Coolify")
        if result.get("deployment_uuid", identifier) != identifier or result.get("application_uuid", config.application) != config.application:
            raise DeployError("Coolify вернул статус другой выкатки")
        status = result.get("status")
        if not isinstance(status, str):
            raise DeployError("Некорректный статус выкатки Coolify")
        if status == "finished":
            break
        if status in {"failed", "cancelled", "cancelled-by-user"}:
            raise DeployError("Выкатка завершилась ошибкой или отменена; проверь Deployments")
        if status not in {"queued", "pending", "in_progress"}:
            raise DeployError("Неизвестный статус выкатки Coolify")
        sleep(min(5, remaining()))
    while True:
        application = call("GET", path)
        check_application(application, config, pinned=True)
        if application.get("status") == "running:healthy":
            break
        sleep(min(5, remaining()))
    for url, expected in config.probes:
        while not probe(probe_opener, url, expected, remaining()):
            sleep(min(5, remaining()))
    # Recheck after probes so concurrent manual changes do not produce success.
    application = call("GET", path)
    check_application(application, config, pinned=True)
    if application.get("status") != "running:healthy":
        raise DeployError("После HTTPS probes приложение перестало быть healthy")
    emit("Выкатка завершена: конфигурация закреплена по digest; Coolify healthy и HTTPS probes проверены")
    return {"application_uuid": config.application, "deployment_uuid": identifier,
            "image": config.image, "digest": config.digest}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", default="coolify.json", help="Путь к манифесту с image/routes/probes")
    args = parser.parse_args(argv)
    try:
        deploy(read_config(os.environ, args.manifest))
    except DeployError as error:
        print("deploy: " + str(error), file=sys.stderr)
        return 1
    except (OSError, TypeError, KeyError, ValueError):
        print("deploy: внутренняя ошибка обработки ответа; проверь Deployments", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
