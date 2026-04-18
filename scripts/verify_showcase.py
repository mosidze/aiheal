import argparse
import json
import shutil
import subprocess
import time
import urllib.request
from pathlib import Path


def run_command(command: list[str]) -> tuple[int, str]:
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    output = result.stdout + result.stderr
    return result.returncode, output


def try_http(url: str, attempts: int = 15, delay: int = 2) -> tuple[bool, int | None, str]:
    last_error = ""
    for _ in range(attempts):
        try:
            with urllib.request.urlopen(url, timeout=5) as response:
                return True, response.getcode(), ""
        except Exception as exc:  # noqa: BLE001
            last_error = str(exc)
            time.sleep(delay)
    return False, None, last_error


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--url", default="http://127.0.0.1:8080")
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    runtime_log = output_dir / "runtime.log"

    if shutil.which("docker") is None:
        verification = {
            "success": False,
            "summary": "Docker is not available on the runner.",
        }
        (output_dir / "verification.json").write_text(json.dumps(verification, indent=2))
        runtime_log.write_text("Docker binary is unavailable.\n")
        raise SystemExit(1)

    steps = []
    build_code, build_output = run_command(["docker", "compose", "build"])
    steps.append({"step": "docker compose build", "exit_code": build_code})

    up_code, up_output = run_command(["docker", "compose", "up", "-d"])
    steps.append({"step": "docker compose up -d", "exit_code": up_code})

    http_ok = False
    status_code = None
    http_error = ""
    if build_code == 0 and up_code == 0:
        http_ok, status_code, http_error = try_http(args.url)

    ps_code, ps_output = run_command(["docker", "compose", "ps"])
    logs_code, logs_output = run_command(["docker", "compose", "logs", "--no-color"])
    down_code, down_output = run_command(["docker", "compose", "down", "-v"])
    steps.extend(
        [
            {"step": "docker compose ps", "exit_code": ps_code},
            {"step": "docker compose logs --no-color", "exit_code": logs_code},
            {"step": "docker compose down -v", "exit_code": down_code},
        ]
    )

    runtime_log.write_text(
        "\n\n".join(
            [
                "### docker compose build",
                build_output,
                "### docker compose up -d",
                up_output,
                "### docker compose ps",
                ps_output,
                "### docker compose logs --no-color",
                logs_output,
                "### docker compose down -v",
                down_output,
                "### http check",
                f"ok={http_ok} status={status_code} error={http_error}",
            ]
        )
    )

    verification = {
        "success": build_code == 0 and up_code == 0 and http_ok,
        "summary": "Service is reachable after docker compose build/up."
        if build_code == 0 and up_code == 0 and http_ok
        else "Service verification failed during build, startup or HTTP probing.",
        "http_status": status_code,
        "http_error": http_error,
        "steps": steps,
    }
    (output_dir / "verification.json").write_text(json.dumps(verification, indent=2))

    raise SystemExit(0 if verification["success"] else 1)
