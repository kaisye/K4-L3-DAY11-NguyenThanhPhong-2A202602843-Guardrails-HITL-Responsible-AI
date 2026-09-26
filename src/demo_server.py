"""Local VinBank chatbot demo with real Blue LLM and defense trace.

Run from the repository root::

    python src/demo_server.py

Then open http://127.0.0.1:8080. The server uses the existing
OPENROUTER_API_KEY and the locked Blue model from ``core.config``.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

SRC_DIR = Path(__file__).resolve().parent
ROOT_DIR = SRC_DIR.parent
UI_FILE = ROOT_DIR / "ui" / "guardrail-defense.html"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from google.genai import types

from agents.agent import create_blue_agent
from assignment.audit_log import AuditLogPlugin
from assignment.monitoring import MonitoringAlert
from assignment.pipeline import is_egress_allowed
from assignment.rate_limiter import RateLimitPlugin
from core.config import get_blue_model, get_openrouter_api_key
from core.utils import chat_with_agent
from guardrails.input_guardrails import inspect_input
from guardrails.output_guardrails import inspect_output
from guardrails.security_normalization import canonicalize_security_text


class DemoRuntime:
    def __init__(self):
        self.rate_limiter = RateLimitPlugin(max_requests=10, window_seconds=60)
        self.audit = AuditLogPlugin()
        self.monitor = MonitoringAlert()
        # Guardrails are executed explicitly below so every decision can be
        # returned to the UI. The actual model call therefore receives only
        # input that has passed the deterministic gates.
        self.agent, self.runner = create_blue_agent([])
        # The graded path keeps the exact locked slug. OpenRouter currently
        # exposes its live endpoint with the ``:free`` route suffix, so the
        # demo uses that by default without changing core.config.
        self.runner.model = os.environ.get(
            "BLUE_DEMO_MODEL", f"{get_blue_model()}:free"
        ).strip()

    def model_label(self) -> str:
        return f"openrouter:{self.runner.model}"

    @staticmethod
    def trace(layer: str, status: str, reason: str) -> dict:
        return {"layer": layer, "status": status, "reason": reason}

    async def chat(self, payload: dict) -> tuple[int, dict]:
        prompt = str(payload.get("prompt") or "").strip()
        user_id = str(payload.get("user_id") or "demo-user")[:80]
        destination = str(
            payload.get("destination") or "https://api.vinbank.example"
        )
        burst = max(1, min(int(payload.get("burst") or 1), 20))
        request_id = str(uuid.uuid4())
        trace: list[dict] = []

        if not prompt:
            return 400, {"error": "Prompt không được để trống.", "trace": trace}

        self.audit.record_input(
            user_id=user_id, text=prompt, request_id=request_id
        )
        normalized = canonicalize_security_text(prompt)
        trace.append(self.trace(
            "normalize", "passed",
            "unicode_and_spacing_normalized" if normalized != prompt else "already_canonical",
        ))

        user_content = types.Content(
            role="user", parts=[types.Part.from_text(text=normalized)]
        )
        rate_result = None
        for _ in range(burst):
            rate_result = await self.rate_limiter.on_user_message_callback(
                invocation_context=SimpleNamespace(user_id=user_id),
                user_message=user_content,
            )
            if rate_result is not None:
                break

        if rate_result is not None:
            response = "Rate limit exceeded. Vui lòng thử lại sau."
            trace.append(self.trace("rate_limit", "blocked", "request_budget_exceeded"))
            return self._finish(request_id, user_id, prompt, response, trace, "rate_limit")
        trace.append(self.trace("rate_limit", "passed", "within_request_budget"))

        decision = inspect_input(normalized)
        if decision["layer"] == "input_injection":
            response = "Tôi không thể xử lý yêu cầu có dấu hiệu thao túng chỉ dẫn hoặc lấy dữ liệu bí mật."
            trace.append(self.trace("input_injection", "blocked", decision["reason"]))
            return self._finish(request_id, user_id, prompt, response, trace, "input_injection")
        trace.append(self.trace("input_injection", "passed", "no_injection_detected"))

        if decision["layer"] == "input_topic":
            response = "Tôi là trợ lý VinBank và chỉ hỗ trợ các câu hỏi liên quan đến ngân hàng."
            trace.append(self.trace("input_topic", "blocked", decision["reason"]))
            return self._finish(request_id, user_id, prompt, response, trace, "input_topic")
        trace.append(self.trace("input_topic", "passed", "banking_topic_allowed"))

        try:
            raw_response, _ = await chat_with_agent(
                self.agent, self.runner, normalized
            )
        except Exception as exc:
            trace.append(self.trace("llm", "error", type(exc).__name__))
            response = "Không thể kết nối Blue LLM. Hãy kiểm tra OPENROUTER_API_KEY và kết nối mạng."
            return self._finish(request_id, user_id, prompt, response, trace, "llm", http_status=502)
        trace.append(self.trace("llm", "passed", f"response_generated_by_{self.model_label()}"))

        output = inspect_output(raw_response)
        response = output["redacted"]
        if output["action"] == "REDACT":
            trace.append(self.trace("output_secret", "blocked", output["reason"]))
            return self._finish(request_id, user_id, prompt, response, trace, "output_secret")
        trace.append(self.trace("output_secret", "passed", "no_sensitive_content"))

        if not is_egress_allowed(destination, response):
            response = "Phản hồi đã bị chặn vì đích đến hoặc payload không đạt chính sách egress."
            trace.append(self.trace("egress", "blocked", "destination_or_payload_denied"))
            return self._finish(request_id, user_id, prompt, response, trace, "egress")
        trace.append(self.trace("egress", "passed", "trusted_https_destination"))
        return self._finish(request_id, user_id, prompt, response, trace, None)

    def _finish(
        self,
        request_id: str,
        user_id: str,
        prompt: str,
        response: str,
        trace: list[dict],
        blocked_layer: str | None,
        *,
        http_status: int = 200,
    ) -> tuple[int, dict]:
        blocked = blocked_layer is not None
        self.monitor.total_requests += 1
        if blocked:
            self.monitor.blocked_requests += 1
        if blocked_layer == "rate_limit":
            self.monitor.rate_limit_hits += 1
        trace.append(self.trace("audit_metrics", "passed", "interaction_recorded"))
        self.audit.record_output(
            user_id=user_id,
            text=response,
            blocked=blocked,
            layer=blocked_layer,
            request_id=request_id,
        )
        self.monitor.check_metrics()
        self.audit.export_json()
        self.monitor.export_json()
        return http_status, {
            "request_id": request_id,
            "response": response,
            "blocked": blocked,
            "blocked_layer": blocked_layer,
            "trace": trace,
            "model": self.model_label(),
            "metrics": self.monitor.snapshot(),
        }


RUNTIME: DemoRuntime | None = None


class DemoHandler(BaseHTTPRequestHandler):
    server_version = "VinBankGuardrailDemo/1.0"

    def log_message(self, fmt: str, *args) -> None:
        print(f"[demo] {self.address_string()} - {fmt % args}")

    def _json(self, status: int, data: dict) -> None:
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path in {"/", "/index.html", "/ui/guardrail-defense.html"}:
            body = UI_FILE.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/api/health":
            self._json(200, {
                "ok": True,
                "model": RUNTIME.model_label(),
                "api_key_configured": bool(get_openrouter_api_key()),
            })
            return
        self._json(404, {"error": "Not found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/api/chat":
            self._json(404, {"error": "Not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 100_000:
                raise ValueError("Invalid body length")
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            status, result = asyncio.run(RUNTIME.chat(payload))
            self._json(status, result)
        except (ValueError, json.JSONDecodeError) as exc:
            self._json(400, {"error": str(exc)})
        except Exception as exc:
            self._json(500, {"error": f"Server error: {type(exc).__name__}"})


def main() -> None:
    parser = argparse.ArgumentParser(description="VinBank guardrail chatbot demo")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=8080, type=int)
    args = parser.parse_args()
    if not get_openrouter_api_key():
        raise SystemExit("Thiếu OPENROUTER_API_KEY trong file .env")
    global RUNTIME
    RUNTIME = DemoRuntime()
    server = ThreadingHTTPServer((args.host, args.port), DemoHandler)
    print(f"VinBank Guardrail Demo: http://{args.host}:{args.port}")
    print(f"Blue LLM: {RUNTIME.model_label()}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nĐã dừng demo.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
