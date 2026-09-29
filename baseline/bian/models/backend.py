"""Small local Transformers backend shared by the two logical BiAn roles."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .structured_output import parse_and_validate


@dataclass(frozen=True)
class ModelConfig:
    max_input_tokens: int = 8192
    batch_size: int = 8
    device_max_new_tokens: int = 256
    stage1_max_new_tokens: int = 256
    stage2_max_new_tokens: int = 384
    classification_max_new_tokens: int = 192
    retries: int = 1
    seed: int = 42


EXPECTED_KEYS = {
    "7b_a_device_analysis": "device_analyses",
    "7b_b_stage1": "scores",
    "7b_b_stage2": "candidates",
    "classification": None,
}

RESPONSE_PREFIXES = {
    "7b_b_stage2": '{"candidates":[',
}


def response_prefix_for(prompt_name: str) -> str:
    """Schema-only assistant prefill; contains no candidate or label values."""
    return RESPONSE_PREFIXES.get(prompt_name, "")


class JsonModelBackend:
    def __init__(self, model: str, config: ModelConfig, prompt_dir: Path):
        self.model = model
        self.config = config
        self.prompt_dir = prompt_dir
        self._tokenizer = None
        self._network = None

    def load(self) -> None:
        if self._network is not None:
            return
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer
        local = Path(self.model).exists()
        self._tokenizer = AutoTokenizer.from_pretrained(self.model, local_files_only=local, trust_remote_code=False)
        kwargs = {"trust_remote_code": False, "local_files_only": local, "low_cpu_mem_usage": True}
        if torch.cuda.is_available():
            kwargs.update({"torch_dtype": torch.bfloat16, "device_map": {"": 0}})
        self._network = AutoModelForCausalLM.from_pretrained(self.model, **kwargs)
        self._network.eval()

    def _render_prompt(self, name: str, payload: dict[str, Any]) -> str:
        template = (self.prompt_dir / f"{name}.txt").read_text(encoding="utf-8")
        return template + "\n\nINPUT_JSON:\n" + json.dumps(payload, ensure_ascii=False, separators=(",", ":"))

    def generate_json(self, *, role: str, prompt_name: str, payload: dict[str, Any], validator: Callable[[Any], dict[str, Any]], max_new_tokens: int) -> dict[str, Any]:
        try:
            self.load()
        except Exception as exc:
            reason = " ".join(str(exc).splitlines()).replace(self.model, "<model>")[:500]
            raise RuntimeError(
                f"{role}/{prompt_name} model loading failed: "
                f"{type(exc).__name__}: {reason}"
            ) from None
        import torch
        assert self._tokenizer is not None and self._network is not None
        error = None
        for attempt in range(1, self.config.retries + 2):
            prompt = self._render_prompt(prompt_name, payload)
            rendered = self._tokenizer.apply_chat_template([{"role": "user", "content": prompt}], tokenize=False, add_generation_prompt=True)
            rendered += "<think>\n</think>\n"
            response_prefix = response_prefix_for(prompt_name)
            rendered += response_prefix
            inputs = self._tokenizer(rendered, return_tensors="pt", truncation=True, max_length=self.config.max_input_tokens)
            device = next(self._network.parameters()).device
            inputs = {key: value.to(device) for key, value in inputs.items()}
            with torch.inference_mode():
                output = self._network.generate(**inputs, max_new_tokens=max_new_tokens, do_sample=False, pad_token_id=self._tokenizer.eos_token_id, use_cache=True)
            generated = output[0, inputs["input_ids"].shape[-1]:]
            raw = response_prefix + self._tokenizer.decode(generated, skip_special_tokens=True)
            try:
                return parse_and_validate(
                    raw,
                    expected_key=EXPECTED_KEYS.get(prompt_name),
                    validator=validator,
                )
            except Exception as exc:
                error = f"{type(exc).__name__}: {exc}"
        raise ValueError(f"{role}/{prompt_name} failed after retries: {error}")


def load_dotenv(path: Path) -> dict[str, str]:
    """Load simple KEY=VALUE pairs without adding a runtime dependency."""
    if not path.exists():
        return {}
    values: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        values[key] = value
        os.environ.setdefault(key, value)
    return values


def _env(name: str, dotenv: dict[str, str], default: str | None = None) -> str | None:
    return os.environ.get(name) or dotenv.get(name) or default


class OpenAICompatibleJsonBackend:
    """OpenAI Chat Completions compatible backend for JSON-producing stages."""

    def __init__(
        self,
        model: str,
        config: ModelConfig,
        prompt_dir: Path,
        *,
        api_key: str,
        base_url: str = "https://api.openai.com/v1",
        timeout: float = 120.0,
        json_mode: bool = True,
        thinking_disabled: bool = False,
        retries: int | None = None,
        debug_dir: Path | None = None,
        max_token_overrides: dict[str, int] | None = None,
    ):
        if not api_key:
            raise ValueError("OPENAI_API_KEY is required for the openai backend")
        self.model = model
        self.config = config
        self.prompt_dir = prompt_dir
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.json_mode = json_mode
        self.thinking_disabled = thinking_disabled
        self.retries = max(config.retries, 2) if retries is None else retries
        self.debug_dir = debug_dir
        self.max_token_overrides = max_token_overrides or {}
        self._debug_counter = 0
        self._last_response_meta: dict[str, Any] = {}

    @classmethod
    def from_env(
        cls,
        model: str | None,
        config: ModelConfig,
        prompt_dir: Path,
        *,
        env_file: Path,
    ) -> "OpenAICompatibleJsonBackend":
        dotenv = load_dotenv(env_file)
        selected_model = model or _env("OPENAI_MODEL", dotenv)
        if not selected_model:
            raise ValueError("model is required; pass --model or set OPENAI_MODEL in .env")
        timeout_text = _env("OPENAI_TIMEOUT", dotenv, "120")
        try:
            timeout = float(timeout_text or "120")
        except ValueError as exc:
            raise ValueError("OPENAI_TIMEOUT must be a number") from exc
        retries_text = _env("OPENAI_RETRIES", dotenv)
        retries = None
        if retries_text:
            try:
                retries = int(retries_text)
            except ValueError as exc:
                raise ValueError("OPENAI_RETRIES must be an integer") from exc
        json_mode = (_env("OPENAI_JSON_MODE", dotenv, "1") or "1").lower() not in {
            "0",
            "false",
            "no",
            "off",
        }
        thinking_disabled = (_env("OPENAI_DISABLE_THINKING", dotenv, "0") or "0").lower() not in {
            "0",
            "false",
            "no",
            "off",
        }
        debug_dir_text = _env("OPENAI_DEBUG_DIR", dotenv, "outputs/llm_debug")
        debug_dir = None
        if debug_dir_text:
            debug_path = Path(debug_dir_text)
            debug_dir = debug_path if debug_path.is_absolute() else env_file.parent / debug_path
        max_token_overrides = {}
        for env_name, prompt_name in (
            ("OPENAI_DEVICE_MAX_TOKENS", "7b_a_device_analysis"),
            ("OPENAI_STAGE1_MAX_TOKENS", "7b_b_stage1"),
            ("OPENAI_STAGE2_MAX_TOKENS", "7b_b_stage2"),
            ("OPENAI_CLASSIFICATION_MAX_TOKENS", "classification"),
        ):
            value = _env(env_name, dotenv)
            if not value:
                continue
            try:
                max_token_overrides[prompt_name] = int(value)
            except ValueError as exc:
                raise ValueError(f"{env_name} must be an integer") from exc
        return cls(
            selected_model,
            config,
            prompt_dir,
            api_key=_env("OPENAI_API_KEY", dotenv, "") or "",
            base_url=_env("OPENAI_BASE_URL", dotenv, "https://api.openai.com/v1") or "https://api.openai.com/v1",
            timeout=timeout,
            json_mode=json_mode,
            thinking_disabled=thinking_disabled,
            retries=retries,
            debug_dir=debug_dir,
            max_token_overrides=max_token_overrides,
        )

    def _render_prompt(self, name: str, payload: dict[str, Any]) -> str:
        template = (self.prompt_dir / f"{name}.txt").read_text(encoding="utf-8")
        return template + "\n\nINPUT_JSON:\n" + json.dumps(payload, ensure_ascii=False, separators=(",", ":"))

    def _endpoint(self) -> str:
        if self.base_url.endswith("/chat/completions"):
            return self.base_url
        return f"{self.base_url}/chat/completions"

    def _request(self, prompt: str, max_new_tokens: int) -> str:
        self._last_response_meta = {}
        thinking_variants = [self.thinking_disabled]
        if self.json_mode and not self.thinking_disabled:
            thinking_variants.append(True)
        last_content = ""
        for request_index, disable_thinking in enumerate(thinking_variants, start=1):
            content = self._request_once(
                prompt,
                max_new_tokens,
                disable_thinking=disable_thinking,
                request_index=request_index,
            )
            if content:
                return content
            last_content = content
        return last_content

    def _request_once(
        self,
        prompt: str,
        max_new_tokens: int,
        *,
        disable_thinking: bool,
        request_index: int,
    ) -> str:
        body = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": "Return only valid JSON object output. Do not include markdown fences or explanatory prose.",
                },
                {"role": "user", "content": prompt},
            ],
            "temperature": 0,
            "max_tokens": max_new_tokens,
        }
        if self.json_mode:
            body["response_format"] = {"type": "json_object"}
        if disable_thinking:
            body["thinking"] = {"type": "disabled"}
        request = Request(
            self._endpoint(),
            data=json.dumps(body).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urlopen(request, timeout=self.timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:500]
            raise RuntimeError(f"OpenAI-compatible API returned HTTP {exc.code}: {detail}") from None
        except URLError as exc:
            raise RuntimeError(f"OpenAI-compatible API request failed: {exc.reason}") from None
        try:
            choice = payload["choices"][0]
            message = choice["message"]
        except (KeyError, IndexError, TypeError) as exc:
            raise RuntimeError("OpenAI-compatible API response does not contain choices[0].message.content") from exc
        content = message.get("content")
        if isinstance(content, list):
            content = "".join(
                item.get("text", "")
                for item in content
                if isinstance(item, dict) and item.get("type") in {None, "text"}
            )
        if not isinstance(content, str):
            raise RuntimeError("OpenAI-compatible API message content is not a string")
        reasoning_content = message.get("reasoning_content")
        self._last_response_meta = {
            "finish_reason": choice.get("finish_reason") if isinstance(choice, dict) else None,
            "message_keys": sorted(message.keys()) if isinstance(message, dict) else [],
            "content_length": len(content),
            "has_reasoning_content": isinstance(reasoning_content, str) and bool(reasoning_content),
            "reasoning_content_length": len(reasoning_content) if isinstance(reasoning_content, str) else 0,
            "request_thinking_disabled": disable_thinking,
            "request_index": request_index,
        }
        return content

    def _write_debug(
        self,
        *,
        role: str,
        prompt_name: str,
        attempt: int,
        prompt: str,
        raw: str,
        error: str | None,
        max_new_tokens: int,
    ) -> None:
        if self.debug_dir is None:
            return
        self._debug_counter += 1
        self.debug_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        stem = f"{timestamp}_{self._debug_counter:04d}_{role}_{prompt_name}_attempt{attempt}"
        metadata = {
            "role": role,
            "prompt_name": prompt_name,
            "attempt": attempt,
            "model": self.model,
            "base_url": self.base_url,
            "json_mode": self.json_mode,
            "thinking_disabled": self.thinking_disabled,
            "max_new_tokens": max_new_tokens,
            "error": error,
        }
        metadata.update(self._last_response_meta)
        (self.debug_dir / f"{stem}.meta.json").write_text(
            json.dumps(metadata, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        (self.debug_dir / f"{stem}.prompt.txt").write_text(prompt, encoding="utf-8")
        (self.debug_dir / f"{stem}.raw.txt").write_text(raw, encoding="utf-8")

    def generate_json(
        self,
        *,
        role: str,
        prompt_name: str,
        payload: dict[str, Any],
        validator: Callable[[Any], dict[str, Any]],
        max_new_tokens: int,
    ) -> dict[str, Any]:
        error = None
        raw = ""
        prompt = self._render_prompt(prompt_name, payload)
        effective_max_tokens = self.max_token_overrides.get(prompt_name, max_new_tokens)
        for attempt in range(1, self.retries + 2):
            try:
                raw = self._request(prompt, effective_max_tokens)
                result = parse_and_validate(
                    raw,
                    expected_key=EXPECTED_KEYS.get(prompt_name),
                    validator=validator,
                )
                self._write_debug(
                    role=role,
                    prompt_name=prompt_name,
                    attempt=attempt,
                    prompt=prompt,
                    raw=raw,
                    error=None,
                    max_new_tokens=effective_max_tokens,
                )
                return result
            except Exception as exc:
                error = f"{type(exc).__name__}: {exc}"
                self._write_debug(
                    role=role,
                    prompt_name=prompt_name,
                    attempt=attempt,
                    prompt=prompt,
                    raw=raw,
                    error=error,
                    max_new_tokens=effective_max_tokens,
                )
        raw_preview = raw.replace("\r", " ").replace("\n", " ")[:500]
        suffix = f"; raw output preview: {raw_preview!r}" if raw_preview else ""
        if self.debug_dir is not None:
            suffix += f"; debug dir: {self.debug_dir}"
        raise ValueError(f"{role}/{prompt_name} failed after retries: {error}{suffix}")
