"""
Provider-agnostic LLM client.

Agents never call OpenAI/Azure/Ollama SDKs directly — they call this class,
so the provider stays configurable (Section 23) and every call gets:
  - a consistent structured-JSON contract
  - retries with backoff
  - a hard instruction not to invent citations/standards (Section 9)

Swap providers purely via TM_LLM_PROVIDER / TM_LLM_MODEL env vars — no code
change required in any service module.
"""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from typing import Any

from config import get_settings

logger = logging.getLogger(__name__)

GROUNDING_GUARDRAIL = (
    "You are a security reasoning engine for an authorized threat-modeling "
    "platform. Only reference OWASP, CWE, MITRE ATT&CK, or CVE identifiers "
    "that are explicitly present in the provided context. If no supporting "
    "context is given for a standard/citation, omit it rather than invent "
    "one. Respond with strict JSON only, matching the requested schema, and "
    "no prose outside the JSON."
)


@dataclass
class LLMResponse:
    text: str
    raw: Any = None

    def json(self) -> dict:
        cleaned = self.text.strip()
        if cleaned.startswith("```"):
            cleaned = cleaned.strip("`")
            if cleaned.lower().startswith("json"):
                cleaned = cleaned[4:]
        return json.loads(cleaned)


class LLMClient:
    def __init__(self):
        self.settings = get_settings()

    def complete(self, system_prompt: str, user_prompt: str, *, json_mode: bool = True) -> LLMResponse:
        provider = self.settings.llm_provider
        full_system = f"{GROUNDING_GUARDRAIL}\n\n{system_prompt}" if json_mode else system_prompt

        last_err: Exception | None = None
        for attempt in range(self.settings.llm_max_retries):
            try:
                if provider == "mock":
                    return self._mock_complete(full_system, user_prompt)
                elif provider == "openai":
                    return self._openai_complete(full_system, user_prompt)
                elif provider == "azure_openai":
                    return self._azure_openai_complete(full_system, user_prompt)
                elif provider == "ollama":
                    return self._ollama_complete(full_system, user_prompt)
                elif provider == "anthropic":
                    return self._anthropic_complete(full_system, user_prompt)
                else:
                    raise ValueError(f"Unknown LLM provider: {provider}")
            except Exception as exc:  # noqa: BLE001
                last_err = exc
                logger.warning("LLM call failed (attempt %s/%s): %s", attempt + 1, self.settings.llm_max_retries, exc)
                time.sleep(min(2**attempt, 8))
        raise RuntimeError(f"LLM call failed after retries: {last_err}")

    # ---- provider implementations -------------------------------------

    def _openai_complete(self, system_prompt: str, user_prompt: str) -> LLMResponse:
        from openai import OpenAI

        client = OpenAI(api_key=self.settings.llm_api_key, base_url=self.settings.llm_api_base or None)
        resp = client.chat.completions.create(
            model=self.settings.llm_model,
            temperature=self.settings.llm_temperature,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            response_format={"type": "json_object"},
        )
        return LLMResponse(text=resp.choices[0].message.content, raw=resp)

    def _azure_openai_complete(self, system_prompt: str, user_prompt: str) -> LLMResponse:
        from openai import AzureOpenAI

        client = AzureOpenAI(
            api_key=self.settings.llm_api_key,
            azure_endpoint=self.settings.llm_api_base,
            api_version="2024-06-01",
        )
        resp = client.chat.completions.create(
            model=self.settings.llm_model,
            temperature=self.settings.llm_temperature,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            response_format={"type": "json_object"},
        )
        return LLMResponse(text=resp.choices[0].message.content, raw=resp)

    def _ollama_complete(self, system_prompt: str, user_prompt: str) -> LLMResponse:
        import requests

        base = self.settings.llm_api_base or "http://localhost:11434"
        resp = requests.post(
            f"{base}/api/chat",
            json={
                "model": self.settings.llm_model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                "stream": False,
                "format": "json",
                "options": {"temperature": self.settings.llm_temperature},
            },
            timeout=120,
        )
        resp.raise_for_status()
        data = resp.json()
        return LLMResponse(text=data["message"]["content"], raw=data)

    def _anthropic_complete(self, system_prompt: str, user_prompt: str) -> LLMResponse:
        import anthropic

        client = anthropic.Anthropic(api_key=self.settings.llm_api_key)
        resp = client.messages.create(
            model=self.settings.llm_model,
            max_tokens=4000,
            temperature=self.settings.llm_temperature,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        )
        text = "".join(block.text for block in resp.content if block.type == "text")
        return LLMResponse(text=text, raw=resp)

    def complete_vision(self, system_prompt: str, user_prompt: str, image_bytes: bytes, image_media_type: str = "image/png") -> LLMResponse:
        """
        Vision-capable completion for the Architecture Diagram input path
        (Section 4, Input 3). Only openai/azure_openai/anthropic/ollama
        (with a vision-capable local model like llava) support this; mock
        raises NotImplementedError so callers can fall back to a documented
        manual-entry path instead of silently returning nonsense.
        """
        provider = self.settings.llm_provider
        last_err: Exception | None = None
        for attempt in range(self.settings.llm_max_retries):
            try:
                if provider == "openai":
                    return self._openai_vision(system_prompt, user_prompt, image_bytes, image_media_type)
                elif provider == "azure_openai":
                    return self._azure_openai_vision(system_prompt, user_prompt, image_bytes, image_media_type)
                elif provider == "anthropic":
                    return self._anthropic_vision(system_prompt, user_prompt, image_bytes, image_media_type)
                elif provider == "ollama":
                    return self._ollama_vision(system_prompt, user_prompt, image_bytes)
                elif provider == "mock":
                    raise NotImplementedError(
                        "TM_LLM_PROVIDER=mock has no vision capability. Configure openai, "
                        "azure_openai, anthropic, or a vision-capable ollama model to analyze "
                        "architecture diagrams, or use the OpenAPI/manual input methods instead."
                    )
                else:
                    raise ValueError(f"Unknown LLM provider: {provider}")
            except NotImplementedError:
                raise  # don't retry — this is a configuration issue, not a transient failure
            except Exception as exc:  # noqa: BLE001
                last_err = exc
                logger.warning("Vision LLM call failed (attempt %s/%s): %s", attempt + 1, self.settings.llm_max_retries, exc)
                time.sleep(min(2**attempt, 8))
        raise RuntimeError(f"Vision LLM call failed after retries: {last_err}")

    def _openai_vision(self, system_prompt, user_prompt, image_bytes, media_type) -> LLMResponse:
        import base64

        from openai import OpenAI

        b64 = base64.b64encode(image_bytes).decode("utf-8")
        client = OpenAI(api_key=self.settings.llm_api_key, base_url=self.settings.llm_api_base or None)
        resp = client.chat.completions.create(
            model=self.settings.llm_model,
            temperature=self.settings.llm_temperature,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": [
                    {"type": "text", "text": user_prompt},
                    {"type": "image_url", "image_url": {"url": f"data:{media_type};base64,{b64}"}},
                ]},
            ],
            response_format={"type": "json_object"},
        )
        return LLMResponse(text=resp.choices[0].message.content, raw=resp)

    def _azure_openai_vision(self, system_prompt, user_prompt, image_bytes, media_type) -> LLMResponse:
        import base64

        from openai import AzureOpenAI

        b64 = base64.b64encode(image_bytes).decode("utf-8")
        client = AzureOpenAI(
            api_key=self.settings.llm_api_key,
            azure_endpoint=self.settings.llm_api_base,
            api_version="2024-06-01",
        )
        resp = client.chat.completions.create(
            model=self.settings.llm_model,
            temperature=self.settings.llm_temperature,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": [
                    {"type": "text", "text": user_prompt},
                    {"type": "image_url", "image_url": {"url": f"data:{media_type};base64,{b64}"}},
                ]},
            ],
            response_format={"type": "json_object"},
        )
        return LLMResponse(text=resp.choices[0].message.content, raw=resp)

    def _anthropic_vision(self, system_prompt, user_prompt, image_bytes, media_type) -> LLMResponse:
        import base64

        import anthropic

        b64 = base64.b64encode(image_bytes).decode("utf-8")
        client = anthropic.Anthropic(api_key=self.settings.llm_api_key)
        resp = client.messages.create(
            model=self.settings.llm_model,
            max_tokens=4000,
            temperature=self.settings.llm_temperature,
            system=system_prompt,
            messages=[{
                "role": "user",
                "content": [
                    {"type": "image", "source": {"type": "base64", "media_type": media_type, "data": b64}},
                    {"type": "text", "text": user_prompt},
                ],
            }],
        )
        text = "".join(block.text for block in resp.content if block.type == "text")
        return LLMResponse(text=text, raw=resp)

    def _ollama_vision(self, system_prompt, user_prompt, image_bytes) -> LLMResponse:
        import base64

        import requests

        b64 = base64.b64encode(image_bytes).decode("utf-8")
        base = self.settings.llm_api_base or "http://localhost:11434"
        resp = requests.post(
            f"{base}/api/chat",
            json={
                "model": self.settings.llm_model,  # must be a vision-capable model, e.g. "llava"
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt, "images": [b64]},
                ],
                "stream": False,
                "format": "json",
                "options": {"temperature": self.settings.llm_temperature},
            },
            timeout=180,
        )
        resp.raise_for_status()
        data = resp.json()
        return LLMResponse(text=data["message"]["content"], raw=data)

    def _mock_complete(self, system_prompt: str, user_prompt: str) -> LLMResponse:
        """
        Deterministic offline mode so the whole pipeline (and grading/demo)
        works with zero API keys. Each service module supplies a
        `_mock_response(user_prompt)` fallback it can call directly instead
        of relying on this generic stub; this exists mainly so `complete()`
        never breaks the pipeline when no key is configured.
        """
        logger.info("LLM_PROVIDER=mock — returning empty structured stub. "
                     "Configure TM_LLM_PROVIDER for real reasoning.")
        return LLMResponse(text=json.dumps({"_mock": True, "note": "Set TM_LLM_PROVIDER to a real provider."}))
