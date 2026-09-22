"""Shared SDK conformance fixtures.

Each case in sdk-conformance/cases.json is signed in this harness from the
shared private JWK. The expected verdict is accept or reject.
"""

import json
import time
from pathlib import Path
from typing import Any

import httpx
import jwt
import pytest
from jwt.algorithms import RSAAlgorithm
from mcp_auth_client import JWTVerifier, TokenVerificationError


def fixture_root() -> Path:
    current = Path(__file__).resolve()
    for parent in current.parents:
        candidate = parent / "sdk-conformance"
        if candidate.is_dir():
            return candidate
    raise RuntimeError("sdk-conformance fixtures not found")


def load_suite() -> dict[str, Any]:
    root = fixture_root()
    suite = json.loads((root / "cases.json").read_text())
    suite["private_jwk"] = json.loads((root / "key.json").read_text())
    suite["jwks"] = json.loads((root / "jwks.json").read_text())
    return suite


def sign(private_jwk: dict[str, Any], header: dict[str, Any], claims: dict[str, Any]) -> str:
    key = RSAAlgorithm.from_jwk(json.dumps(private_jwk))
    token = jwt.encode(claims, key, algorithm="RS256", headers=header)
    return token if isinstance(token, str) else token.decode()


def case_token(suite: dict[str, Any], case: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    defaults = suite["defaults"]
    header = dict(defaults["header"])
    header.update(case.get("header") or {})
    claims = dict(defaults["claims"])
    claims.update(case.get("claims") or {})
    now = int(time.time())
    exp_offset = case.get("exp_offset_seconds", defaults["exp_offset_seconds"])
    claims["exp"] = now + int(exp_offset)
    if "nbf_offset_seconds" in case:
        claims["nbf"] = now + int(case["nbf_offset_seconds"])
    return sign(suite["private_jwk"], header, claims), claims


def verifier_kwargs(suite: dict[str, Any], case: dict[str, Any]) -> dict[str, Any]:
    defaults = suite["defaults"]
    return {
        "issuer": defaults["issuer"],
        "audience": defaults["audience"],
        "required_scopes": set(case.get("required_scopes") or []),
        "clock_skew": float(case.get("clock_skew_seconds", defaults["clock_skew_seconds"])),
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("case", load_suite()["cases"], ids=lambda case: case["id"])
async def test_sdk_conformance_case(case: dict[str, Any]) -> None:
    suite = load_suite()
    token, _claims = case_token(suite, case)
    if case.get("kind") == "oversized_jwks":
        pad = str(suite["pad_char"]) * int(suite["pad_count"])
        body = json.dumps({"keys": suite["jwks"]["keys"], "pad": pad}).encode()
        assert len(body) > int(suite["max_jwks_bytes"])

        def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=body)

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            verifier = JWTVerifier(
                "https://auth.example.com/jwks",
                http_client=client,
                **verifier_kwargs(suite, case),
            )
            with pytest.raises(TokenVerificationError):
                await verifier.verify(token)
        return

    verifier = JWTVerifier.from_jwks(
        {"keys": suite["jwks"]["keys"]}, **verifier_kwargs(suite, case)
    )
    if case["expect"] == "accept":
        claims = await verifier.verify(token)
        assert claims.subject == "user"
        return
    with pytest.raises(TokenVerificationError):
        await verifier.verify(token)
