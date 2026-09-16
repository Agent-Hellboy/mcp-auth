import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from mcp_auth_client import JWTVerifier, OAuthState, TokenVerificationError, unauthorized_headers
from mcp_auth_client.cache import BoundedTokenCache
from mcp_auth_client.challenge import parse_www_authenticate
from mcp_auth_client.models import AuthorizationServerConfig


def key_pair() -> tuple[rsa.RSAPrivateKey, dict[str, object]]:
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = private.public_key().public_numbers()

    def b64(value: int) -> str:
        return jwt.utils.base64url_encode(
            value.to_bytes((value.bit_length() + 7) // 8, "big")
        ).decode()

    return private, {
        "kty": "RSA",
        "kid": "test",
        "alg": "RS256",
        "use": "sig",
        "n": b64(public.n),
        "e": b64(public.e),
    }


@pytest.mark.asyncio
async def test_jwt_signature_issuer_audience_expiry_and_scopes() -> None:
    private, jwk = key_pair()
    token = jwt.encode(
        {
            "iss": "https://auth.example.com",
            "sub": "user",
            "aud": "https://mcp.example.com",
            "exp": time.time() + 300,
            "scope": "tools:read",
        },
        private,
        algorithm="RS256",
        headers={"kid": "test"},
    )
    verifier = JWTVerifier.from_jwks(
        {"keys": [jwk]},
        issuer="https://auth.example.com",
        audience="https://mcp.example.com",
        required_scopes={"tools:read"},
    )
    claims = await verifier.verify(token)
    assert claims.subject == "user"
    with pytest.raises(TokenVerificationError):
        await JWTVerifier.from_jwks(
            {"keys": [jwk]}, issuer="https://wrong.example.com", audience="https://mcp.example.com"
        ).verify(token)
    with pytest.raises(TokenVerificationError):
        await JWTVerifier.from_jwks(
            {"keys": [jwk]}, issuer="https://auth.example.com", audience="https://other.example.com"
        ).verify(token)


@pytest.mark.asyncio
async def test_expiry_algorithm_and_missing_scope_rejected() -> None:
    private, jwk = key_pair()
    expired = jwt.encode(
        {
            "iss": "https://auth.example.com",
            "sub": "user",
            "aud": "https://mcp.example.com",
            "exp": time.time() - 1,
        },
        private,
        algorithm="RS256",
        headers={"kid": "test"},
    )
    verifier = JWTVerifier.from_jwks(
        {"keys": [jwk]},
        issuer="https://auth.example.com",
        audience="https://mcp.example.com",
        required_scopes={"tools:read"},
    )
    with pytest.raises(TokenVerificationError):
        await verifier.verify(expired)
    unsigned = jwt.encode(
        {
            "iss": "https://auth.example.com",
            "sub": "user",
            "aud": "https://mcp.example.com",
            "exp": time.time() + 300,
        },
        key="",
        algorithm="none",
        headers={"kid": "test"},
    )
    with pytest.raises(TokenVerificationError):
        await verifier.verify(unsigned)


def test_challenge_and_metadata_config() -> None:
    header = unauthorized_headers(
        "https://mcp.example.com/.well-known/oauth-protected-resource", {"tools:read"}
    )["WWW-Authenticate"]
    challenge = parse_www_authenticate(header)
    assert challenge.resource_metadata.endswith("oauth-protected-resource")
    config = AuthorizationServerConfig.from_metadata(
        {
            "issuer": "https://auth.example.com",
            "authorization_endpoint": "https://auth.example.com/authorize",
            "token_endpoint": "https://auth.example.com/token",
        }
    )
    assert config.issuer == "https://auth.example.com"


def test_bounded_cache_expiry_and_limit() -> None:
    cache = BoundedTokenCache(max_entries=1, expiry_margin=1)
    cache.put("a", "one", time.time() + 100)
    cache.put("b", "two", time.time() + 100)
    assert cache.get("a") is None
    assert cache.get("b") == "two"
    cache.put("expired", "no", time.time() + 0.1)
    assert cache.get("expired") is None


def test_state_nonce_and_pkce_validation() -> None:
    state = OAuthState.generate()
    assert len(state.code_challenge) > 20
    state.validate_callback(state.state, state.nonce)
    with pytest.raises(ValueError, match="state"):
        state.validate_callback("wrong", state.nonce)
    with pytest.raises(ValueError, match="nonce"):
        state.validate_callback(state.state, "wrong")
    state.validate_callback(
        state.state,
        returned_issuer="https://auth.example.com",
        expected_issuer="https://auth.example.com",
        issuer_parameter_supported=True,
    )
    with pytest.raises(ValueError, match="issuer"):
        state.validate_callback(
            state.state,
            expected_issuer="https://auth.example.com",
            issuer_parameter_supported=True,
        )
