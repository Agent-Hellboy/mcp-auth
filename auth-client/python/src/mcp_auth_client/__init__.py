"""Reusable OAuth helpers for Python MCP resource servers."""

from .boundaries import DownstreamToken, MCPClientToken, ResourceServerCredential
from .challenge import ProtectedResourceChallenge, parse_www_authenticate, unauthorized_headers
from .discovery import discover_authorization_server, discover_protected_resource
from .fastmcp import RemoteAuthProvider
from .http import AsyncHTTPClient
from .models import AuthorizationServerConfig, ProtectedResourceConfig
from .oauth import OAuthState, authorization_url
from .token_exchange import (
    PrivateKeyJWTClientAuth,
    TokenExchangeClient,
    TokenSet,
)
from .verifier import JWTVerifier, TokenClaims, TokenVerificationError

__all__ = [
    "AuthorizationServerConfig",
    "AsyncHTTPClient",
    "DownstreamToken",
    "JWTVerifier",
    "MCPClientToken",
    "OAuthState",
    "PrivateKeyJWTClientAuth",
    "ProtectedResourceChallenge",
    "ProtectedResourceConfig",
    "RemoteAuthProvider",
    "ResourceServerCredential",
    "TokenClaims",
    "TokenExchangeClient",
    "TokenSet",
    "TokenVerificationError",
    "discover_authorization_server",
    "discover_protected_resource",
    "parse_www_authenticate",
    "unauthorized_headers",
    "authorization_url",
]
