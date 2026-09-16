"""Reusable OAuth helpers for Python MCP resource servers."""

from .boundaries import DownstreamToken, MCPClientToken, ResourceServerCredential
from .challenge import ProtectedResourceChallenge, unauthorized_headers
from .discovery import discover_authorization_server, discover_protected_resource
from .fastmcp import RemoteAuthProvider
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
    "unauthorized_headers",
    "authorization_url",
]
