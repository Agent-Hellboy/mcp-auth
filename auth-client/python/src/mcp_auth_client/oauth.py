import base64
import hashlib
import secrets
from dataclasses import dataclass
from urllib.parse import urlencode


@dataclass(frozen=True, slots=True)
class OAuthState:
    state: str
    nonce: str
    code_verifier: str

    @classmethod
    def generate(cls) -> "OAuthState":
        verifier = secrets.token_urlsafe(32)
        return cls(
            state=secrets.token_urlsafe(24),
            nonce=secrets.token_urlsafe(24),
            code_verifier=verifier,
        )

    @property
    def code_challenge(self) -> str:
        digest = hashlib.sha256(self.code_verifier.encode()).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()

    def validate_callback(
        self,
        returned_state: str | None,
        returned_nonce: str | None = None,
        returned_issuer: str | None = None,
        expected_issuer: str | None = None,
        issuer_parameter_supported: bool = False,
    ) -> None:
        if not returned_state or not secrets.compare_digest(returned_state, self.state):
            raise ValueError("OAuth state mismatch")
        if returned_nonce is not None and not secrets.compare_digest(returned_nonce, self.nonce):
            raise ValueError("OAuth nonce mismatch")
        if issuer_parameter_supported and not returned_issuer:
            raise ValueError("OAuth issuer is missing")
        if returned_issuer is not None:
            if expected_issuer is None or not secrets.compare_digest(
                returned_issuer, expected_issuer
            ):
                raise ValueError("OAuth issuer mismatch")


def authorization_url(
    endpoint: str,
    client_id: str,
    redirect_uri: str,
    resource: str,
    scopes: set[str] | frozenset[str],
    oauth_state: OAuthState,
) -> str:
    query = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": " ".join(sorted(scopes)),
        "state": oauth_state.state,
        "nonce": oauth_state.nonce,
        "code_challenge": oauth_state.code_challenge,
        "code_challenge_method": "S256",
        "resource": resource,
    }
    return f"{endpoint}?{urlencode(query)}"
