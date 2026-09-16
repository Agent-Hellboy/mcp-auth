from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class AuthorizationServerConfig:
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str | None = None
    registration_endpoint: str | None = None
    revocation_endpoint: str | None = None
    authorization_response_iss_parameter_supported: bool = False
    scopes_supported: frozenset[str] = field(default_factory=frozenset)
    token_endpoint_auth_methods_supported: frozenset[str] = field(default_factory=frozenset)

    @classmethod
    def from_metadata(cls, metadata: dict[str, object]) -> "AuthorizationServerConfig":
        def text(name: str, required: bool = True) -> str | None:
            value = metadata.get(name)
            if not isinstance(value, str) and required:
                raise ValueError(f"authorization metadata is missing {name}")
            return value if isinstance(value, str) else None

        scopes = metadata.get("scopes_supported", [])
        methods = metadata.get("token_endpoint_auth_methods_supported", [])
        issuer_parameter = metadata.get("authorization_response_iss_parameter_supported", False)
        return cls(
            issuer=text("issuer") or "",
            authorization_endpoint=text("authorization_endpoint") or "",
            token_endpoint=text("token_endpoint") or "",
            jwks_uri=text("jwks_uri", required=False),
            registration_endpoint=text("registration_endpoint", required=False),
            revocation_endpoint=text("revocation_endpoint", required=False),
            authorization_response_iss_parameter_supported=issuer_parameter is True,
            scopes_supported=frozenset(x for x in scopes if isinstance(x, str))
            if isinstance(scopes, list)
            else frozenset(),
            token_endpoint_auth_methods_supported=frozenset(
                x for x in methods if isinstance(x, str)
            )
            if isinstance(methods, list)
            else frozenset(),
        )


@dataclass(frozen=True, slots=True)
class ProtectedResourceConfig:
    resource: str
    authorization_servers: tuple[str, ...]
    scopes_supported: frozenset[str] = field(default_factory=frozenset)

    @classmethod
    def from_metadata(cls, metadata: dict[str, object]) -> "ProtectedResourceConfig":
        resource = metadata.get("resource")
        servers = metadata.get("authorization_servers")
        if (
            not isinstance(resource, str)
            or not isinstance(servers, list)
            or not all(isinstance(x, str) for x in servers)
        ):
            raise ValueError("invalid protected resource metadata")
        scopes = metadata.get("scopes_supported", [])
        return cls(
            resource,
            tuple(servers),
            frozenset(x for x in scopes if isinstance(x, str))
            if isinstance(scopes, list)
            else frozenset(),
        )
