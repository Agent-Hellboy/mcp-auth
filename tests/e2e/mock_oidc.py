"""Minimal local OIDC issuer used only by the Compose E2E."""

import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlencode, urlsplit

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
CODES: dict[str, dict[str, str]] = {}
ISSUER = "http://mock-oidc:8082"
JWK = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(KEY.public_key()))
JWK.update({"kid": "mock-oidc-key", "use": "sig", "alg": "RS256"})


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        if parsed.path == "/jwks":
            self.write_json(200, {"keys": [JWK]})
            return
        if parsed.path == "/healthz":
            self.write_json(200, {"status": "ok"})
            return
        if parsed.path == "/authorize":
            query = parse_qs(parsed.query)
            code = f"code-{len(CODES) + 1}"
            CODES[code] = {
                "client_id": query["client_id"][0],
                "redirect_uri": query["redirect_uri"][0],
                "nonce": query["nonce"][0],
            }
            location = (
                CODES[code]["redirect_uri"]
                + "?"
                + urlencode({"code": code, "state": query["state"][0]})
            )
            self.send_response(302)
            self.send_header("Location", location)
            self.end_headers()
            return
        self.send_error(404)

    def do_POST(self) -> None:  # noqa: N802
        if urlsplit(self.path).path != "/token":
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", "0"))
        form = parse_qs(self.rfile.read(length).decode())
        grant_type = form.get("grant_type", [""])[0]
        now = int(time.time())
        if grant_type == "urn:ietf:params:oauth:grant-type:token-exchange":
            if not form.get("subject_token", [""])[0] or not form.get("audience", [""])[0]:
                self.write_json(400, {"error": "invalid_target"})
                return
            token = jwt.encode(
                {
                    "iss": ISSUER,
                    "sub": "compose-user",
                    "aud": form["audience"][0],
                    "iat": now,
                    "exp": now + 300,
                },
                KEY,
                algorithm="RS256",
                headers={"kid": "mock-oidc-key"},
            )
            self.write_json(200, {"access_token": token, "token_type": "Bearer", "expires_in": 300})
            return
        code = form.get("code", [""])[0]
        record = CODES.pop(code, None)
        if record is None or form.get("client_id", [""])[0] != record["client_id"]:
            self.write_json(400, {"error": "invalid_grant"})
            return
        token = jwt.encode(
            {
                "iss": ISSUER,
                "sub": "compose-user",
                "aud": record["client_id"],
                "nonce": record["nonce"],
                "iat": now,
                "exp": now + 300,
            },
            KEY,
            algorithm="RS256",
            headers={"kid": "mock-oidc-key"},
        )
        self.write_json(200, {"id_token": token, "access_token": "compose-upstream-access"})

    def write_json(self, status: int, value: object) -> None:
        body = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        return


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8082), Handler).serve_forever()
