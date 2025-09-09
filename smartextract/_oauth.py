"""Helper functions to get OAuth tokens."""

import asyncio
import functools
import hashlib
import html
import json
import os
import secrets
import sys
import webbrowser
from base64 import urlsafe_b64decode, urlsafe_b64encode
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, AsyncGenerator, Generator
from urllib.parse import parse_qs, quote, urljoin, urlparse

import httpx

try:
    import platformdirs
    from httpx_oauth.clients.openid import OpenID
    from httpx_oauth.oauth2 import BaseOAuth2, OAuth2Token, RefreshTokenError

except ModuleNotFoundError as err:
    err.add_note("Run `pip install smartextract[oauth]` to enable OAuth login")
    raise


class OAuth2Auth(httpx.Auth):
    """OAuth2 authentication with token cache and interactive login."""

    def __init__(self, base_url: str, token_file: str | Path | None) -> None:
        self._token: OAuth2Token | None = None
        self.base_url = base_url
        if token_file is not None:
            self.token_file = Path(token_file)

    @functools.cached_property
    def oauth_client(self) -> BaseOAuth2:
        return OpenID(
            openid_configuration_endpoint=urljoin(
                self.base_url.replace("api.", "auth."),
                "auth/realms/smartextract/.well-known/openid-configuration",
            ),
            client_id="smartextract-sdk",
            client_secret="",
        )

    @functools.cached_property
    def token_file(self) -> Path:
        data_dir = platformdirs.user_data_path(
            appname="smartextract", ensure_exists=True
        )
        base_name = quote(self.base_url, "")
        return data_dir / f"{base_name}.json"

    @property
    def current_access_token(self) -> str | None:
        """Return an already loaded access token, if not expired.

        Doesn't perform IO.
        """
        token = self._token
        if token is None or token.is_expired():
            return None
        return token["access_token"]

    def sync_auth_flow(
        self, request: httpx.Request
    ) -> Generator[httpx.Request, httpx.Response, None]:
        access_token = self.current_access_token
        if access_token is None:
            access_token = asyncio.run(self.get_access_token())
        request.headers["Authorization"] = f"Bearer {access_token}"
        yield request

    async def async_auth_flow(
        self, request: httpx.Request
    ) -> AsyncGenerator[httpx.Request, httpx.Response]:
        access_token = self.current_access_token
        if access_token is None:
            access_token = await self.get_access_token()
        request.headers["Authorization"] = f"Bearer {access_token}"
        yield request

    def oauth_login_extra_params(self) -> dict[str, Any]:
        params = {"prompt": "login"}
        try:
            access_token = self._token["access_token"]  # type: ignore[index]
            _, encoded, _ = access_token.split(".")
            encoded += "=" * (-len(encoded) % 4)
            payload = json.loads(urlsafe_b64decode(encoded))
            params["login_hint"] = payload["email"]
        except Exception:
            pass
        return params

    async def oauth_login(
        self, listen_host="127.0.0.1", listen_port: int = 0, timeout: int = 120
    ) -> OAuth2Token:
        """Get an OAuth token interactively via web browser."""
        qs: dict | None = None

        class OAuthHandler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                nonlocal qs
                qs = parse_qs(urlparse(self.path).query)

                if "code" in qs:
                    status = 200
                    title = "Authentication successful"
                    text = "You can close this page."
                else:
                    status = 400
                    title = "Authentication failed"
                    text = html.escape(str(qs))
                self.send_response(status)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(
                    f"""\
<!DOCTYPE HTML><html lang="en"><body>
<h1>{title}</h1>{text}
</body></html>
""".encode()
                )

            def log_message(self, *_):
                pass

        pkce_code = secrets.token_urlsafe(96)
        pkce_hash = hashlib.sha256(pkce_code.encode()).digest()
        server = HTTPServer((listen_host, listen_port), OAuthHandler)
        server.timeout = timeout
        _, listen_port = server.socket.getsockname()
        redirect_uri = f"http://{listen_host}:{listen_port}/"
        auth_url = await self.oauth_client.get_authorization_url(
            redirect_uri=redirect_uri,
            code_challenge_method="S256",
            code_challenge=urlsafe_b64encode(pkce_hash).decode().rstrip("="),
            extras_params=self.oauth_login_extra_params(),
        )
        webbrowser.open(auth_url)
        sys.stderr.write(
            "Go to your web browser to log in."
            f" If it doesn't open automatically, please navigate to {auth_url}\n"
        )
        try:
            server.handle_request()
        finally:
            server.server_close()
        try:
            auth_code = qs["code"][0]  # type: ignore[index]
        except Exception:
            raise RuntimeError("Error getting authorization code", qs) from None
        return await self.oauth_client.get_access_token(
            auth_code, redirect_uri, pkce_code
        )

    async def oauth_logout(self):
        token = self.load_token()
        if token is not None:
            await self.oauth_client.revoke_token(token["refresh_token"])
            os.unlink(self.token_file)

    async def get_access_token(self) -> str:
        """Get a valid access token, possibly via refresh or a new login."""
        # Look for a good token on disk
        token = self.load_token()
        if token is not None:
            self._token = token
            if not token.is_expired():
                return token["access_token"]

        # Attempt to refresh the token
        if token is not None and "refresh_token" in token:
            try:
                token = await self.oauth_client.refresh_token(token["refresh_token"])
                self._token = token
                self.save_token(token)
                return token["access_token"]
            except RefreshTokenError:
                pass

        # Attempt a new login
        token = await self.oauth_login()
        self._token = token
        self.save_token(token)
        return token["access_token"]

    def load_token(self) -> OAuth2Token | None:
        try:
            with open(self.token_file) as f:
                return OAuth2Token(json.load(f).items())
        except FileNotFoundError:
            return None

    def save_token(self, token) -> None:
        with open(self.token_file, "w") as f:
            json.dump(token, f)
