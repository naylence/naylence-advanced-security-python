"""
Auth Policy Server - Authorization Policy HTTP endpoint

Provides authorization policies via HTTP using FastAPI.
Supports OAuth2 JWT authentication and ETag-based caching.
Serves multiple policies by ID from a configurable directory.
This is a development server for testing HTTP policy source functionality.

Policy files should be named: policy-{policy_id}.yaml or policy-{policy_id}.json
Example: policy-production.yaml, policy-dev.json

Authentication:
    Set FAME_OAUTH2_ISSUER to enable OAuth2 JWT validation
    Optionally set FAME_OAUTH2_AUDIENCE, FAME_OAUTH2_JWKS_URL
    If no OAuth2 config provided, authentication is disabled (dev mode)

Environment variables:
    FAME_APP_HOST - Host to bind to (default: 0.0.0.0)
    FAME_APP_PORT - Port to listen on (default: 8099)
    FAME_POLICY_DIR - Directory containing policy files
    FAME_OAUTH2_ISSUER - OAuth2 issuer URL (enables JWT auth)
    FAME_OAUTH2_AUDIENCE - Expected audience claim
    FAME_OAUTH2_JWKS_URL - JWKS endpoint URL (defaults to issuer/.well-known/jwks.json)
    FAME_OAUTH2_REQUIRED_SCOPES - Comma-separated list of required scopes
    FAME_OAUTH2_ALGORITHMS - Comma-separated JWT algorithms (default: RS256,ES256,EdDSA)
    FAME_LOG_LEVEL - Log level (debug, info, warning, error)

Usage:
    python -m naylence.fame.security.auth.policy.auth_policy_server
    FAME_POLICY_DIR=./policies FAME_OAUTH2_ISSUER=https://auth.example.com python -m ...
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

import uvicorn
import yaml
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from watchdog.events import FileSystemEventHandler

from naylence.fame.util.logging import enable_logging, getLogger

ENV_VAR_LOG_LEVEL = "FAME_LOG_LEVEL"
ENV_VAR_FAME_APP_HOST = "FAME_APP_HOST"
ENV_VAR_FAME_APP_PORT = "FAME_APP_PORT"
ENV_VAR_FAME_POLICY_DIR = "FAME_POLICY_DIR"
# OAuth2 configuration
ENV_VAR_OAUTH2_ISSUER = "FAME_OAUTH2_ISSUER"
ENV_VAR_OAUTH2_AUDIENCE = "FAME_OAUTH2_AUDIENCE"
ENV_VAR_OAUTH2_JWKS_URL = "FAME_OAUTH2_JWKS_URL"
ENV_VAR_OAUTH2_REQUIRED_SCOPES = "FAME_OAUTH2_REQUIRED_SCOPES"
ENV_VAR_OAUTH2_ALGORITHMS = "FAME_OAUTH2_ALGORITHMS"

# Default algorithms for JWT verification (matches @naylence/runtime defaults)
DEFAULT_JWT_ALGORITHMS = ["RS256", "ES256", "EdDSA"]

# Policy file naming pattern: policy-{id}.yaml or policy-{id}.json
POLICY_FILE_PATTERN = re.compile(r"^policy-(.+)\.(ya?ml|json)$", re.IGNORECASE)

enable_logging(log_level=os.getenv(ENV_VAR_LOG_LEVEL, "warning"))
logger = getLogger(__name__)

# Default authorization policy for development
# Allows all operations - suitable for testing only
DEFAULT_POLICY: dict[str, Any] = {
    "version": "1",
    "type": "AdvancedAuthorizationPolicy",
    "default_effect": "deny",
    "rules": [
        {
            "id": "allow-all-dev",
            "effect": "allow",
            "comment": "Development policy - allows all operations",
        },
    ],
}


class PolicyEntry:
    """A single policy entry with metadata."""

    def __init__(
        self,
        policy_id: str,
        policy: dict[str, Any],
        policy_content: str,
        etag: str,
        last_modified: datetime,
        file_path: str,
        format: str,  # "yaml" or "json"
    ):
        self.id = policy_id
        self.policy = policy
        self.policy_content = policy_content
        self.etag = etag
        self.last_modified = last_modified
        self.file_path = file_path
        self.format = format


class PolicyServerState:
    """State container for the policy server."""

    def __init__(self, policy_dir: str | None = None):
        self.policy_dir = policy_dir
        self.policies: dict[str, PolicyEntry] = {}


def compute_etag(content: str) -> str:
    """Compute ETag from content using SHA-256."""
    digest = hashlib.sha256(content.encode()).hexdigest()[:16]
    return f'"{digest}"'


def extract_policy_id(filename: str) -> tuple[str, str] | None:
    """
    Extract policy ID and format from filename.
    Expected format: policy-{id}.yaml or policy-{id}.json
    Returns (id, format) tuple or None if not a valid policy file.
    """
    match = POLICY_FILE_PATTERN.match(filename)
    if not match:
        return None
    policy_id = match.group(1)
    ext = match.group(2).lower()
    format = "json" if ext == "json" else "yaml"
    return (policy_id, format)


def load_policy_file(file_path: Path) -> PolicyEntry | None:
    """Load a single policy from file."""
    try:
        content = file_path.read_text(encoding="utf-8")
        ext = file_path.suffix.lower()

        if ext == ".json":
            policy = json.loads(content)
            format = "json"
        else:
            policy = yaml.safe_load(content)
            format = "yaml"

        stat = file_path.stat()
        last_modified = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)

        # Extract ID from filename
        parsed = extract_policy_id(file_path.name)
        if not parsed:
            return None

        policy_id, _ = parsed

        return PolicyEntry(
            policy_id=policy_id,
            policy=policy,
            policy_content=content,
            etag=compute_etag(content),
            last_modified=last_modified,
            file_path=str(file_path),
            format=format,
        )
    except Exception as e:
        logger.error("policy_file_load_error", path=str(file_path), error=str(e))
        return None


def load_policies_from_dir(dir_path: str) -> dict[str, PolicyEntry]:
    """Load all policies from a directory."""
    policies: dict[str, PolicyEntry] = {}
    path = Path(dir_path)

    if not path.exists():
        logger.warning("policy_directory_not_found", path=dir_path)
        return policies

    for file_path in path.iterdir():
        if not file_path.is_file():
            continue

        parsed = extract_policy_id(file_path.name)
        if not parsed:
            continue

        entry = load_policy_file(file_path)
        if entry:
            policies[entry.id] = entry
            logger.info("policy_loaded", id=entry.id, path=str(file_path))

    return policies


def create_default_policy_entry() -> PolicyEntry:
    """Create a default policy entry."""
    content = json.dumps(DEFAULT_POLICY, indent=2)
    return PolicyEntry(
        policy_id="default",
        policy=DEFAULT_POLICY,
        policy_content=content,
        etag=compute_etag(content),
        last_modified=datetime.now(tz=timezone.utc),
        file_path="(built-in)",
        format="json",
    )


class PolicyFileEventHandler(FileSystemEventHandler):
    """Handle file system events for policy directory watching."""

    def __init__(self, state: PolicyServerState):
        self.state = state

    def _handle_file_change(self, file_path: str) -> None:
        path = Path(file_path)
        parsed = extract_policy_id(path.name)
        if not parsed:
            return

        policy_id, _ = parsed

        if path.exists():
            entry = load_policy_file(path)
            if entry:
                self.state.policies[policy_id] = entry
                logger.info("policy_reloaded", id=policy_id, path=file_path)
        else:
            if policy_id in self.state.policies:
                del self.state.policies[policy_id]
                logger.info("policy_removed", id=policy_id)

    def on_modified(self, event):
        if not event.is_directory:
            src_path = event.src_path if isinstance(event.src_path, str) else event.src_path.decode()
            self._handle_file_change(src_path)

    def on_created(self, event):
        if not event.is_directory:
            src_path = event.src_path if isinstance(event.src_path, str) else event.src_path.decode()
            self._handle_file_change(src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            src_path = event.src_path if isinstance(event.src_path, str) else event.src_path.decode()
            self._handle_file_change(src_path)


class TokenVerifier(Protocol):
    """Protocol for token verifiers."""

    async def verify(self, token: str) -> dict[str, Any]:
        """Verify a token and return its claims."""
        ...


async def create_token_verifier() -> TokenVerifier | None:
    """Create an OAuth2 token verifier from environment configuration."""
    issuer = os.getenv(ENV_VAR_OAUTH2_ISSUER)
    if not issuer:
        return None

    try:
        # Dynamically import the token verifier factory from naylence.fame.security.auth
        from naylence.fame.security.auth.token_verifier_factory import (
            TokenVerifierFactory,
        )

        jwks_url = os.getenv(ENV_VAR_OAUTH2_JWKS_URL) or f"{issuer.rstrip('/')}/.well-known/jwks.json"
        audience = os.getenv(ENV_VAR_OAUTH2_AUDIENCE)

        # Parse algorithms from environment or use defaults
        algorithms_env = os.getenv(ENV_VAR_OAUTH2_ALGORITHMS)
        if algorithms_env:
            algorithms = [a.strip() for a in algorithms_env.split(",") if a.strip()]
        else:
            algorithms = DEFAULT_JWT_ALGORITHMS

        config: dict[str, Any] = {
            "type": "JWKSJWTTokenVerifier",
            "issuer": issuer,
            "jwks_url": jwks_url,
            "algorithms": algorithms,
        }

        if audience:
            config["audience"] = audience

        verifier = await TokenVerifierFactory.create_token_verifier(config)
        logger.info("oauth2_token_verifier_created", issuer=issuer, jwks_url=jwks_url)
        return verifier
    except Exception as e:
        logger.error("failed_to_create_token_verifier", error=str(e))
        return None


# Global state - will be initialized in lifespan
_state: PolicyServerState | None = None
_token_verifier: TokenVerifier | None = None

# Optional bearer auth
security = HTTPBearer(auto_error=False)


async def verify_jwt_token(
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
) -> dict[str, Any] | None:
    """Verify JWT token if authentication is enabled."""
    if not _token_verifier:
        # No auth required (dev mode)
        return None

    if not credentials:
        raise HTTPException(
            status_code=401,
            detail={"error": "unauthorized", "message": "Missing Authorization header"},
        )

    try:
        claims = await _token_verifier.verify(credentials.credentials)

        # Check required scopes if configured
        required_scopes_env = os.getenv(ENV_VAR_OAUTH2_REQUIRED_SCOPES)
        if required_scopes_env:
            required_scopes = [s.strip() for s in required_scopes_env.split(",")]
            token_scopes: list[str] = []

            if isinstance(claims.get("scope"), str):
                token_scopes = claims["scope"].split(" ")
            elif isinstance(claims.get("scp"), list):
                token_scopes = claims["scp"]

            missing = [s for s in required_scopes if s not in token_scopes]
            if missing:
                raise HTTPException(
                    status_code=403,
                    detail={
                        "error": "forbidden",
                        "message": f"Missing required scopes: {', '.join(missing)}",
                    },
                )

        logger.debug("jwt_token_verified", sub=claims.get("sub"))
        return claims
    except HTTPException:
        raise
    except Exception as e:
        logger.warning("jwt_verification_failed", error=str(e))
        raise HTTPException(
            status_code=401,
            detail={"error": "unauthorized", "message": str(e)},
        )


# Directory watcher
_observer = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager for the policy server."""
    global _state, _token_verifier, _observer

    # Load policies from directory or use default
    policy_dir = os.getenv(ENV_VAR_FAME_POLICY_DIR)

    _state = PolicyServerState(policy_dir=policy_dir)

    if policy_dir and Path(policy_dir).exists():
        _state.policies = load_policies_from_dir(policy_dir)

        # Set up directory watcher
        from watchdog.observers import Observer

        event_handler = PolicyFileEventHandler(_state)
        _observer = Observer()
        assert _observer is not None  # Type narrowing for pyright
        _observer.schedule(event_handler, policy_dir, recursive=False)
        _observer.start()
        logger.info("watching_policy_directory", path=policy_dir)

    # Always add default policy if no policies found
    if not _state.policies:
        _state.policies["default"] = create_default_policy_entry()
        logger.info(
            "using_default_policy",
            reason="no_policies_found_in_directory" if policy_dir else "no_directory_specified",
        )

    # Create OAuth2 token verifier if configured
    _token_verifier = await create_token_verifier()

    if _token_verifier:
        logger.info("oauth2_jwt_auth_enabled", issuer=os.getenv(ENV_VAR_OAUTH2_ISSUER))
    else:
        logger.warning(
            "auth_disabled",
            message="Set FAME_OAUTH2_ISSUER to enable OAuth2 JWT authentication",
        )

    yield

    # Cleanup
    if _observer:
        _observer.stop()
        _observer.join()
        _observer = None
    _state = None
    _token_verifier = None


def create_app() -> FastAPI:
    """Create and return a FastAPI application for serving policies."""
    app = FastAPI(
        title="Auth Policy Server",
        description="Development server for serving authorization policies by ID",
        lifespan=lifespan,
    )

    @app.get("/fame/v1/auth-policies", dependencies=[Depends(verify_jwt_token)])
    async def list_policies():
        """List all available policies."""
        if not _state:
            raise HTTPException(status_code=500, detail="Server not initialized")

        policy_list = [
            {
                "id": entry.id,
                "lastModified": entry.last_modified.isoformat(),
                "format": entry.format,
            }
            for entry in _state.policies.values()
        ]

        return {"policies": policy_list}

    @app.get(
        "/fame/v1/auth-policies/{policy_id}",
        dependencies=[Depends(verify_jwt_token)],
    )
    async def get_policy(policy_id: str, request: Request):
        """Get authorization policy by ID."""
        if not _state:
            raise HTTPException(status_code=500, detail="Server not initialized")

        entry = _state.policies.get(policy_id)
        if not entry:
            raise HTTPException(
                status_code=404,
                detail={
                    "error": "not_found",
                    "message": f"Policy '{policy_id}' not found",
                    "availablePolicies": list(_state.policies.keys()),
                },
            )

        # Check ETag for conditional request
        if_none_match = request.headers.get("if-none-match")
        if if_none_match and if_none_match == entry.etag:
            return Response(
                status_code=304,
                headers={
                    "ETag": entry.etag,
                    "Cache-Control": "public, max-age=60, stale-while-revalidate=300",
                },
            )

        # Determine content type based on Accept header or original format
        accept_header = request.headers.get("accept", "")
        is_yaml_request = "yaml" in accept_header or "text/plain" in accept_header

        if is_yaml_request or entry.format == "yaml":
            content_type = "application/yaml"
            response_body = (
                entry.policy_content
                if entry.format == "yaml"
                else yaml.dump(entry.policy, default_flow_style=False)
            )
        else:
            content_type = "application/json"
            response_body = json.dumps(entry.policy, indent=2)

        return Response(
            content=response_body,
            media_type=content_type,
            headers={
                "ETag": entry.etag,
                "Last-Modified": entry.last_modified.strftime(
                    "%a, %d %b %Y %H:%M:%S GMT"
                ),
                "Cache-Control": "public, max-age=60, stale-while-revalidate=300",
            },
        )

    @app.get(
        "/fame/v1/auth-policies/{policy_id}.yaml",
        dependencies=[Depends(verify_jwt_token)],
    )
    async def get_policy_yaml(policy_id: str, request: Request):
        """Get authorization policy by ID in YAML format."""
        if not _state:
            raise HTTPException(status_code=500, detail="Server not initialized")

        entry = _state.policies.get(policy_id)
        if not entry:
            raise HTTPException(
                status_code=404,
                detail={"error": "not_found", "message": f"Policy '{policy_id}' not found"},
            )

        if_none_match = request.headers.get("if-none-match")
        if if_none_match and if_none_match == entry.etag:
            return Response(
                status_code=304,
                headers={
                    "ETag": entry.etag,
                    "Cache-Control": "public, max-age=60, stale-while-revalidate=300",
                },
            )

        yaml_content = (
            entry.policy_content
            if entry.format == "yaml"
            else yaml.dump(entry.policy, default_flow_style=False)
        )

        return Response(
            content=yaml_content,
            media_type="application/yaml",
            headers={
                "ETag": entry.etag,
                "Last-Modified": entry.last_modified.strftime(
                    "%a, %d %b %Y %H:%M:%S GMT"
                ),
                "Cache-Control": "public, max-age=60, stale-while-revalidate=300",
            },
        )

    @app.get(
        "/fame/v1/auth-policies/{policy_id}.json",
        dependencies=[Depends(verify_jwt_token)],
    )
    async def get_policy_json(policy_id: str, request: Request):
        """Get authorization policy by ID in JSON format."""
        if not _state:
            raise HTTPException(status_code=500, detail="Server not initialized")

        entry = _state.policies.get(policy_id)
        if not entry:
            raise HTTPException(
                status_code=404,
                detail={"error": "not_found", "message": f"Policy '{policy_id}' not found"},
            )

        if_none_match = request.headers.get("if-none-match")
        if if_none_match and if_none_match == entry.etag:
            return Response(
                status_code=304,
                headers={
                    "ETag": entry.etag,
                    "Cache-Control": "public, max-age=60, stale-while-revalidate=300",
                },
            )

        return Response(
            content=json.dumps(entry.policy, indent=2),
            media_type="application/json",
            headers={
                "ETag": entry.etag,
                "Last-Modified": entry.last_modified.strftime(
                    "%a, %d %b %Y %H:%M:%S GMT"
                ),
                "Cache-Control": "public, max-age=60, stale-while-revalidate=300",
            },
        )

    @app.get("/health")
    async def health_check():
        """Health check endpoint."""
        return {
            "status": "healthy",
            "service": "auth-policy-server",
            "policyDirectory": _state.policy_dir if _state else "(not initialized)",
            "policyCount": len(_state.policies) if _state else 0,
            "policies": list(_state.policies.keys()) if _state else [],
        }

    return app


def main():
    """Main entry point for the auth policy server."""
    app = create_app()
    host = os.getenv(ENV_VAR_FAME_APP_HOST, "0.0.0.0")
    port = int(os.getenv(ENV_VAR_FAME_APP_PORT, "8099"))

    policy_dir = os.getenv(ENV_VAR_FAME_POLICY_DIR)
    oauth2_issuer = os.getenv(ENV_VAR_OAUTH2_ISSUER)

    print(f"\n📍 Auth Policy Server listening on http://{host}:{port}")
    print(f"📋 List policies: http://{host}:{port}/fame/v1/auth-policies")
    print(f"📋 Get policy: http://{host}:{port}/fame/v1/auth-policies/{{policy_id}}")
    print(f"📋 Get as YAML: http://{host}:{port}/fame/v1/auth-policies/{{policy_id}}.yaml")
    print(f"📋 Get as JSON: http://{host}:{port}/fame/v1/auth-policies/{{policy_id}}.json")
    print(f"🔍 Health check: http://{host}:{port}/health")
    if policy_dir:
        print(f"📁 Serving policies from: {policy_dir}")
        print("📁 Policy files should be named: policy-{id}.yaml or policy-{id}.json")
    else:
        print("⚠️  No policy directory set (set FAME_POLICY_DIR to serve custom policies)")
    if oauth2_issuer:
        print(f"🔐 OAuth2 JWT authentication enabled (issuer: {oauth2_issuer})")
    else:
        print("⚠️  No authentication (set FAME_OAUTH2_ISSUER to enable)")
    print("")

    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()
