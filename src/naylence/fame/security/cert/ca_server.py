import os
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, HTTPException, Request, Response

from naylence.fame.security.cert.ca_service_factory import CAServiceFactory
from naylence.fame.util.logging import enable_logging

from .ca_fastapi_router import create_ca_router

ENV_VAR_LOG_LEVEL = "FAME_LOG_LEVEL"
ENV_VAR_FAME_APP_HOST = "FAME_APP_HOST"
ENV_VAR_FAME_APP_PORT = "FAME_APP_PORT"

enable_logging(log_level=os.getenv(ENV_VAR_LOG_LEVEL, "warning"))


@asynccontextmanager
async def lifespan(app: FastAPI):
    ca_service = await CAServiceFactory.create_ca_service()
    app.include_router(create_ca_router(ca_service=ca_service))

    # Register trust bundle endpoint at app root level (not under router prefix)
    @app.get("/.well-known/naylence/trust-bundle.json")
    async def get_trust_bundle(request: Request):
        """Serve the trust bundle at the well-known location."""
        import hashlib

        bundle = await ca_service.get_trust_bundle()
        if bundle is None:
            raise HTTPException(status_code=404, detail={"error": "trust_bundle_unavailable"})

        # Serialize with camelCase field names and exclude None values
        payload = bundle.model_dump_json(by_alias=True, exclude_none=True)
        etag_hash = hashlib.sha256(payload.encode()).hexdigest()[:16]
        etag = f'"{etag_hash}"'

        # Check if client has cached version
        request_etag = request.headers.get("if-none-match")
        if request_etag:
            clean_request_etag = request_etag.replace("W/", "").strip('"')
            clean_etag = etag.strip('"')
            if clean_request_etag == clean_etag:
                return Response(
                    status_code=304,
                    headers={
                        "ETag": etag,
                        "Cache-Control": "public, max-age=3600, stale-while-revalidate=86400",
                    },
                )

        return Response(
            content=payload,
            media_type="application/json",
            headers={
                "ETag": etag,
                "Cache-Control": "public, max-age=3600, stale-while-revalidate=86400",
            },
        )

    yield


def create_app() -> FastAPI:
    """Create and return a FastAPI application with CA service."""
    return FastAPI(lifespan=lifespan)


if __name__ == "__main__":
    app = create_app()
    host = os.getenv(ENV_VAR_FAME_APP_HOST, "0.0.0.0")
    port = int(os.getenv(ENV_VAR_FAME_APP_PORT, 8091))
    uvicorn.run(app, host=host, port=port, log_level="info")
