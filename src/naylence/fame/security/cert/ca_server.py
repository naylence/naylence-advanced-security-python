import os
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI

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
    yield


if __name__ == "__main__":
    app = FastAPI(lifespan=lifespan)
    host = os.getenv(ENV_VAR_FAME_APP_HOST, "0.0.0.0")
    port = int(os.getenv(ENV_VAR_FAME_APP_PORT, 8091))
    uvicorn.run(app, host=host, port=port, log_level="info")
