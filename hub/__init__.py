"""Agent Context Hub core service: anonymous liveness, everything else authenticated.

The operator UI (hub/ui.py) is mounted only when a stack declares HUB_UI=1 or auth (stacks/*.env).
"""

import os

from fastapi import FastAPI

from hub import api, tools

# Interactive docs would be anonymous endpoints; only /health/live is.
app = FastAPI(
    title="Agent Context Hub",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=tools.lifespan,
)


@app.get("/health/live")
def live():
    return {"status": "ok"}


api.install(app)
app.add_route("/mcp", tools.Endpoint(), methods=["GET", "POST", "DELETE"])

if os.environ.get("HUB_UI") in ("1", "auth"):
    from fastapi.responses import RedirectResponse

    from hub import ui

    app.include_router(ui.router)
    app.add_api_route("/", lambda: RedirectResponse("/ui"), include_in_schema=False)
