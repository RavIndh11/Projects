import json
import os
from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.responses import StreamingResponse
import httpx
from src.logger import logger
from src.security import check_container_create, check_read_only_mode, SecurityViolation

app = FastAPI(title="Docker Socket Guard", description="A security proxy for the Docker socket.")

DOCKER_SOCKET_PATH = os.environ.get("DOCKER_SOCKET_PATH", "/var/run/docker.sock")
transport = httpx.AsyncHTTPTransport(uds=DOCKER_SOCKET_PATH)
client = httpx.AsyncClient(transport=transport, base_url="http://localhost")

@app.on_event("shutdown")
async def shutdown_event():
    if not os.environ.get("TESTING"):
        await client.aclose()

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def proxy_to_docker(path: str, request: Request):
    logger.info(f"Received {request.method} request for /{path}")

    try:
        check_read_only_mode(request.method)
    except SecurityViolation as e:
        raise HTTPException(status_code=403, detail=str(e))

    body = await request.body()

    # Path inside api_route with {path:path} won't have a leading slash
    if request.method == "POST" and path.endswith("containers/create"):
        if body:
            try:
                payload = json.loads(body)
                check_container_create(payload)
            except json.JSONDecodeError:
                raise HTTPException(status_code=400, detail="Invalid JSON payload")
            except SecurityViolation as e:
                raise HTTPException(status_code=403, detail=str(e))

    url = httpx.URL(path=f"/{path}", query=request.url.query.encode("utf-8"))

    headers = dict(request.headers)
    headers.pop("host", None)

    req = client.build_request(
        method=request.method,
        url=url,
        headers=headers,
        content=body,
    )

    try:
        resp = await client.send(req, stream=True)

        async def response_generator():
            async for chunk in resp.aiter_raw():
                yield chunk
            await resp.aclose()

        excluded_headers = ["content-encoding", "content-length", "transfer-encoding", "connection"]
        resp_headers = {k: v for k, v in resp.headers.items() if k.lower() not in excluded_headers}

        return StreamingResponse(
            response_generator(),
            status_code=resp.status_code,
            headers=resp_headers
        )

    except httpx.RequestError as e:
        logger.error(f"Error communicating with Docker socket: {e}")
        raise HTTPException(status_code=502, detail="Error communicating with Docker daemon")
