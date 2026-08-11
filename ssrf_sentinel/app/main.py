import asyncio
import ipaddress
import socket
from urllib.parse import urlparse
import httpx
from fastapi import FastAPI, HTTPException, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
import logging
from pythonjsonlogger import jsonlogger

app = FastAPI(title="SSRF Sentinel", description="An SSRF-safe proxy with DNS Rebinding prevention.")
templates = Jinja2Templates(directory="app/templates")

logger = logging.getLogger(__name__)
logHandler = logging.StreamHandler()
formatter = jsonlogger.JsonFormatter('%(asctime)s %(levelname)s %(name)s %(message)s')
logHandler.setFormatter(formatter)
logger.addHandler(logHandler)
logger.setLevel(logging.INFO)

def is_safe_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_loopback:
            return False
        if ip.is_private:
            return False
        if ip.is_link_local:
            return False
        if ip.is_multicast:
            return False
        if ip.is_unspecified:
            return False
        if ip.is_reserved:
            return False
        if str(ip) == "169.254.169.254":
            return False
        return True
    except ValueError:
        return False

async def resolve_and_check(hostname: str) -> str:
    try:
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(hostname, None, family=socket.AF_INET)
        ip = infos[0][4][0]
        if not is_safe_ip(ip):
            raise ValueError(f"Resolved IP {ip} is not safe.")
        return ip
    except ValueError as ve:
        raise ve
    except Exception:
        raise ValueError(f"Could not resolve hostname {hostname}.")

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(request=request, name="index.html", context={"request": request})

@app.post("/fetch")
async def fetch_url(request: Request, url: str = Form(...)):
    logger.info("Received request to fetch URL", extra={"url": url})
    try:
        parsed_url = urlparse(url)
        if parsed_url.scheme not in ["http", "https"]:
            raise ValueError("Invalid scheme. Only http and https are allowed.")

        hostname = parsed_url.hostname
        if not hostname:
            raise ValueError("Invalid URL. Hostname is missing.")

        ip = await resolve_and_check(hostname)

        port = f":{parsed_url.port}" if parsed_url.port else ""
        path = parsed_url.path if parsed_url.path else "/"
        query = f"?{parsed_url.query}" if parsed_url.query else ""

        target_url = f"{parsed_url.scheme}://{ip}{port}{path}{query}"

        headers = {"Host": hostname}

        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(target_url, headers=headers, follow_redirects=False)

            return templates.TemplateResponse(request=request, name="index.html", context={
                "request": request,
                "url": url,
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "content": response.text[:2000] # truncate
            })

    except ValueError as e:
        logger.warning("SSRF Check failed", extra={"url": url, "error": str(e)})
        return templates.TemplateResponse(request=request, name="index.html", context={
            "request": request,
            "url": url,
            "error": str(e)
        })
    except Exception as e:
        logger.error("Error fetching URL", extra={"url": url, "error": str(e)})
        return templates.TemplateResponse(request=request, name="index.html", context={
            "request": request,
            "url": url,
            "error": f"Failed to fetch URL: {str(e)}"
        })
