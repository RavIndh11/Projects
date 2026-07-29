import uuid
import time
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from app.models.schemas import AnalyzeRequest, AnalyzeResponse, DetectionResult
from app.security.analyzer import PromptAnalyzer
from app.core.logger import logger

app = FastAPI(
    title="LLM Prompt Guard",
    description="Security proxy to analyze and block LLM prompt injections and jailbreaks.",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time

    logger.info(
        "Request processed",
        extra={
            "extra_data": {
                "method": request.method,
                "url": str(request.url),
                "status_code": response.status_code,
                "process_time": f"{process_time:.4f}s"
            }
        }
    )
    return response

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

@app.post("/api/v1/analyze", response_model=AnalyzeResponse)
async def analyze_prompt(request: AnalyzeRequest):
    request_id = str(uuid.uuid4())

    try:
        # Full prompt analysis including any context
        full_text = request.prompt
        if request.context:
            full_text = f"{request.context}\n{request.prompt}"

        result = PromptAnalyzer.analyze(full_text)

        response = AnalyzeResponse(
            request_id=request_id,
            prompt_length=len(request.prompt),
            result=result,
            metadata={"context_provided": bool(request.context)}
        )

        # Log the analysis result
        logger.info(
            "Prompt analysis completed",
            extra={
                "extra_data": {
                    "request_id": request_id,
                    "is_malicious": result.is_malicious,
                    "score": result.score,
                    "severity": result.severity,
                    "reasons": result.reasons
                }
            }
        )

        return response

    except Exception as e:
        logger.error(f"Analysis failed: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error during analysis")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
