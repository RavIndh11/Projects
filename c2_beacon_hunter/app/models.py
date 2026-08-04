from pydantic import BaseModel, Field, IPvAnyAddress, field_validator
from typing import List, Optional
from datetime import datetime
import re

class NetworkLog(BaseModel):
    timestamp: datetime = Field(..., description="Timestamp of the connection")
    src_ip: str = Field(..., description="Source IP address")
    dst_ip: str = Field(..., description="Destination IP address")
    dst_port: int = Field(..., ge=1, le=65535, description="Destination port")
    bytes_sent: int = Field(..., ge=0, description="Bytes sent in the connection")
    bytes_received: int = Field(..., ge=0, description="Bytes received in the connection")

    @field_validator('src_ip', 'dst_ip')
    @classmethod
    def validate_ip(cls, v: str) -> str:
        # Basic validation to ensure it looks like an IPv4 or IPv6
        # Relying mostly on Pydantic's IPvAnyAddress would be better, but strings are easier to mock in tests
        # Let's enforce basic structure to prevent injection
        if not re.match(r"^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$", v) and ":" not in v:
             raise ValueError("Invalid IP address format")
        return v

class ConnectionBatch(BaseModel):
    logs: List[NetworkLog] = Field(..., description="A batch of network logs to analyze")

class BeaconAlert(BaseModel):
    src_ip: str
    dst_ip: str
    dst_port: int
    connection_count: int
    jitter_percent: float
    avg_interval_seconds: float
    severity: str = Field(..., description="Low, Medium, High, or Critical")
    description: str

class AnalysisResult(BaseModel):
    status: str
    processed_logs: int
    alerts_found: int
    alerts: List[BeaconAlert]
