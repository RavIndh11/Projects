from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any

class UserInfo(BaseModel):
    username: Optional[str] = None
    uid: Optional[str] = None
    groups: Optional[List[str]] = []
    extra: Optional[Dict[str, Any]] = None

class ObjectReference(BaseModel):
    resource: Optional[str] = None
    namespace: Optional[str] = None
    name: Optional[str] = None
    uid: Optional[str] = None
    apiGroup: Optional[str] = None
    apiVersion: Optional[str] = None
    resourceVersion: Optional[str] = None
    subresource: Optional[str] = None

class ResponseStatus(BaseModel):
    metadata: Optional[Dict[str, Any]] = None
    code: Optional[int] = None
    reason: Optional[str] = None
    status: Optional[str] = None

class AuditEvent(BaseModel):
    kind: str = "Event"
    apiVersion: str = Field(default="audit.k8s.io/v1")
    level: str
    auditID: str
    stage: str
    requestURI: str
    verb: str
    user: UserInfo
    sourceIPs: Optional[List[str]] = []
    userAgent: Optional[str] = None
    objectRef: Optional[ObjectReference] = None
    responseStatus: Optional[ResponseStatus] = None
    requestObject: Optional[Dict[str, Any]] = None
    responseObject: Optional[Dict[str, Any]] = None
    annotations: Optional[Dict[str, str]] = None

class AuditEventList(BaseModel):
    kind: str = "EventList"
    apiVersion: str = Field(default="audit.k8s.io/v1")
    items: List[AuditEvent]

class Alert(BaseModel):
    id: str
    timestamp: str
    rule_name: str
    severity: str  # Low, Medium, High, Critical
    description: str
    audit_id: str
    user: str
    source_ips: List[str]
    resource: str
    namespace: str
