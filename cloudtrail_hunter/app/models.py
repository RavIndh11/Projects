from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime

class UserIdentity(BaseModel):
    type: str = Field(default="Unknown")
    principalId: Optional[str] = None
    arn: Optional[str] = None
    accountId: Optional[str] = None
    userName: Optional[str] = None

class CloudTrailEvent(BaseModel):
    eventVersion: str
    userIdentity: UserIdentity
    eventTime: datetime
    eventSource: str
    eventName: str
    awsRegion: str
    sourceIPAddress: str
    userAgent: Optional[str] = None
    errorCode: Optional[str] = None
    errorMessage: Optional[str] = None
    requestParameters: Optional[Dict[str, Any]] = None
    responseElements: Optional[Dict[str, Any]] = None
    eventID: str
    eventType: str
    readOnly: Optional[bool] = None

class CloudTrailLogFile(BaseModel):
    Records: List[CloudTrailEvent]

class Finding(BaseModel):
    eventID: str
    severity: str
    title: str
    description: str
    eventTime: datetime
    eventName: str
    eventSource: str
    sourceIPAddress: str
    userName: str
