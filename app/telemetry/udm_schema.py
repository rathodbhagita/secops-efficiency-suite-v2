# Copyright 2026 Google LLC
#
# Google SecOps Unified Data Model (UDM) Telemetry Schema

from typing import Optional
from pydantic import BaseModel, Field


class UDMUser(BaseModel):
    userid: Optional[str] = Field(None, description="User identifier (e.g. email or username)")
    user_displayName: Optional[str] = Field(None, description="Display name of the user")


class UDMPrincipal(BaseModel):
    hostname: Optional[str] = Field(None, description="Principal host name")
    ip: Optional[str] = Field(None, description="Principal IP address")
    port: Optional[int] = Field(None, description="Principal network port")
    user: Optional[UDMUser] = Field(None, description="Associated user identity")


class UDMTarget(BaseModel):
    hostname: Optional[str] = Field(None, description="Target host name")
    ip: Optional[str] = Field(None, description="Target IP address")
    port: Optional[int] = Field(None, description="Target network port")
    user: Optional[UDMUser] = Field(None, description="Target user identity")
    resource: Optional[str] = Field(None, description="GCP resource or URI targeted")


class UDMNetwork(BaseModel):
    ip_protocol: Optional[str] = Field("TCP", description="IP Protocol (TCP, UDP, ICMP)")
    direction: Optional[str] = Field("INBOUND", description="Network traffic direction")
    application_protocol: Optional[str] = Field(None, description="Application layer protocol")


class UDMSecurityResult(BaseModel):
    action: str = Field("ALLOW", description="Security action taken (ALLOW, BLOCK, AUDIT)")
    category: Optional[str] = Field("NETWORK_DETECTION", description="Alert category")
    severity: str = Field("MEDIUM", description="Alert severity (LOW, MEDIUM, HIGH, CRITICAL)")
    description: Optional[str] = Field(None, description="Detailed security summary")
    rule_id: Optional[str] = Field(None, description="YARA-L or SCC Rule ID")
    rule_name: Optional[str] = Field(None, description="YARA-L or SCC Rule Name")


class UDMMetadata(BaseModel):
    event_type: str = Field("USER_LOGIN", description="SecOps UDM Event Type")
    event_timestamp: str = Field(..., description="ISO 8601 Timestamp of event")
    vendor_name: str = Field("Google", description="Security telemetry vendor")
    product_name: str = Field("Google SecOps", description="Security product name")
    product_event_type: Optional[str] = Field(None, description="Raw product event type")


class UDMEvent(BaseModel):
    metadata: UDMMetadata
    principal: Optional[UDMPrincipal] = None
    target: Optional[UDMTarget] = None
    network: Optional[UDMNetwork] = None
    security_result: Optional[UDMSecurityResult] = None
