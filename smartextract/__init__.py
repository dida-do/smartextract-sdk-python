from __future__ import annotations

import json
from datetime import datetime, timedelta
from enum import Enum
from typing import IO, TYPE_CHECKING, Any, Generic, Optional, TypeVar, Union
from uuid import UUID

if TYPE_CHECKING:
    from typing import Self  # For Python ≤ 3.10

import httpx
from pydantic import BaseModel, EmailStr, Field, JsonValue

__version__ = "0"

DEFAULT_BASE_URL = "https://api.smartextract.ai"
DEFAULT_TIMEOUT = 600  # seconds

ResourceID = Union[str, UUID]


class BillingScheme(str, Enum):
    """Enumeration of billing schemes."""

    by_invoice = "by_invoice"
    per_page = "per_page"


class AccessLevel(str, Enum):
    """Enumeration expressing the usage rights over a resource."""

    own = "own"
    edit = "edit"
    view = "view"
    list = "list"
    run = "run"
    none = "none"


class BaseInfo(BaseModel):
    """Base class for API return values."""

    @classmethod
    def from_response(cls, r: httpx.Response) -> Self:
        return cls(**r.json())

    def _repr_pretty_(self, p, cycle) -> None:
        p.text(f"{self.__class__.__name__}(")
        if cycle:
            p.text("...)")
            return
        with p.indent(2):
            for k, v in self:
                p.break_()
                p.text(f"{k}=")
                if isinstance(v, list):
                    p.text("[")
                    with p.indent(2):
                        for v1 in v:
                            p.break_()
                            p.pretty(v1)
                            p.text(",")
                    p.break_()
                    p.text("]")
                    continue
                if isinstance(v, dict):
                    p.text("{")
                    with p.indent(2):
                        for k1, v1 in v.items():
                            p.break_()
                            p.pretty(k1)
                            p.text(": ")
                            p.pretty(v1)
                            p.text(",")
                    p.break_()
                    p.text("}")
                    continue
                if isinstance(v, Enum):
                    v = v.value
                elif isinstance(v, (timedelta, datetime, UUID)):
                    v = str(v)
                p.pretty(v)
                p.text(",")
        p.break_()
        p.text(")")


class UserInfo(BaseInfo):
    id: UUID
    email: EmailStr
    billing_scheme: BillingScheme
    balance: Optional[int]
    previous_refill_balance: int
    previous_refill_credits: int
    previous_refill_date: datetime


class JobInfo(BaseInfo):
    pipeline_id: UUID
    started_at: datetime
    duration: timedelta
    error: Optional[str]


class UserPermission(BaseInfo):
    user: EmailStr
    level: AccessLevel
    created_at: datetime
    created_by: EmailStr


class IdInfo(BaseInfo):
    id: UUID
    alias: Optional[str] = None


class ResourceInfo(IdInfo):
    type: str
    name: str
    private_access: AccessLevel
    public_access: AccessLevel
    created_at: datetime
    created_by: EmailStr


class LuaPipelineInfo(ResourceInfo):
    code: str


class TemplatePipelineInfo(ResourceInfo):
    template: dict
    ocr_id: UUID
    chat_id: UUID


class TemplateInfo(IdInfo):
    name: str
    description: str


class InboxInfo(ResourceInfo):
    document_count: int
    pipeline_id: UUID
    ocr_id: UUID


class DocumentShortInfo(BaseInfo):
    id: UUID
    name: str
    created_at: datetime
    created_by: EmailStr


class DocumentInfo(BaseInfo):
    id: UUID
    inbox_id: UUID = Field(validation_alias="collection")
    name: str
    media_type: str
    created_at: datetime
    created_by: EmailStr


class ExtractionInfo(BaseInfo):
    document_id: UUID
    document_name: str
    pipeline_id: UUID = Field(validation_alias="pipeline")
    created_at: datetime
    created_by: EmailStr
    result: JsonValue = Field(validation_alias="data")


class PipelineResult(BaseInfo):
    result: JsonValue
    error: Optional[str] = None
    log: Optional[list[str]] = None


InfoT = TypeVar("InfoT", bound=BaseInfo)


class Page(BaseInfo, Generic[InfoT]):
    count: int
    results: list[InfoT]


class ClientError(Exception):
    """Error from the smartextract client error."""

    @classmethod
    def from_response(cls, r: httpx.Response) -> Self:
        return cls(r.reason_phrase, r.text, r.request)


def drop_none(**kwargs) -> dict[str, Any]:
    """Return a dictionary excluding any None values."""
    return {k: v for k, v in kwargs.items() if v is not None}


def _get_jwt_token(base_url, username, password) -> str:
    r = httpx.post(
        f"{base_url}/auth/jwt/login",
        data={"username": username, "password": password},
    )
    if not r.is_success:
        raise ClientError.from_response(r)
    return r.json()["access_token"]


class Client:
    """smartextract API client."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        base_url: str = DEFAULT_BASE_URL,
        timeout: Union[None, float, httpx.Timeout] = DEFAULT_TIMEOUT,
        _transport: httpx.BaseTransport | None = None,
    ):
        if api_key is None:
            if not username:
                raise ValueError(
                    "Either an API key or a username/password pair must be provided."
                )
            if not password:
                raise ValueError("A password must be provided.")
            api_key = _get_jwt_token(base_url, username, password)
        self._httpx = httpx.Client(
            base_url=base_url,
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=timeout,
            transport=_transport,
        )

    def _request(self, method: str, url: str, **kwargs) -> httpx.Response:
        r = self._httpx.request(method, url, **kwargs)
        if not r.is_success:
            raise ClientError.from_response(r)
        return r

    def list_templates(self, language: str = "en") -> Page[TemplateInfo]:
        # Only accepts languages "en" and "de"

        r = self._request("GET", f"/templates/?lang={language}")
        return Page[TemplateInfo].from_response(r)

    # User Management

    def get_user_info(self, user: str = "me") -> UserInfo:
        r1 = self._request("GET", f"/users/{user}")
        r2 = self._request("GET", f"/users/{user}/credits")
        return UserInfo(**r1.json(), **r2.json())

    def list_user_jobs(self, user: str = "me") -> Page[JobInfo]:
        r = self._request("GET", f"/users/{user}/jobs")
        return Page[JobInfo].from_response(r)

    def set_user_credits(
        self,
        user: str,
        *,
        billing_scheme: Optional[BillingScheme] = None,
        new_credits: Optional[int] = None,
        balance: Optional[int] = None,
    ) -> None:
        self._request(
            "PATCH",
            f"/users/{user}/credits",
            json=drop_none(
                billing_scheme=billing_scheme,
                new_credits=new_credits,
                balance=balance,
            ),
        )

    # Resources

    def list_resources(self, type: str | None = None) -> Page[IdInfo]:  # noqa: A002
        r = self._request("GET", "/resources", params=drop_none(type=type))
        return Page[IdInfo].from_response(r)

    def list_lua_pipelines(self) -> Page[IdInfo]:
        return self.list_resources(type="lua_pipeline")

    def list_template_pipelines(self) -> Page[IdInfo]:
        return self.list_resources(type="template_pipeline")

    def list_inboxes(self) -> Page[IdInfo]:
        return self.list_resources(type="inbox")

    def list_inbox_documents(self, inbox_id: ResourceID) -> Page[DocumentInfo]:
        r = self._request("GET", f"/inboxes/{inbox_id}/documents")
        return Page[DocumentInfo].from_response(r)

    def get_resource_info(self, resource_id: ResourceID) -> ResourceInfo:
        info = self._request("GET", f"/resources/{resource_id}").json()
        if info["type"] == "lua_pipeline":
            r = self._request("GET", f"/pipelines/{resource_id}")
            return LuaPipelineInfo.from_response(r)
        if info["type"] == "template_pipeline":
            r = self._request("GET", f"/pipelines/{resource_id}")
            return TemplatePipelineInfo.from_response(r)
        if info["type"] == "inbox":
            r = self._request("GET", f"/inboxes/{resource_id}")
            return InboxInfo.from_response(r)
        return ResourceInfo(**info)

    def list_permissions(self, resource_id: ResourceID) -> Page[UserPermission]:
        r = self._request("GET", f"/resources/{resource_id}/permissions")
        return Page[UserPermission].from_response(r)

    def create_permission(
        self, resource_id: ResourceID, user: str, level: AccessLevel
    ) -> None:
        self._request(
            "POST",
            f"/resources/{resource_id}/permissions",
            json={"user": user, "level": level},
        )

    # Pipelines

    def create_lua_pipeline(
        self,
        name: str,
        code: str,
        *,
        permissions: Optional[dict[str, AccessLevel]] = None,
    ) -> UUID:
        r = self._request(
            "POST",
            "/pipelines",
            json=drop_none(name=name, code=code, permissions=permissions),
        )
        return UUID(r.json()["id"])

    def create_template_pipeline(
        self,
        name: str,
        template: Union[str, dict],
        *,
        chat_id: Optional[ResourceID] = None,
        ocr_id: Optional[ResourceID] = None,
        permissions: Optional[dict[str, AccessLevel]] = None,
    ) -> UUID:
        r = self._request(
            "POST",
            "/pipelines",
            json=drop_none(
                name=name,
                template=template,
                chat_id=chat_id,
                ocr_id=ocr_id,
                permissions=permissions,
            ),
        )
        return UUID(r.json()["id"])

    def modify_pipeline(
        self,
        pipeline_id: ResourceID,
        *,
        name: Optional[str] = None,
        code: Optional[str] = None,
        template: Union[None, str, dict] = None,
        chat_id: Optional[ResourceID] = None,
        ocr_id: Optional[ResourceID] = None,
    ) -> None:
        self._request(
            "PATCH",
            f"/pipelines/{pipeline_id}",
            json=drop_none(
                name=name,
                code=code,
                template=template,
                chat_id=chat_id,
                ocr_id=ocr_id,
            ),
        )

    def run_pipeline(
        self, pipeline_id: Optional[ResourceID], document: Union[bytes, IO]
    ) -> PipelineResult:
        r = self._request(
            "POST", f"/pipelines/{pipeline_id}/run", files={"document": document}
        )
        return PipelineResult.from_response(r)

    def run_anonymous_pipeline(
        self,
        document: Union[bytes, IO],
        code: Optional[str] = None,
        template: Optional[dict] = None,
    ) -> PipelineResult:
        if code is None:
            if template is None:
                raise ValueError("Either code or template must be provided")
            code = json.dumps(template)
        elif template is not None:
            raise ValueError("Only one of code or template must be provided")
        r = self._request(
            "POST", "/pipelines/run", files={"document": document, "code": code}
        )
        return PipelineResult.from_response(r)

    def list_pipeline_jobs(self, pipeline_id: Optional[ResourceID]) -> Page[JobInfo]:
        r = self._request("GET", f"/pipelines/{pipeline_id}/jobs")
        return Page[JobInfo].from_response(r)

    # Inboxes

    def create_inbox(
        self, name: str, pipeline_id: str, *, ocr_id: Optional[str] = None
    ) -> UUID:
        r = self._request(
            "POST",
            "/inboxes",
            json=drop_none(name=name, pipeline_id=pipeline_id, ocr_id=ocr_id),
        )
        return UUID(r.json()["id"])

    def modify_inbox(
        self,
        inbox_id: ResourceID,
        *,
        name: Optional[str] = None,
        pipeline_id: Optional[ResourceID] = None,
        ocr_id: Optional[ResourceID] = None,
    ) -> None:
        self._request(
            "PATCH",
            f"/inboxes/{inbox_id}",
            json=drop_none(
                pipeline_id=pipeline_id,
                ocr_id=ocr_id,
            ),
        )

    def list_inbox_jobs(self, inbox_id: ResourceID) -> Page[JobInfo]:
        r = self._request("GET", f"/inboxes/{inbox_id}/jobs")
        return Page[JobInfo].from_response(r)

    def create_document(self, inbox_id: ResourceID, document: Union[bytes, IO]) -> UUID:
        r = self._request("POST", f"/inboxes/{inbox_id}", files={"document": document})
        return UUID(r.json()["id"])

    def list_inbox_extraction(self, inbox_id: ResourceID) -> Page[ExtractionInfo]:
        r = self._request("GET", f"inboxes/{inbox_id}/extractions")
        return Page[ExtractionInfo].from_response(r)

    # Documents

    def get_document_info(self, document_id: ResourceID) -> DocumentInfo:
        r = self._request("GET", f"/documents/{document_id}")
        return DocumentInfo.from_response(r)

    def delete_document(self, document_id: ResourceID) -> None:
        self._request("DELETE", f"/documents/{document_id}")

    def get_document_bytes(self, document_id: ResourceID) -> bytes:
        r = self._request("GET", f"/documents/{document_id}")
        return r.content

    def get_document_extraction(self, document_id: ResourceID) -> ExtractionInfo:
        r = self._request("GET", f"/documents/{document_id}/extraction")
        return ExtractionInfo.from_response(r)
