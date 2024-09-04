"""The smartextract SDK allows easy access to the smartextract API.

See https://docs.smartextract.ai/ for the user guide and package
documentation.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from enum import Enum
from io import IOBase
from mimetypes import MimeTypes
from os.path import basename
from typing import IO, TYPE_CHECKING, Any, Generic, Literal, Optional, TypeVar, Union
from uuid import UUID

if TYPE_CHECKING:
    from typing import Self  # For Python ≤ 3.10

import httpx
from pydantic import BaseModel, EmailStr, Field, JsonValue

__version__ = "0"

DEFAULT_BASE_URL = "https://api.smartextract.ai"
DEFAULT_TIMEOUT = 600  # seconds

Language = Literal["de", "en"]
ResourceID = Union[str, UUID]


class BillingScheme(str, Enum):
    """Enumeration of billing schemes.

    The following options are available:
    - by_invoice: User has unlimited access.
    - per_page: Each processed document consumes one credit per page.

    """

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
        """Create this object based on the output of an API request."""
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
    """Details about a user including email, credit balance and billing method."""

    id: UUID
    email: EmailStr
    billing_scheme: BillingScheme
    balance: Optional[int]
    previous_refill_balance: int
    previous_refill_credits: int
    previous_refill_date: datetime


class JobInfo(BaseInfo):
    """Information about a pipeline run."""

    pipeline_id: Optional[UUID]
    started_at: datetime
    duration: timedelta
    error: Optional[str]


class UserPermission(BaseInfo):
    """Access permissions of a user to a resource."""

    user: EmailStr
    level: AccessLevel
    created_at: datetime
    created_by: EmailStr


class IdInfo(BaseInfo):
    """Identification of a resource."""

    id: UUID
    alias: Optional[str] = None


class ResourceInfo(IdInfo):
    """Basic information about a resource."""

    type: str = Field(description="The resource type.")
    name: str = Field(description="The resource name.")
    private_access: AccessLevel = Field(
        description="Access permissions of the current user."
    )
    public_access: AccessLevel = Field(
        description="Access permissions granted to all smartextract users."
    )
    created_at: datetime = Field(
        description="Creation date of the current revision of the resource."
    )
    created_by: EmailStr = Field(
        description="User who created the current revision ofthe resource."
    )


class LuaPipelineInfo(ResourceInfo):
    """Information about a Lua pipeline."""

    code: str = Field(description="Lua code of the pipeline.")


class TemplatePipelineInfo(ResourceInfo):
    """Information about a template pipeline."""

    template: dict = Field(
        description="The extraction template, conforming to the schema "
        " described at https://smartextract.ai/schemas/template."
    )
    ocr_id: UUID = Field(description="OCR component used by the pipeline.")
    chat_id: UUID = Field(description="LLM component used by the pipeline.")


class TemplateInfo(BaseInfo):
    """Information about an extraction template."""

    id: str = Field(
        description="Template identifier, in the document_type.language form.",
        examples=["invoice.en", "bank_statement.de"],
    )
    name: str = Field(description="Localized name of the template.")
    description: str = Field(description="Localized description of the template.")
    categories: list = Field(
        description="List of business domains relevant to this template."
    )


class InboxInfo(ResourceInfo):
    """Information about an inbox.

    An inbox is a repository where documents can be stored long-term.
    Every inbox has an associated pipeline (but one pipeline
    may be associated to multiple inboxes).
    """

    document_count: int = Field(description="Total number of documents in the inbox.")
    pipeline_id: UUID = Field(
        description="Pipeline used to process documents in the inbox."
    )
    ocr_id: UUID = Field(
        description="OCR component used to search documents in the inbox."
        " Ideally (but not necessarily) should match the OCR of the inbox pipeline."
    )


class DocumentInfo(BaseInfo):
    """Information about a document."""

    id: UUID = Field(description="The document ID number.")
    inbox_id: UUID = Field(description="The inbox containing the document.")
    name: str = Field(description="The document file name.")
    media_type: str = Field(
        description="The type of document",
        examples=["application/pdf", "image/jpeg"],
    )
    created_at: datetime = Field(
        description="Creation date of the current version of the doucment."
    )
    created_by: EmailStr = Field(
        description="User who uploaded the current version of the document."
    )


class ExtractionInfo(BaseInfo):
    """Result of a document extraction."""

    document_id: UUID = Field(description="The document ID number.")
    document_name: str = Field(description="The document file name.")
    pipeline_id: UUID = Field(description="Pipeline used to compute the extraction")
    created_at: datetime = Field(description="Date when the extraction was computed.")
    created_by: EmailStr = Field(
        description="User responsible for triggering the extraction compuattion."
    )
    result: JsonValue = Field(
        description="Extracted information; the data schema depends on the pipeline."
    )


class JobResult(BaseInfo):
    """Result of a pipeline run."""

    result: JsonValue = Field(
        description="Result of the pipeline run;"
        " the data schema depends on the pipeline."
    )
    error: Optional[str] = Field(
        default=None,
        description="Error message, or null if the run was successful.",
    )
    log: Optional[list[str]] = Field(
        default=None,
        description="List of log messages emmited by the pipeline, if any.",
    )


InfoT = TypeVar("InfoT", bound=BaseInfo)


class Page(BaseInfo, Generic[InfoT]):
    """Abstract Class used to contain a list of information."""

    count: int = Field(
        description="Total number of matches of the query,"
        " potentially more than the returned results."
    )
    results: list[InfoT] = Field(
        description="Sorted list of results matching the search filters,"
        " including limit and offset."
    )


class ClientError(Exception):
    """Error from the smartextract client error."""

    @classmethod
    def from_response(cls, r: httpx.Response) -> Self:
        """Read error from the API's response."""
        return cls(r.reason_phrase, r.text, r.request)


def drop_none(**kwargs) -> dict[str, Any]:
    """Return a dictionary excluding any None values."""
    return {k: v for k, v in kwargs.items() if v is not None}


def _get_jwt_token(base_url, username, password) -> str:
    """Obtain a temporary JWT access token."""
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
        """Initialize the Client using either an API key or username and password."""
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

    def list_templates(self, language: Language = "en") -> list[TemplateInfo]:
        """List all available templates in format name.language."""
        r = self._request("GET", "/templates", params={"lang": language})
        return [TemplateInfo(**template) for template in r.json()]

    # User Management

    def get_user_info(self, user: str = "me") -> UserInfo:
        """Request stored information and credit balance of a given user."""
        r1 = self._request("GET", f"/users/{user}")
        r2 = self._request("GET", f"/users/{user}/credits")
        return UserInfo(**r1.json(), **r2.json())

    def list_user_jobs(
        self,
        user: str = "me",
        *,
        limit: int | None = None,
        offset: int | None = None,
    ) -> Page[JobInfo]:
        """List all a user's jobs with their duration and status.

        A job started whenever a document is passed throuh a pipeline.
        """
        r = self._request(
            "GET",
            f"/users/{user}/jobs",
            params=drop_none(limit=limit, offset=offset),
        )
        return Page[JobInfo].from_response(r)

    def set_user_credits(
        self,
        user: str,
        *,
        billing_scheme: Optional[BillingScheme] = None,
        new_credits: Optional[int] = None,
        balance: Optional[int] = None,
    ) -> None:
        """Set billing information for a user.

        billing_scheme ... a user can be billed "by_invoice" or "per_page"

        If the user is billed "per_page", they will consume
        one credit of their balance per processed page.

        Then Smartextract admins can either:

        new_credits ... add new credits to existing balance
        balance ... reset balance to new value

        """
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

    def list_resources(
        self,
        type: str | None = None,  # noqa: A002
        *,
        limit: int | None = None,
        offset: int | None = None,
    ) -> Page[IdInfo]:
        """List the ids of all the users resources.

        The user can create resources of type
        ["inbox", "template_pipeline", "lua_pipeline"]

        The user can use resources of type ["aws-ocr", "openai-chat, "anthropic-chat"]
        as input to the creation methods.

        """
        r = self._request(
            "GET",
            "/resources",
            params=drop_none(
                type=type,
                limit=limit,
                offset=offset,
            ),
        )
        return Page[IdInfo].from_response(r)

    def list_lua_pipelines(
        self, limit: int | None = None, offset: int | None = None
    ) -> Page[IdInfo]:
        """List the ids of all the users lua_pipelines.

        Pipelines can be started with a lua script
        by using create_lua_pipeline(...)
        """
        return self.list_resources(type="lua_pipeline", limit=limit, offset=offset)

    def list_template_pipelines(
        self, limit: int | None = None, offset: int | None = None
    ) -> Page[IdInfo]:
        """List all created pipelines that are based on a template."""
        return self.list_resources(type="template_pipeline", limit=limit, offset=offset)

    def list_inboxes(
        self,
        *,
        limit: int | None = None,
        offset: int | None = None,
        order_by: str | None = "date:desc",
    ) -> Page[IdInfo]:
        """List all inboxes with the attached pipeline.

        order_by must be one of "id", "name", "date".
        """
        r = self._request(
            "GET",
            "/inboxes",
            params=drop_none(limit=limit, offset=offset, order_by=order_by),
        )
        return Page[IdInfo].from_response(r)

    def list_inbox_documents(
        self,
        inbox_id: ResourceID,
        *,
        limit: int | None = None,
        offset: int | None = None,
        order_by: str | None = "date:desc",
    ) -> Page[DocumentInfo]:
        """List all documents inside an inbox.

        order_by must be one of ["id", "name", "date"]
        """
        r = self._request(
            "GET",
            f"/inboxes/{inbox_id}/documents",
            params=drop_none(limit=limit, offset=offset, order_by=order_by),
        )
        return Page[DocumentInfo].from_response(r)

    def get_resource_info(self, resource_id: ResourceID) -> ResourceInfo:
        """Get various information about a given resource.

        Information includes the resource type, name, access level,
        and additional details specific to the resource type.
        """
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

    def list_permissions(
        self,
        resource_id: ResourceID,
        *,
        limit: int | None = None,
        offset: int | None = None,
    ) -> Page[UserPermission]:
        """For a given resource, list all users with access rights."""
        r = self._request(
            "GET",
            f"/resources/{resource_id}/permissions",
            params=drop_none(limit=limit, offset=offset),
        )
        return Page[UserPermission].from_response(r)

    def create_permission(
        self, resource_id: ResourceID, user: str, level: AccessLevel
    ) -> None:
        """Allow user access to a resource."""
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
        """Create a new pipeline by providing a lua script.

        To run the pipeline for a PDF-document use run_pipeline(..)

        In the lua script's scope the PDF is available by the variable
        "document", which is an Iterator of Pages.
        """
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
        """Create a new pipeline based on a yaml-template.

        template ... consult the docs: https://docs.smartextract.ai/guide/pipelines/#templates

        chat_id ... must be of resource type "openai-chat" or "anthropic-chat"
        ocr_id ... must be of resource type "aws-ocr"

        """
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
        """Change details of an existing pipeline.

        Provide a new Lua script (code) for a Lua pipeline.
        Or provide a new chat_id, ocr_id or template for a template pipeline.
        """
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
        self,
        pipeline_id: ResourceID,
        document: Union[bytes, IO],
        *,
        filename: str | None = None,
    ) -> JobResult:
        """Process a document through a pipeline.

        Provide the pipeline id and document as IO string or in bytes.
        """
        document = document.read() if not isinstance(document, bytes) else document

        r = self._request(
            "POST",
            f"/pipelines/{pipeline_id}/run",
            files={"document": ("_", document, "application/pdf")},
        )
        return JobResult.from_response(r)

    def run_anonymous_pipeline(
        self,
        document: Union[bytes, IO],
        code: Optional[str] = None,
        template: Optional[dict] = None,
    ) -> JobResult:
        """Run document through pipeline without creating an inbox.

        A lua script (code) or a yaml-file (template) must be provided.
        """
        if code is None:
            if template is None:
                raise ValueError("Either code or template must be provided")
            code = json.dumps(template)
        elif template is not None:
            raise ValueError("Only one of code or template must be provided")

        document = document.read() if not isinstance(document, bytes) else document
        r = self._request(
            "POST", "/pipelines/run", files={"document": document, "code": code}
        )
        return JobResult.from_response(r)

    def list_pipeline_jobs(
        self,
        pipeline_id: Optional[ResourceID],
        limit: int | None = None,
        offset: int | None = None,
    ) -> Page[JobInfo]:
        """List all pipeline runs of a pipeline."""
        r = self._request(
            "GET",
            f"/pipelines/{pipeline_id}/jobs",
            params=drop_none(limit=limit, offset=offset),
        )
        return Page[JobInfo].from_response(r)

    # Inboxes

    def create_inbox(
        self, name: str, pipeline_id: str, *, ocr_id: Optional[str] = None
    ) -> UUID:
        """Create container for storing documents of common type.

        Inbox must be set up with document-type specific extraction pipeline.
        """
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
        """Set new pipeline for an inbox."""
        self._request(
            "PATCH",
            f"/inboxes/{inbox_id}",
            json=drop_none(
                name=name,
                pipeline_id=pipeline_id,
                ocr_id=ocr_id,
            ),
        )

    def list_inbox_jobs(
        self,
        inbox_id: ResourceID,
        *,
        limit: int | None = None,
        offset: int | None = None,
    ) -> Page[JobInfo]:
        """List all a inbox' pipeline runs."""
        r = self._request(
            "GET",
            f"/inboxes/{inbox_id}/jobs",
            params=drop_none(limit=limit, offset=offset),
        )
        return Page[JobInfo].from_response(r)

    def create_document(
        self,
        inbox_id: ResourceID,
        document: Union[bytes, IO],
        *,
        filename: str | None = None,
    ) -> UUID:
        """Push document to the database."""
        if not filename:
            if isinstance(document, IOBase) and isinstance(
                getattr(document, "name", None), str
            ):
                filename = basename(document.name)
            else:
                raise ValueError("Filename needs to be specified.")

        datatype = MimeTypes().guess_type(filename)[0]
        document = document.read() if not isinstance(document, bytes) else document

        r = self._request(
            "POST",
            f"/inboxes/{inbox_id}",
            files={"document": (filename, document, datatype)},
        )
        return UUID(r.json()["id"])

    def list_inbox_extraction(
        self,
        inbox_id: ResourceID,
        *,
        limit: int | None = None,
        offset: int | None = None,
        order_by: str | None = "date:desc",
    ) -> Page[ExtractionInfo]:
        """List all extraction results of an inbox.

        order_by must be one of ["id", "name", "date"]
        """
        r = self._request(
            "GET",
            f"inboxes/{inbox_id}/extractions",
            params=drop_none(limit=limit, offset=offset, order_by=order_by),
        )
        return Page[ExtractionInfo].from_response(r)

    # Documents

    def get_document_info(self, document_id: ResourceID) -> DocumentInfo:
        """Get name, access level and inbox location for a given document id."""
        r = self._request("GET", f"/documents/{document_id}")
        return DocumentInfo.from_response(r)

    def delete_document(self, document_id: ResourceID) -> None:
        """Delete document from database."""
        self._request("DELETE", f"/documents/{document_id}")

    def get_document_bytes(self, document_id: ResourceID) -> bytes:
        """Get document content in bytes."""
        r = self._request("GET", f"/documents/{document_id}/blob")
        return r.content

    def get_document_extraction(self, document_id: ResourceID) -> ExtractionInfo:
        """Get the document extraction from its latest pipeline processing."""
        r = self._request("GET", f"/documents/{document_id}/extraction")
        return ExtractionInfo.from_response(r)
