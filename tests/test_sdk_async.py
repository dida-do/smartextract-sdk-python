import os
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from uuid import UUID

import httpx
import pytest

from smartextract import (
    AccessLevel,
    AsyncClient,
    BillingScheme,
    ClientError,
    DocumentInfo,
    ExtractionInfo,
    IdInfo,
    InboxInfo,
    JobInfo,
    LuaPipelineInfo,
    Page,
    TemplatePipelineInfo,
    UserPermission,
)

from .helpers import recent_time  # noqa: TID252


@pytest.mark.parametrize("lang", ["de", "en"])
async def test_list_templates(aclient: AsyncClient, lang):
    template_list = await aclient.list_templates(language=lang)
    assert isinstance(template_list, list)
    assert any("invoice" in template.id for template in template_list)


## User managment methods


async def test_get_user_info_async(aclient: AsyncClient):
    info = await aclient.get_user_info()
    assert info.email == os.getenv("SMARTEXTRACT_TEST_USERNAME")
    assert info.previous_refill_date.tzinfo == timezone.utc
    assert info.previous_refill_date < datetime.now(timezone.utc)


async def test_list_user_jobs(aclient: AsyncClient):
    job_list = await aclient.list_user_jobs()
    assert isinstance(job_list, Page[JobInfo])
    for job in job_list.results:
        assert isinstance(job, JobInfo)


@pytest.mark.xfail  # Test user is not allowed to set credits
async def test_set_user_credits(aclient: AsyncClient, user_id):
    await aclient.set_user_credits(user_id, billing_scheme="by_invoice", balance=0)
    user_info_1 = await aclient.get_user_info()
    assert user_info_1.billing_scheme == BillingScheme.by_invoice

    await aclient.set_user_credits(user_id, billing_scheme="per_page", balance=20)
    user_info_2 = await aclient.get_user_info()
    assert user_info_2.billing_scheme == BillingScheme.per_page
    assert user_info_2.balance == 20

    await aclient.set_user_credits(user_id, billing_scheme="per_page", new_credits=2)
    user_info_3 = await aclient.get_user_info()
    assert user_info_3.billing_scheme == BillingScheme.per_page
    assert user_info_3.balance == 22
    assert user_info_3.previous_refill_credits == 2


# Resource Methods


async def test_list_resources(aclient: AsyncClient):
    resource_list = await aclient.list_resources()
    assert isinstance(resource_list, Page[IdInfo])


async def test_list_lua_pipelines(aclient: AsyncClient):
    pipeline_list = await aclient.list_lua_pipelines()
    assert isinstance(pipeline_list, Page[IdInfo])
    for pipeline in pipeline_list.results:
        assert isinstance(await aclient.get_resource_info(pipeline.id), LuaPipelineInfo)


async def test_list_template_pipelines(aclient: AsyncClient):
    pipeline_list = await aclient.list_template_pipelines()
    assert isinstance(pipeline_list, Page[IdInfo])
    for pipeline in pipeline_list.results:
        assert isinstance(
            await aclient.get_resource_info(pipeline.id), TemplatePipelineInfo
        )


@pytest.mark.xfail
async def test_list_inboxes(aclient: AsyncClient):
    inbox_list = await aclient.list_inboxes(order_by="date")
    assert isinstance(inbox_list, Page[IdInfo])


async def test_list_documents(aclient: AsyncClient, inbox_id):
    document_list = await aclient.list_documents(inbox_id, order_by="date")
    assert isinstance(document_list, Page[DocumentInfo])
    for doc in document_list.results:
        assert isinstance(doc, DocumentInfo)
        assert recent_time(doc.created_at)


async def test_get_resource_info(
    aclient: AsyncClient,
    lua_pipeline_id,
    template_pipeline_id,
    inbox_id,
    my_email,
):
    lua_pipeline = await aclient.get_resource_info(str(lua_pipeline_id))
    assert isinstance(lua_pipeline, LuaPipelineInfo)
    assert lua_pipeline.name == "Fixture Lua Pipeline"
    assert lua_pipeline.code == "return 'Hello Smartextract!'"
    assert lua_pipeline.created_by == my_email
    assert recent_time(lua_pipeline.created_at)

    template_pipeline = await aclient.get_resource_info(str(template_pipeline_id))
    assert isinstance(template_pipeline, TemplatePipelineInfo)
    assert template_pipeline.name == "Fixture Template Pipeline"

    # Skip test, if template_pipeline.ocr_id is ocr_alias
    # This information is not accessible to the test user.
    inbox = await aclient.get_resource_info(inbox_id)
    assert isinstance(inbox, InboxInfo)
    assert inbox.name == "Test Inbox"
    assert inbox.pipeline_id == lua_pipeline_id
    assert inbox.document_count >= 1


async def test_list_permissions(aclient: AsyncClient, inbox_id, my_email):
    permission_list = await aclient.list_permissions(inbox_id)
    assert isinstance(permission_list, Page[UserPermission])
    assert permission_list.count == 1
    my_permission = permission_list.results[0]
    assert my_permission.user == my_email
    assert my_permission.level == AccessLevel.own
    assert recent_time(my_permission.created_at)


@pytest.mark.xfail  # Waiting for backend to accept user_id's as well
async def test_create_permission(
    aclient: AsyncClient, lua_pipeline_id, user_id, my_email
):
    # Set permission by user_id
    await aclient.create_permission(
        str(lua_pipeline_id), str(user_id), level=AccessLevel.own
    )

    # Set permission by user email
    user_2 = "user1@example.com"
    await aclient.create_permission(str(lua_pipeline_id), user_2, level=AccessLevel.run)
    permission_list = await aclient.list_permissions(str(lua_pipeline_id))
    new_permission = next(
        perm for perm in permission_list.results if perm.user == user_2
    )
    assert new_permission.user == user_2
    assert new_permission.level == AccessLevel.run
    assert new_permission.created_by == my_email
    assert recent_time(new_permission.created_at)


## Pipeline methods


async def test_create_lua_pipeline(aclient: AsyncClient):
    new_name = "Test Lua Pipeline"
    new_code = "return 'This is just a test pipeline.'"
    new_pipeline_id = await aclient.create_lua_pipeline(name=new_name, code=new_code)
    new_pipeline = await aclient.get_resource_info(new_pipeline_id)
    assert new_name == new_pipeline.name
    assert new_code == new_pipeline.code


async def test_create_template_pipeline(aclient: AsyncClient, ocr_alias, chat_alias):
    new_name = "Test Template Pipeline"
    new_pipeline_id = await aclient.create_template_pipeline(
        name=new_name,
        template="invoice.de",
        ocr_id=ocr_alias,
        chat_id=chat_alias,
    )

    new_pipeline = await aclient.get_resource_info(new_pipeline_id)
    assert new_name == new_pipeline.name
    assert isinstance(
        new_pipeline.template, dict
    )  # Shows full template including descriptions
    assert new_name == new_pipeline.name
    assert isinstance(new_pipeline.ocr_id, UUID)
    assert isinstance(new_pipeline.chat_id, UUID)

    # Don't check if new_pipeline.chat_id corresponds to chat_alias


async def test_modify_pipeline(aclient: AsyncClient):
    name_1 = "Original Pipeline"
    code_1 = "return 'I am the original pipeline!'"
    pipeline_id = await aclient.create_lua_pipeline(name=name_1, code=code_1)
    name_2 = "Modified Pipeline"
    code_2 = "return 'I am the modified pipeline!"
    await aclient.modify_pipeline(pipeline_id, name=name_2, code=code_2)
    pipeline_info = await aclient.get_resource_info(pipeline_id)
    assert pipeline_info.name == name_2
    assert pipeline_info.code == code_2


async def test_run_lua_pipeline(aclient: AsyncClient, lua_pipeline_id, document):
    pipeline_result = await aclient.run_pipeline(lua_pipeline_id, document)
    assert pipeline_result.error is None
    assert pipeline_result.result == "Hello Smartextract!"


async def test_run_template_pipeline(
    aclient: AsyncClient, template_pipeline_id, document
):
    expected_result = "mocked pipeline result"
    response = httpx.Response(status_code=200, json={"result": expected_result})
    with patch.object(AsyncClient, "_request", return_value=response) as _request:
        result = await aclient.run_pipeline(template_pipeline_id, document)
        assert expected_result == result.result
        assert _request.called
        args, kwargs = _request.call_args
        assert args[0] == "POST"
        assert args[1] == f"/pipelines/{template_pipeline_id}/run"
        assert kwargs["files"]["document"]


@pytest.mark.skip
async def test_integrated_run_template_pipeline(
    aclient: AsyncClient, document, ocr_alias, chat_alias
):
    # This test requires access to an external chat LLM endpoint
    # and to an external OCR service.

    pipeline_id = await aclient.create_template_pipeline(
        name="Test Template Pipeline",
        template="invoice.de",
        ocr_id=ocr_alias,
        chat_id=chat_alias,
    )
    job_result = await aclient.run_pipeline(pipeline_id, document).result
    assert job_result["schema"] == "https://smartextract.ai/schemas/extraction/v0"
    assert all(
        "label" in field and "value" in field for field in job_result["entities"]
    )


async def test_run_anonymous_pipeline_0(aclient: AsyncClient, document):
    pipeline_result = await aclient.run_anonymous_pipeline(
        document, code="return 'Hello anonymous Smartextract!'"
    )
    assert pipeline_result.error is None
    assert pipeline_result.result == "Hello anonymous Smartextract!"


async def test_run_anonymous_pipeline_1(aclient: AsyncClient, document):
    with pytest.raises(
        ValueError,
        match="Only one of code or template must be provided",
    ):
        await aclient.run_anonymous_pipeline(
            document, code="return 1", template="invoice.de"
        )


async def test_run_anonymous_pipeline_2(aclient: AsyncClient, document):
    with pytest.raises(
        ValueError,
        match="Either code or template must be provided",
    ):
        await aclient.run_anonymous_pipeline(document)


async def test_list_pipeline_jobs(aclient: AsyncClient, lua_pipeline_id, inbox_id):
    pipeline_job_list = await aclient.list_pipeline_jobs(lua_pipeline_id)
    assert isinstance(pipeline_job_list, Page[JobInfo])
    for job_info in pipeline_job_list.results:
        assert isinstance(job_info, JobInfo)
        assert job_info.pipeline_id == lua_pipeline_id
        assert isinstance(job_info.started_at, datetime)
        assert isinstance(job_info.duration, timedelta)


## Inbox methods


async def test_create_inbox(aclient: AsyncClient, lua_pipeline_id, ocr_alias):
    name = "Test Inbox"
    inbox_id = await aclient.create_inbox(name, str(lua_pipeline_id), ocr_id=ocr_alias)
    inbox_info = await aclient.get_resource_info(str(inbox_id))
    assert inbox_info.type == "inbox"
    assert inbox_info.name == name
    assert inbox_info.document_count == 0
    assert inbox_info.pipeline_id == lua_pipeline_id
    # Don't test if inbox_info.ocr_id is ocr_alias


async def test_modify_inbox(
    aclient: AsyncClient, lua_pipeline_id, template_pipeline_id, ocr_alias, ocr_alias_2
):
    name_1 = "Original Inbox"

    inbox_id = await aclient.create_inbox(
        name_1, str(lua_pipeline_id), ocr_id=ocr_alias
    )
    await aclient.get_resource_info(inbox_id)
    name_2 = "Modified Inbox"
    await aclient.modify_inbox(
        inbox_id,
        name=name_2,
        pipeline_id=str(template_pipeline_id),
        ocr_id=ocr_alias_2,
    )

    inbox_info = await aclient.get_resource_info(inbox_id)
    assert inbox_info.name == name_2
    assert inbox_info.pipeline_id == template_pipeline_id
    # Skip test if inbox_info.ocr_id has ocr_alias_2


async def test_list_inbox_jobs(aclient: AsyncClient, inbox_id):
    inbox_job_list = await aclient.list_inbox_jobs(inbox_id)
    assert isinstance(inbox_job_list, Page[JobInfo])
    info = await aclient.get_resource_info(inbox_id)
    pipeline_id = info.pipeline_id
    for job_info in inbox_job_list.results:
        assert isinstance(job_info, JobInfo)
        assert job_info.pipeline_id == pipeline_id
        assert recent_time(job_info.started_at)
        assert isinstance(job_info.duration, timedelta)


async def test_list_extractions(
    aclient: AsyncClient, inbox_id, document_id, lua_pipeline_id
):
    inbox_extraction_list = await aclient.list_extractions(inbox_id)
    assert isinstance(inbox_extraction_list, Page[ExtractionInfo])
    for extraction in inbox_extraction_list.results:
        assert isinstance(extraction, ExtractionInfo)
        assert extraction.document_id == document_id
        assert extraction.pipeline_id == lua_pipeline_id
        assert extraction.result == "Hello Smartextract!"
        assert recent_time(extraction.created_at)


## Document methods


async def test_create_document(aclient: AsyncClient, inbox_id, document_2, my_email):
    doc_id = await aclient.create_document(inbox_id, document_2)
    doc_info = await aclient.get_document_info(doc_id)
    assert doc_info.id == doc_id
    assert doc_info.inbox_id == inbox_id
    assert doc_info.name == "hello-world.png"
    assert doc_info.media_type == "image/png"
    assert recent_time(doc_info.created_at)
    assert doc_info.created_by == my_email


async def test_create_document_2(aclient: AsyncClient, inbox_id, document, my_email):
    doc_id = await aclient.create_document(
        inbox_id, document.read(), filename="smartextract.pdf"
    )
    doc_info = await aclient.get_document_info(doc_id)
    assert doc_info.id == doc_id
    assert doc_info.inbox_id == inbox_id
    assert doc_info.name == "smartextract.pdf"
    assert doc_info.media_type == "application/pdf"
    assert recent_time(doc_info.created_at)
    assert doc_info.created_by == my_email


async def test_get_document_info(
    aclient: AsyncClient, inbox_id, document_id, document_name, my_email
):
    doc_info = await aclient.get_document_info(document_id)
    assert doc_info.id == document_id
    assert doc_info.inbox_id == inbox_id
    assert doc_info.name == document_name
    assert doc_info.media_type == "application/pdf"
    assert recent_time(doc_info.created_at)
    assert doc_info.created_by == my_email


async def test_delete_document(aclient: AsyncClient, inbox_id, document):
    doc_id = await aclient.create_document(inbox_id, document)

    # Check if document was correctly created
    doc_info = await aclient.get_document_info(doc_id)
    assert doc_info.id == doc_id

    await aclient.delete_document(doc_id)
    with pytest.raises(ClientError):
        doc_info = await aclient.get_document_info(doc_id)


async def test_get_document_bytes(aclient: AsyncClient, document_id, document_bytes):
    doc_bytes = await aclient.get_document_bytes(document_id)
    assert doc_bytes == document_bytes


async def test_get_document_extraction(
    aclient: AsyncClient,
    document_id,
    document,
    document_name,
    lua_pipeline_id,
    my_email,
):
    doc_extraction = await aclient.get_document_extraction(document_id)
    assert doc_extraction.document_id == document_id
    assert doc_extraction.document_name == document_name
    assert doc_extraction.pipeline_id == lua_pipeline_id
    assert recent_time(doc_extraction.created_at)
    assert doc_extraction.created_by == my_email
    assert doc_extraction.result == "Hello Smartextract!"
