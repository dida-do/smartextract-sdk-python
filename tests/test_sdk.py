import os
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from uuid import UUID

import httpx
import pytest

from smartextract import (
    AccessLevel,
    BillingScheme,
    Client,
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


def recent_time(time: datetime, max_timedelta_second=100) -> bool:
    delta = datetime.now(timezone.utc) - time

    return delta <= timedelta(seconds=max_timedelta_second)


@pytest.mark.parametrize("lang", ["de", "en"])
def test_list_templates(client, lang):
    template_list = client.list_templates(language=lang)

    assert isinstance(template_list, list)
    assert any("invoice" in template.id for template in template_list)


# User Managment Methods


def test_get_user_info(client: Client):
    info = client.get_user_info()

    assert info.email == os.getenv("SMARTEXTRACT_TEST_USERNAME")

    assert info.previous_refill_date.tzinfo == timezone.utc
    assert info.previous_refill_date < datetime.now(timezone.utc)


def test_list_user_jobs(client: Client):
    job_list = client.list_user_jobs()
    assert isinstance(job_list, Page[JobInfo])

    for job in job_list.results:
        assert isinstance(job, JobInfo)


@pytest.mark.xfail  # Test user is not allowed to set credits
def test_set_user_credits(client, user_id):
    client.set_user_credits(user_id, billing_scheme="by_invoice", balance=0)
    user_info_1 = client.get_user_info()
    assert user_info_1.billing_scheme == BillingScheme.by_invoice

    client.set_user_credits(user_id, billing_scheme="per_page", balance=20)
    user_info_2 = client.get_user_info()
    assert user_info_2.billing_scheme == BillingScheme.per_page
    assert user_info_2.balance == 20

    client.set_user_credits(user_id, billing_scheme="per_page", new_credits=2)
    user_info_3 = client.get_user_info()
    assert user_info_3.billing_scheme == BillingScheme.per_page
    assert user_info_3.balance == 22
    assert user_info_3.previous_refill_credits == 2


# Resource Methods


def test_list_resources(client: Client):
    resource_list = client.list_resources()
    assert isinstance(resource_list, Page[IdInfo])


def test_list_lua_pipelines(client: Client):
    pipeline_list = client.list_lua_pipelines()
    assert isinstance(pipeline_list, Page[IdInfo])

    for pipeline in pipeline_list.results:
        assert isinstance(client.get_resource_info(pipeline.id), LuaPipelineInfo)


def test_list_template_pipelines(client: Client):
    pipeline_list = client.list_template_pipelines()
    assert isinstance(pipeline_list, Page[IdInfo])

    for pipeline in pipeline_list.results:
        assert isinstance(client.get_resource_info(pipeline.id), TemplatePipelineInfo)


@pytest.mark.xfail
def test_list_inboxes(client):
    inbox_list = client.list_inboxes(order_by="date")
    assert isinstance(inbox_list, Page[IdInfo])


def test_list_inbox_documents(client, inbox_id):
    document_list = client.list_inbox_documents(inbox_id, order_by="date")
    assert isinstance(document_list, Page[DocumentInfo])

    for doc in document_list.results:
        assert isinstance(doc, DocumentInfo)
        assert recent_time(doc.created_at)


def test_get_resource_info(
    client,
    lua_pipeline_id,
    template_pipeline_id,
    inbox_id,
    my_email,
):
    lua_pipeline = client.get_resource_info(str(lua_pipeline_id))

    assert isinstance(lua_pipeline, LuaPipelineInfo)
    assert lua_pipeline.name == "Fixture Lua Pipeline"
    assert lua_pipeline.code == "return 'Hello Smartextract!'"
    assert lua_pipeline.created_by == my_email
    assert recent_time(lua_pipeline.created_at)

    template_pipeline = client.get_resource_info(str(template_pipeline_id))

    assert isinstance(template_pipeline, TemplatePipelineInfo)
    assert template_pipeline.name == "Fixture Template Pipeline"
    # Skip test, if template_pipeline.ocr_id is ocr_alias
    # This information is not accessible to the test user.

    inbox = client.get_resource_info(inbox_id)

    assert isinstance(inbox, InboxInfo)
    assert inbox.name == "Test Inbox"
    assert inbox.pipeline_id == lua_pipeline_id
    assert inbox.document_count >= 1


def test_list_permissions(client, inbox_id, my_email):
    permission_list = client.list_permissions(inbox_id)

    assert isinstance(permission_list, Page[UserPermission])
    assert permission_list.count == 1

    my_permission = permission_list.results[0]

    assert my_permission.user == my_email
    assert my_permission.level == AccessLevel.own
    assert recent_time(my_permission.created_at)


@pytest.mark.xfail  # Waiting for backend to accept user_id's as well
def test_create_permission(client, lua_pipeline_id, user_id, my_email):
    # Set permission by user_id
    client.create_permission(str(lua_pipeline_id), str(user_id), level=AccessLevel.own)

    # Set permission by user email
    user_2 = "user1@example.com"
    client.create_permission(str(lua_pipeline_id), user_2, level=AccessLevel.run)

    permission_list = client.list_permissions(str(lua_pipeline_id))
    new_permission = next(
        perm for perm in permission_list.results if perm.user == user_2
    )
    assert new_permission.user == user_2
    assert new_permission.level == AccessLevel.run
    assert new_permission.created_by == my_email
    assert recent_time(new_permission.created_at)


# Pipeline Methods


def test_create_lua_pipeline(client: Client):
    new_name = "Test Lua Pipeline"
    new_code = "return 'This is just a test pipeline.'"
    new_pipeline_id = client.create_lua_pipeline(name=new_name, code=new_code)

    new_pipeline = client.get_resource_info(new_pipeline_id)
    assert new_name == new_pipeline.name
    assert new_code == new_pipeline.code


def test_create_template_pipeline(client, ocr_alias, chat_alias):
    new_name = "Test Template Pipeline"
    new_pipeline_id = client.create_template_pipeline(
        name=new_name,
        template="invoice.de",
        ocr_id=ocr_alias,
        chat_id=chat_alias,
    )

    new_pipeline = client.get_resource_info(new_pipeline_id)
    assert new_name == new_pipeline.name
    assert isinstance(
        new_pipeline.template, dict
    )  # Shows full template including descriptions
    assert new_name == new_pipeline.name
    assert isinstance(new_pipeline.ocr_id, UUID)
    assert isinstance(new_pipeline.chat_id, UUID)

    # Don't check if new_pipeline.chat_id corresponds to chat_alias


def test_modify_pipeline(client):
    name_1 = "Original Pipeline"
    code_1 = "return 'I am the original pipeline!'"
    pipeline_id = client.create_lua_pipeline(name=name_1, code=code_1)

    name_2 = "Modified Pipeline"
    code_2 = "return 'I am the modified pipeline!"
    client.modify_pipeline(pipeline_id, name=name_2, code=code_2)

    pipeline_info = client.get_resource_info(pipeline_id)
    assert pipeline_info.name == name_2
    assert pipeline_info.code == code_2


def test_run_lua_pipeline(client, lua_pipeline_id, document):
    pipeline_result = client.run_pipeline(lua_pipeline_id, document)

    assert pipeline_result.error is None
    assert pipeline_result.result == "Hello Smartextract!"


def test_run_template_pipeline(client, template_pipeline_id, document):
    expected_result = "mocked pipeline result"
    response = httpx.Response(status_code=200, json={"result": expected_result})

    with patch.object(Client, "_request", return_value=response) as _request:
        result = client.run_pipeline(template_pipeline_id, document)

        assert expected_result == result.result
        assert _request.called

        args, kwargs = _request.call_args
        assert args[0] == "POST"
        assert args[1] == f"/pipelines/{template_pipeline_id}/run"
        assert kwargs["files"]["document"]


@pytest.mark.skip
def test_integrated_run_template_pipeline(client, document, ocr_alias, chat_alias):
    # This test requires access to an external chat LLM endpoint
    # and to an external OCR service.

    pipeline_id = client.create_template_pipeline(
        name="Test Template Pipeline",
        template="invoice.de",
        ocr_id=ocr_alias,
        chat_id=chat_alias,
    )
    job_result = client.run_pipeline(pipeline_id, document).result

    assert job_result["schema"] == "https://smartextract.ai/schemas/extraction/v0"
    assert all(
        "label" in field and "value" in field for field in job_result["entities"]
    )


def test_run_anonymous_pipeline_0(client, document):
    pipeline_result = client.run_anonymous_pipeline(
        document, code="return 'Hello anonymous Smartextract!'"
    )

    assert pipeline_result.error is None
    assert pipeline_result.result == "Hello anonymous Smartextract!"


def test_run_anonymous_pipeline_1(client, document):
    with pytest.raises(
        ValueError,
        match="Only one of code or template must be provided",
    ):
        client.run_anonymous_pipeline(document, code="return 1", template="invoice.de")


def test_run_anonymous_pipeline_2(client, document):
    with pytest.raises(
        ValueError,
        match="Either code or template must be provided",
    ):
        client.run_anonymous_pipeline(document)


def test_list_pipeline_jobs(client, lua_pipeline_id, inbox_id):
    pipeline_job_list = client.list_pipeline_jobs(lua_pipeline_id)
    assert isinstance(pipeline_job_list, Page[JobInfo])

    for job_info in pipeline_job_list.results:
        assert isinstance(job_info, JobInfo)
        assert job_info.pipeline_id == lua_pipeline_id
        assert isinstance(job_info.started_at, datetime)
        assert isinstance(job_info.duration, timedelta)


# Inbox Methods


def test_create_inbox(client, lua_pipeline_id, ocr_alias):
    name = "Test Inbox"

    inbox_id = client.create_inbox(name, str(lua_pipeline_id), ocr_id=ocr_alias)

    inbox_info = client.get_resource_info(str(inbox_id))

    assert inbox_info.type == "inbox"
    assert inbox_info.name == name
    assert inbox_info.document_count == 0
    assert inbox_info.pipeline_id == lua_pipeline_id
    # Don't test if inbox_info.ocr_id is ocr_alias


def test_modify_inbox(
    client, lua_pipeline_id, template_pipeline_id, ocr_alias, ocr_alias_2
):
    name_1 = "Original Inbox"

    inbox_id = client.create_inbox(name_1, str(lua_pipeline_id), ocr_id=ocr_alias)
    client.get_resource_info(inbox_id)

    name_2 = "Modified Inbox"
    client.modify_inbox(
        inbox_id,
        name=name_2,
        pipeline_id=str(template_pipeline_id),
        ocr_id=ocr_alias_2,
    )

    inbox_info = client.get_resource_info(inbox_id)
    assert inbox_info.name == name_2
    assert inbox_info.pipeline_id == template_pipeline_id
    # Skip test if inbox_info.ocr_id has ocr_alias_2


def test_list_inbox_jobs(client, inbox_id):
    inbox_job_list = client.list_inbox_jobs(inbox_id)
    assert isinstance(inbox_job_list, Page[JobInfo])

    pipeline_id = client.get_resource_info(inbox_id).pipeline_id
    for job_info in inbox_job_list.results:
        assert isinstance(job_info, JobInfo)
        assert job_info.pipeline_id == pipeline_id
        assert recent_time(job_info.started_at)
        assert isinstance(job_info.duration, timedelta)


def test_list_inbox_extraction(client, inbox_id, document_id, lua_pipeline_id):
    inbox_extraction_list = client.list_inbox_extraction(inbox_id)
    assert isinstance(inbox_extraction_list, Page[ExtractionInfo])

    for extraction in inbox_extraction_list.results:
        assert isinstance(extraction, ExtractionInfo)
        assert extraction.document_id == document_id
        assert extraction.pipeline_id == lua_pipeline_id
        assert extraction.result == "Hello Smartextract!"
        assert recent_time(extraction.created_at)


# Document Methods


def test_create_document(client, inbox_id, document_2, my_email):
    doc_id = client.create_document(inbox_id, document_2)

    doc_info = client.get_document_info(doc_id)
    assert doc_info.id == doc_id
    assert doc_info.inbox_id == inbox_id
    assert doc_info.name == "hello-world.png"
    assert doc_info.media_type == "image/png"
    assert recent_time(doc_info.created_at)
    assert doc_info.created_by == my_email


def test_create_document_2(client, inbox_id, document, my_email):
    doc_id = client.create_document(
        inbox_id, document.read(), filename="smartextract.pdf"
    )

    doc_info = client.get_document_info(doc_id)
    assert doc_info.id == doc_id
    assert doc_info.inbox_id == inbox_id
    assert doc_info.name == "smartextract.pdf"
    assert doc_info.media_type == "application/pdf"
    assert recent_time(doc_info.created_at)
    assert doc_info.created_by == my_email


def test_get_document_info(client, inbox_id, document_id, document_name, my_email):
    doc_info = client.get_document_info(document_id)

    assert doc_info.id == document_id
    assert doc_info.inbox_id == inbox_id
    assert doc_info.name == document_name
    assert doc_info.media_type == "application/pdf"
    assert recent_time(doc_info.created_at)
    assert doc_info.created_by == my_email


def test_delete_document(client, inbox_id, document):
    doc_id = client.create_document(inbox_id, document)

    # Check if document was correctly created
    doc_info = client.get_document_info(doc_id)
    assert doc_info.id == doc_id

    client.delete_document(doc_id)
    with pytest.raises(ClientError):
        doc_info = client.get_document_info(doc_id)


def test_get_document_bytes(client, document_id, document_bytes):
    doc_bytes = client.get_document_bytes(document_id)
    assert doc_bytes == document_bytes


def test_get_document_extraction(
    client, document_id, document, document_name, lua_pipeline_id, my_email
):
    doc_extraction = client.get_document_extraction(document_id)

    assert doc_extraction.document_id == document_id
    assert doc_extraction.document_name == document_name
    assert doc_extraction.pipeline_id == lua_pipeline_id
    assert recent_time(doc_extraction.created_at)
    assert doc_extraction.created_by == my_email
    assert doc_extraction.result == "Hello Smartextract!"
