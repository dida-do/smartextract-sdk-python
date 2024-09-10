import os
from os.path import basename
from typing import Any
from uuid import UUID

import pytest

from smartextract import AsyncClient, Client

client_args = dict(  # noqa: C408
    username=os.getenv("SMARTEXTRACT_TEST_USERNAME"),
    password=os.getenv("SMARTEXTRACT_TEST_PASSWORD"),
    base_url=os.getenv("SMARTEXTRACT_TEST_BASE_URL"),
)


@pytest.fixture()
def anyio_backend():
    """Fixture allowing async test definitions."""
    return "asyncio"


@pytest.fixture()
def aclient(anyio_backend) -> AsyncClient:
    return AsyncClient(**client_args)


@pytest.fixture()
def client() -> Client:
    return Client(**client_args)


@pytest.fixture(scope="session")
def setup_client() -> Client:
    """Client used to set up session-scoped fixtures."""
    return Client(**client_args)


@pytest.fixture(scope="session")
def lua_pipeline_id(setup_client) -> UUID:
    return setup_client.create_lua_pipeline(
        name="Fixture Lua Pipeline", code="return 'Hello Smartextract!'"
    )


@pytest.fixture(scope="session")
def template_pipeline_id(setup_client, chat_alias, ocr_alias) -> UUID:
    return setup_client.create_template_pipeline(
        name="Fixture Template Pipeline",
        template="invoice.de",
        ocr_id=ocr_alias,
        chat_id=chat_alias,
    )


@pytest.fixture
def document():
    with open("tests/data/hello-world.pdf", "rb") as f:
        yield f


@pytest.fixture
def document_2():
    with open("tests/data/hello-world.png", "rb") as f:
        yield f


@pytest.fixture
def document_name(document):
    return basename(document.name)


@pytest.fixture
def document_bytes(document):
    document.seek(0)
    return document.read()


@pytest.fixture(scope="session")
def user_id(setup_client) -> UUID:
    return setup_client.get_user_info("me").id


@pytest.fixture
def inbox_and_doc(setup_client, lua_pipeline_id, document) -> list[UUID]:
    inbox_id = setup_client.create_inbox(
        name="Test Inbox", pipeline_id=str(lua_pipeline_id)
    )
    doc_id = setup_client.create_document(inbox_id, document)
    setup_client.get_document_extraction(doc_id)
    return inbox_id, doc_id


@pytest.fixture
def inbox_id(inbox_and_doc) -> UUID:
    return inbox_and_doc[0]


@pytest.fixture
def document_id(inbox_and_doc) -> UUID:
    return inbox_and_doc[1]


@pytest.fixture(scope="session")
def ocr_alias():
    return "aws-ocr"


@pytest.fixture(scope="session")
def ocr_alias_2():
    return "google-ocr"


@pytest.fixture(scope="session")
def chat_alias():
    return "chatgpt3.5-json"


@pytest.fixture(scope="session")
def my_email(setup_client):
    return setup_client.get_user_info("me").email
