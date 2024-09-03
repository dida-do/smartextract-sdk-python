import os
from os.path import basename
from uuid import UUID

import pytest

from smartextract import Client


@pytest.fixture(scope="module")
def client() -> Client:
    return Client(
        username=os.getenv("SMARTEXTRACT_TEST_USERNAME"),
        password=os.getenv("SMARTEXTRACT_TEST_PASSWORD"),
        base_url=os.getenv("SMARTEXTRACT_TEST_BASE_URL"),
    )


@pytest.fixture(scope="module")
def lua_pipeline_id(client) -> UUID:
    return client.create_lua_pipeline(
        name="Fixture Lua Pipeline", code="return 'Hello Smartextract!'"
    )


@pytest.fixture(scope="module")
def template_pipeline_id(client, chat_alias, ocr_alias) -> UUID:
    return client.create_template_pipeline(
        name="Fixture Template Pipeline",
        template="invoice.de",
        ocr_id=ocr_alias,
        chat_id=chat_alias,
    )


@pytest.fixture
def document():
    file = open("tests/data/hello-world.pdf", "rb")  # noqa: SIM115
    yield file

    file.close()


@pytest.fixture
def document_2():
    file = open("tests/data/hello-world.png", "rb")  # noqa: SIM115
    yield file

    file.close()


@pytest.fixture
def document_name(document):
    return basename(document.name)


@pytest.fixture
def document_bytes(document):
    document.seek(0)
    return document.read()


@pytest.fixture(scope="module")
def user_id(client) -> UUID:
    return client.get_user_info("me").id


@pytest.fixture
def inbox_and_doc(client, lua_pipeline_id, document) -> list[UUID]:
    inbox_id = client.create_inbox(name="Test Inbox", pipeline_id=str(lua_pipeline_id))
    doc_id = client.create_document(inbox_id, document)
    client.get_document_extraction(doc_id)

    return inbox_id, doc_id


@pytest.fixture
def inbox_id(inbox_and_doc) -> UUID:
    return inbox_and_doc[0]


@pytest.fixture
def document_id(inbox_and_doc) -> UUID:
    return inbox_and_doc[1]


@pytest.fixture(scope="module")
def ocr_alias():
    return "aws-ocr"


@pytest.fixture(scope="module")
def ocr_alias_2():
    return "google-ocr"


@pytest.fixture(scope="module")
def chat_alias():
    return "chatgpt3.5-json"


@pytest.fixture
def my_email(client):
    return client.get_user_info("me").email
