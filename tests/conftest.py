import os

import pytest

from smartextract import Client


@pytest.fixture(scope="module")
def client() -> Client:
    return Client(
        username=os.getenv("SMARTEXTRACT_TEST_USERNAME"),
        password=os.getenv("SMARTEXTRACT_TEST_PASSWORD"),
        base_url=os.getenv("SMARTEXTRACT_TEST_BASE_URL"),
    )
