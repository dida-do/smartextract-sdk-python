import os
from datetime import datetime

from smartextract import Client


def test_get_user_info(client: Client):
    info = client.get_user_info()
    assert info.email == os.getenv("SMARTEXTRACT_TEST_USERNAME")
    assert info.previous_refill_date < datetime.now()  # noqa: DTZ005
