# smartextract Python SDK

[![PyPI - Version](https://img.shields.io/pypi/v/smartextract.svg)](https://pypi.org/project/smartextract)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/smartextract.svg)](https://pypi.org/project/smartextract)

This package provides convenient access to the [smartextract REST API](https://api.smartextract.ai/docs)
for Python applications.

## Installation

This package requires Python 3.9 or higher and is available from PyPI:

```sh
pip install smartextract
```

## Usage

To make your first request to the smartextract API, first make sure that you
have signed up at <https://app.smartextract.ai/>.  Then, try the following:

```python
import smartextract
client = smartextract.Client(username=YOUR_USERNAME, password=YOUR_PASSWORD)
info = client.get_user_info()
print(info)
```

You may also generate an [API key](https://app.smartextract.ai/settings/api-keys)
and use it instead of your username and password to initialize the client.

For more information, use your IDE to explore the methods of the `Client` object or
refer to the [user guide](https://docs.smartextract.ai/guide).

## CLI

This package also offers a command line interface.  To enable a few additional
CLI features, install it with:

```sh
pip install smartextract[cli-extras]
```

Then type, for instance

```sh
smartextract get-user-info
```

to make a request, and

```sh
smartextract --help
```

for more information on all available commands and switches.

To avoid typing your username and password every time, generate an [API
key](https://app.smartextract.ai/settings/api-keys) and set your environment
variable `SMARTEXTRACT_API_KEY`.  Alternatively, you can use short-lived API
tokens, for example like this:

```sh
export SMARTEXTRACT_API_KEY="$(smartextract login YOUR_USERNAME)"
# or, to avoid typing your password interactively
export SMARTEXTRACT_API_KEY="$(cat my-password.txt | smartextract login YOUR_USERNAME)"
```

Finally, see `smartextract completion --help` for instructions on how to set up
command-line completion in your shell.
