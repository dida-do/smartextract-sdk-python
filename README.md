# smartextract Python SDK

[![PyPI - Version](https://img.shields.io/pypi/v/smartextract.svg)](https://pypi.org/project/smartextract)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/smartextract.svg)](https://pypi.org/project/smartextract)

This package provides convenient access to the [smartextract REST API](https://api.smartextract.ai/docs)
for Python applications.

## Installation

This package requires Python 3.9 or higher and is available from PyPI:

```sh
pip install smartextract[oauth,cli-extras]
```

You can leave out `oauth` and `cli-extras` if you don't plan to use those
features.

## Usage

To make your first request to the smartextract API, first make sure that you
have signed up at <https://app.smartextract.ai/>.  Then, try the following:

```python
import smartextract
client = smartextract.Client()
info = client.get_user_info()
print(info)
```

You may also generate an [API key](https://app.smartextract.ai/settings/api-keys)
and pass it as an argument when initializing the client.  This is necessary if
you want to avoid the interactive login via web browser.

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

If you want to use an API key instead of the interactive OAuth authentication,
generate an [API key](https://app.smartextract.ai/settings/api-keys) and set
your environment variable `SMARTEXTRACT_API_KEY`.

Finally, see `smartextract completion --help` for instructions on how to set up
command-line completion in your shell.
