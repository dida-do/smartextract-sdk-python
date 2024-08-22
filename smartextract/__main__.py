"""CLI for the smartextract SDK."""

import logging
import os
import sys
from argparse import ArgumentParser, Namespace
from collections.abc import Callable
from getpass import getpass

from smartextract import (
    DEFAULT_BASE_URL,
    DEFAULT_TIMEOUT,
    BaseInfo,
    Client,
    ClientError,
    _get_jwt_token,
)


def handler(subcommand: ArgumentParser):
    """Define a handler for a subcommand."""

    def register(f: Callable[[Client, Namespace, int], None]):
        subcommand.set_defaults(handler=f)
        return f

    return register


def print_info(m: BaseInfo):
    """Print all the object's content in JSON format."""
    print(m.model_dump_json(indent=2))


def do_login(base_url, username) -> str:
    """Prompt the user to type in username and password."""
    if not username:
        if not sys.stdin.isatty():
            raise SystemExit("error: no username or API key provided")
        username = input("Username: ")
    password = getpass() if sys.stdin.isatty() else sys.stdin.readline().strip()
    try:
        return _get_jwt_token(base_url, username, password)
    except ClientError as e:
        raise SystemExit(f"error logging in: {e.args[0]}") from e


cli = ArgumentParser(
    description="Make requests to the smartextract API.",
)
cli.add_argument(
    "-v",
    "--verbose",
    action="count",
    help="print more log messages",
)
cli.add_argument(
    "--base-url",
    default=DEFAULT_BASE_URL,
    type=str,
    help="base URL of the API",
)
cli.add_argument(
    "--timeout",
    default=DEFAULT_TIMEOUT,
    type=int,
    help="network timeout in seconds (0 for no timeout)",
)
subcommands = cli.add_subparsers(required=True)

get_api_key = subcommands.add_parser(
    "get-api-key", description="Print a temporary API key."
)
get_api_key.add_argument(
    "username",
    nargs="?",
    help="user's email (if omitted, ask interactively or read from stdin)",
)
get_api_key.set_defaults(handler=do_login)

get_user_info = subcommands.add_parser(
    "get-user-info", description="Display information about a user."
)
get_user_info.add_argument("username", nargs="?", help="Email of the user")


@handler(get_user_info)
def _(client: Client, args: Namespace):
    print_info(client.get_user_info(args.username or "me"))


def main():
    """CLI entry point."""
    args = cli.parse_args()

    # Set up logging
    if not args.verbose:
        log_level = logging.WARNING
    elif args.verbose == 1:
        log_level = logging.INFO
    else:
        log_level = logging.DEBUG
    logging.basicConfig()
    logging.getLogger().setLevel(log_level)

    # Handle get-api-key subcommand as a special case
    if args.handler == do_login:
        print(do_login(args.base_url, args.username))
        return

    # Get API key
    api_key = os.getenv("SMARTEXTRACT_API_KEY") or do_login(args.base_url, None)

    # Dispatch subcommand
    timeout = args.timeout if args.timeout > 0 else None
    client = Client(api_key=api_key, timeout=timeout)
    args.handler(client, args)


if __name__ == "__main__":
    main()
