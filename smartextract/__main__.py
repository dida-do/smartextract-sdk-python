"""CLI for the smartextract SDK."""

import logging
import os
from argparse import ArgumentParser, Namespace
from collections.abc import Callable

from smartextract import DEFAULT_TIMEOUT, BaseInfo, Client


def handler(subcommand: ArgumentParser):
    """Define a handler for a subcommand."""

    def register(f: Callable[[Client, Namespace, int], None]):
        subcommand.set_defaults(handler=f)
        return f

    return register


def print_info(m: BaseInfo):
    print(m.model_dump_json(indent=2))


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
    "--timeout",
    default=DEFAULT_TIMEOUT,
    type=int,
    help="network timeout in seconds (0 for no timeout)",
)
subcommands = cli.add_subparsers(required=True)

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

    # Get API key
    api_key = os.getenv("SMARTEXTRACT_API_KEY")
    if not api_key:
        raise RuntimeError("API key not found.")

    # Dispatch subcommand
    timeout = args.timeout if args.timeout > 0 else None
    client = Client(api_key=api_key, timeout=timeout)
    args.handler(client, args)


if __name__ == "__main__":
    main()
