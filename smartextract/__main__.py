"""CLI for the smartextract SDK."""

from __future__ import annotations

import argparse
import io
import json
import logging
import os
import sys
from collections.abc import Callable
from getpass import getpass
from typing import Any

from pydantic import TypeAdapter

from smartextract import (
    DEFAULT_BASE_URL,
    DEFAULT_TIMEOUT,
    AccessLevel,
    Client,
    ClientError,
    Language,
    _get_jwt_token,
    drop_none,
)

logger = logging.getLogger("smartextract")


def get_access_token(base_url: str, username: str | None) -> str:
    """Retrieve access token based on username and password.

    If a username is not given, read it interactively (but only if on
    a TTY).  Read the password interactively when on a TTY, or from
    stdin otherwise.
    """
    if not username:
        if not sys.stdin.isatty():
            raise SystemExit("error: no username or API key provided")
        # Read username, writing prompt to TTY if possible and to
        # stderr as a fallback, so this works well inside shell
        # command substitutions.
        prompt = "Username: "
        try:
            with open("/dev/tty", "w") as tty:
                tty.write(prompt)
        except Exception:
            print(prompt, end="", file=sys.stderr, flush=True)
        username = sys.stdin.readline().strip()
    password = getpass() if sys.stdin.isatty() else sys.stdin.readline().strip()
    try:
        return _get_jwt_token(base_url, username, password)
    except ClientError as e:
        raise SystemExit(f"error logging in: {e.args[0]}") from e


def get_client(args: argparse.Namespace) -> Client:
    """Return a smartextract client based on CLI options."""
    timeout = args.timeout if args.timeout > 0 else None
    api_key = os.getenv("SMARTEXTRACT_API_KEY") or get_access_token(args.base_url, None)
    return Client(api_key=api_key, timeout=timeout, base_url=args.base_url)


def pygments_formatter(args: argparse.Namespace) -> str | None:
    """Decide whether colorize output and, if so, which formatter suits the terminal."""
    if not (args.color and args.output_file.isatty()):
        return None
    try:
        import pygments
    except ModuleNotFoundError:
        logger.info("pygments not found, disabling color output")
        return None
    term, colorterm = os.getenv("TERM", ""), os.getenv("COLORTERM")
    if colorterm == "truecolor" or "truecolor" in term:
        return "terminal16m"
    elif colorterm == "256color" or "256color" in term:
        return "terminal256"
    elif colorterm or "color" in term:
        return "terminal"
    return None


def get_dumper(args: argparse.Namespace) -> Callable:
    """Return a function to print objects with the format chosen on the CLI."""
    stream = args.output_file

    def jsonify(v: Any) -> Any:
        return TypeAdapter(Any).dump_python(v, mode="json")

    if args.output_format == "json":

        def dump(v: Any):
            json.dump(jsonify(v), stream, indent=2)
            stream.write("\n")

    elif args.output_format == "yaml":
        try:
            import yaml
        except ModuleNotFoundError:
            raise RuntimeError("YAML output requires the PyYAML package") from None

        def dump(v: Any):
            yaml.safe_dump(jsonify(v), stream, sort_keys=False)

    else:
        raise RuntimeError("Invalid output format")

    # If using color output, patch dump function
    formatter = pygments_formatter(args)
    if formatter:
        from pygments import highlight
        from pygments.formatters import get_formatter_by_name
        from pygments.lexers import get_lexer_by_name

        orig_dump = dump
        orig_stream = stream
        stream = io.StringIO()

        def dump(v: Any):
            orig_dump(v)
            stream.seek(0)
            highlight(
                stream.read(),
                get_lexer_by_name(args.output_format),
                get_formatter_by_name(formatter),
                outfile=orig_stream,
            )

    return dump


## CLI definition

cli = argparse.ArgumentParser(
    description="Make requests to the smartextract API.",
    formatter_class=argparse.RawDescriptionHelpFormatter,
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
    metavar="URL",
    help="base URL of the API",
)
cli.add_argument(
    "--timeout",
    default=DEFAULT_TIMEOUT,
    type=int,
    metavar="SECONDS",
    help="network timeout in seconds (0 for no timeout)",
)
cli.add_argument(
    "--color",
    default=True,
    action=argparse.BooleanOptionalAction,
    help="colorize output (requires the pygments package)",
)
cli.add_argument(
    "-f",
    "--output-format",
    default="json",
    choices=["json", "yaml"],
    help="data output format (default: json)",
)
cli.add_argument(
    "-o",
    "--output-file",
    type=argparse.FileType("w"),
    default=sys.stdout,
    metavar="FILE",
    help="output file name (default: stdout)",
)

subcommands = cli.add_subparsers(
    required=True,
    metavar="command",
    help="one of the commands listed below",
)
subcommand_groups: dict[str, dict[str, argparse.ArgumentParser]] = {}


def subcommand(
    name: str,
    *,
    group: str,
    handler: Callable[[argparse.Namespace], None],
    aliases: list[str] | None = None,
    **kwargs,
) -> argparse.ArgumentParser:
    """Define a subcommand."""
    if aliases is None:
        aliases = ["".join(s[0] for s in name.split("-"))]
    subcmd = subcommands.add_parser(
        name,
        aliases=aliases,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        **kwargs,
    )
    subcmd.set_defaults(handler=handler)
    if group not in subcommand_groups:
        subcommand_groups[group] = {}
    subcommand_groups[group][name] = subcmd
    return subcmd


optional_user_arg = drop_none(
    nargs="?",
    default="me",
    help="email or ID of the user (yourself if omitted)",
)

### User management

get_user_info = subcommand(
    "get-user-info",
    group="User management",
    description="Display information about a user.",
    handler=lambda args: get_dumper(args)(
        get_client(args).get_user_info(args.username)
    ),
)
get_user_info.add_argument("username", **optional_user_arg)


def do_set_user_credits(args: argparse.Namespace):
    """Call client.set_user_credits and display user info."""
    client = get_client(args)
    dump = get_dumper(args)
    client.set_user_credits(
        args.username, new_credits=args.new_credits, balance=args.balance
    )
    dump(client.get_user_info(args.username))


set_user_credits = subcommand(
    "set-user-credits",
    group="User management",
    description="Add credits to the user's balance.",
    handler=do_set_user_credits,
)
set_user_credits.add_argument("username", help="email or ID of the user")
set_user_credits.add_argument("--balance", "-b", help="set a new balance")
set_user_credits.add_argument(
    "-c", "--new-credits", help="add credits to current balance"
)


list_user_jobs = subcommand(
    "list-user-jobs",
    group="User management",
    description="List pipeline runs triggered by the user.",
    handler=lambda args: get_dumper(args)(
        get_client(args).list_user_jobs(args.username)
    ),
)
list_user_jobs.add_argument("username", **optional_user_arg)

### Resource management

get_resource_info = subcommand(
    "get-resource-info",
    group="Resource management",
    description="Display information about a resource.",
    handler=lambda args: get_dumper(args)(
        get_client(args).get_resource_info(args.id_or_alias)
    ),
)
get_resource_info.add_argument("id_or_alias", help="Resource UUID or resource alias")

list_resources = subcommand(
    "list-resources",
    group="Resource management",
    description="List all resources available for pipelines.",
    handler=lambda args: get_dumper(args)(
        get_client(args).list_resources(type=args.type)
    ),
)
list_resources.add_argument(
    "type",
    nargs="?",
    choices=[
        "lua_pipeline",
        "template_pipeline",
        "page_processor",
        "image_processor",
        "google_ocr",
        "aws_ocr",
        "openai_chat",
        "inbox",
    ],
    help="Filter by resource type.",
)

list_lua_pipelines = subcommand(
    "list-lua-pipelines",
    group="Resource management",
    description="List all lua pipelines of this user.",
    handler=lambda args: get_dumper(args)(get_client(args).list_lua_pipelines()),
)


list_template_pipelines = subcommand(
    "list-template-pipelines",
    group="Resource management",
    description="List all template pipelines of this user.",
    handler=lambda args: get_dumper(args)(get_client(args).list_template_pipelines()),
)


list_inboxes = subcommand(
    "list-inboxes",
    group="Resource management",
    description="List all inboxes of this user.",
    handler=lambda args: get_dumper(args)(get_client(args).list_inboxes()),
)


list_permissions = subcommand(
    "list-permissions",
    group="Resource management",
    description="List users with access to the specified resource.",
    handler=lambda args: get_dumper(args)(
        get_client(args).list_permissions(args.id_or_alias)
    ),
)
list_permissions.add_argument("id_or_alias", help="Resource UUID or resource alias")


create_permission = subcommand(
    "create-permission",
    group="Resource management",
    description="Grant a user permission to access a resource.",
    handler=lambda args: get_client(args).create_permission(
        args.resource, args.username, args.level
    ),
)
create_permission.add_argument("resource", help="resource ID or alias")
create_permission.add_argument(
    "level",
    help="new access level",
    default="edit",
    choices=[v.value for v in AccessLevel],
)
create_permission.add_argument("username", help="user to be granted new permissions")

### Pipelines

create_lua_pipeline = subcommand(
    "create-lua-pipeline",
    group="Pipelines",
    description="Create an extraction pipeline based on a Lua script.",
    handler=lambda args: get_dumper(args)(
        get_client(args).create_lua_pipeline(args.name, args.script.read())
    ),
)
create_lua_pipeline.add_argument(
    "-n", "--name", default="Lua pipeline", help="name of the new pipeline"
)
create_lua_pipeline.add_argument(
    "script", help="path of the Lua script", type=argparse.FileType("r")
)


def cli_template(template: str) -> str | dict:
    """CLI type for extraction templates (template ID of JSON file name)."""
    try:
        f = argparse.FileType("r")(template)
    except argparse.ArgumentTypeError:
        return template
    return json.load(f)


create_template_pipeline = subcommand(
    "create-template-pipeline",
    group="Pipelines",
    description="Create an extraction pipeline based on a template.",
    handler=lambda args: get_dumper(args)(
        get_client(args).create_template_pipeline(
            args.name,
            args.template,
            ocr_id=args.ocr,
            chat_id=args.chat,
        )
    ),
)
create_template_pipeline.add_argument(
    "-n", "--name", default="Template pipeline", help="name of the new pipeline"
)
create_template_pipeline.add_argument(
    "template",
    type=cli_template,
    help="template ID or file containing an extraction template in JSON format",
)
create_template_pipeline.add_argument("--ocr", help="ID or alias of OCR resource")
create_template_pipeline.add_argument("--chat", help="ID or alias of chat resource")


modify_pipeline = subcommand(
    "modify-pipeline",
    group="Pipelines",
    description="""\
Change some details of the pipeline.

Any details not provided as a switch are left unchanged.
""",
    handler=lambda args: get_client(args).modify_pipeline(
        pipeline_id=args.pipeline,
        name=args.name,
        code=args.script and args.script.read(),
        template=args.template,
        ocr_id=args.ocr or None,
        chat_id=args.chat or None,
    ),
)
modify_pipeline.add_argument(
    "pipeline", help="ID or alias of the pipeline to be changed."
)
modify_pipeline.add_argument("--name", help="a new name for the pipeline")
modify_pipeline.add_argument(
    "--script", type=argparse.FileType("r"), help="path of a Lua script"
)
modify_pipeline.add_argument(
    "--template",
    type=cli_template,
    help="template ID or file containing an extraction template in JSON format",
)
modify_pipeline.add_argument("--ocr", help="ID or alias of OCR resource")
modify_pipeline.add_argument("--chat", help="ID or alias of chat resource")


run_pipeline = subcommand(
    "run-pipeline",
    group="Pipelines",
    description="Run a pipeline, returning extraction data.",
    handler=lambda args: get_dumper(args)(
        get_client(args).run_pipeline(args.pipeline, args.document)
    ),
)
run_pipeline.add_argument("pipeline", help="ID or alias of pipeline")
run_pipeline.add_argument(
    "document", type=argparse.FileType("rb"), help="path of document to be processed"
)


run_anonymous_pipeline = subcommand(
    "run-anonymous-pipeline",
    group="Pipelines",
    description="Process document with a Lua script or extraction template.",
    handler=lambda args: get_dumper(args)(
        get_client(args).run_anonymous_pipeline(
            document=args.document,
            code=args.script and args.script.read(),
            template=args.template,
        )
    ),
)
run_anonymous_pipeline.add_argument(
    "document", type=argparse.FileType("rb"), help="path of document to be processed"
)
run_anonymous_pipeline.add_argument(
    "-s", "--script", type=argparse.FileType("r"), help="path of the Lua script"
)
run_anonymous_pipeline.add_argument(
    "-t",
    "--template",
    type=cli_template,
    help="JSON file containing an extraction template",
)


list_pipeline_jobs = subcommand(
    "list-pipeline-jobs",
    group="Pipelines",
    description="List pipeline runs.",
    handler=lambda args: get_dumper(args)(
        get_client(args).list_pipeline_jobs(args.pipeline)
    ),
)
list_pipeline_jobs.add_argument("pipeline", help="ID or alias of pipeline")


list_templates = subcommand(
    "list-templates",
    group="Pipelines",
    description="List predefined extraction templates.",
    handler=lambda args: get_dumper(args)(get_client(args).list_templates(args.lang)),
)
list_templates.add_argument(
    "-l",
    "--lang",
    metavar="LANG",
    choices=Language.__args__,  # type: ignore[attr-defined]
    default="en",
    help="the template language, as a 2-character code (default: en)",
)

### Inboxes

create_inbox = subcommand(
    "create-inbox",
    group="Inboxes",
    description="Create an inbox to store and process documents.",
    handler=lambda args: get_dumper(args)(
        get_client(args).create_inbox(args.name, args.pipeline, ocr_id=args.ocr)
    ),
)
create_inbox.add_argument("name", help="Name of the inbox.")
create_inbox.add_argument("pipeline", help="ID or alias of the extraction pipeline")
create_inbox.add_argument("--ocr", help="OCR used for document display in the web UI")


modify_inbox = subcommand(
    "modify-inbox",
    group="Inboxes",
    description="""\
Change some details of the inbox.

Existing extractions of inbox documents are not automatically
recomputed.
""",
    handler=lambda args: get_client(args).modify_inbox(
        args.inbox,
        name=args.name,
        ocr_id=args.ocr,
        pipeline_id=args.pipeline,
    ),
)
modify_inbox.add_argument("inbox", help="ID of the inbox")
modify_inbox.add_argument("--name", help="New name of the inbox")
modify_inbox.add_argument("--pipeline", help="ID of the extraction pipeline")
modify_inbox.add_argument("--ocr", help="OCR used in document display in frontend.")


create_document = subcommand(
    "create-document",
    group="Inboxes",
    description="Upload a document to the inbox.",
    handler=lambda args: get_dumper(args)(
        get_client(args).create_document(args.inbox, args.document)
    ),
)
create_document.add_argument("inbox", help="ID of the inbox")
create_document.add_argument(
    "document",
    type=argparse.FileType("rb"),
    help="path of the document to be uploaded",
)


list_documents = subcommand(
    "list-documents",
    group="Inboxes",
    description="List documents in the inbox.",
    handler=lambda args: get_dumper(args)(get_client(args).list_documents(args.inbox)),
)
list_documents.add_argument(
    "inbox", help="Specify UUID of the inbox containing the documents."
)


list_extractions = subcommand(
    "list-extractions",
    group="Inboxes",
    description="Retrieve extraction results in batches.",
    handler=lambda args: get_dumper(args)(
        get_client(args).list_extractions(args.inbox)
    ),
)
list_extractions.add_argument("inbox", help="ID of the inbox")


list_inbox_jobs = subcommand(
    "list-inbox-jobs",
    group="Inboxes",
    description="List pipeline runs triggered by documents of the inbox.",
    handler=lambda args: get_dumper(args)(get_client(args).list_inbox_jobs(args.inbox)),
)
list_inbox_jobs.add_argument("inbox", help="ID of the inbox.")

### Documents

get_document_info = subcommand(
    "get-document-info",
    group="Documents",
    description="Get information about a document.",
    handler=lambda args: get_dumper(args)(
        get_client(args).get_document_info(args.document)
    ),
)
get_document_info.add_argument("document", help="ID of the document")


get_document_contents = subcommand(
    "get-document-contents",
    group="Documents",
    description="Download the document itself.",
    handler=lambda args: args.output_file.buffer.write(
        get_client(args).get_document_bytes(args.document)
    ),
)
get_document_contents.add_argument("document", help="ID of the document")


get_document_extraction = subcommand(
    "get-document-extraction",
    group="Documents",
    description="Get document extraction.",
    handler=lambda args: get_dumper(args)(
        get_client(args).get_document_extraction(args.document)
    ),
)
get_document_extraction.add_argument("document", help="ID of the document")


delete_document = subcommand(
    "delete-document",
    group="Documents",
    description="Permanently delete a document.",
    handler=lambda args: get_client(args).delete_document(args.document),
)
delete_document.add_argument("document", help="ID of the document")

### Miscellaneous

login = subcommand(
    "login",
    group="Miscellaneous",
    description="Print a temporary API key.",
    handler=lambda args: print(
        get_access_token(args.base_url, args.username),
        file=args.output_file,
    ),
)
login.add_argument(
    "username",
    nargs="?",
    help="user's email (if omitted, ask interactively)",
)


def generate_completion(shell: str | None) -> str:
    """Generate a completion script for the given shell type."""
    try:
        import pycomplete  # type: ignore[import-untyped]
    except ImportError:
        raise SystemExit(
            "generating completions requires the pycomplete package"
        ) from None
    return pycomplete.Completer(cli).render(shell)


completion = subcommand(
    "completion",
    group="Miscellaneous",
    description="""\
Print a shell completion script.

The procedure to activate this depends on your shell.  For bash, try
one of the following options:

  # Current session only
  eval "$(smartextract completion)"
  # Eager loading (restart required)
  smartextract completion >> ~/.bash_completion
  # Lazy loading (restart required)
  smartextract completion > ~/.local/share/bash-completion/completions/smartextract
""",
    handler=lambda args: print(
        generate_completion(args.shell),
        file=args.output_file,
    ),
)
completion.add_argument(
    "shell",
    nargs="?",
    help="shell type (bash, zsh, fish or powershell; if omitted, try to guess)",
)
## Final considerations

# Construct epilog message
epilog: list[str] = []
for name, subcmds in subcommand_groups.items():
    if name:
        epilog.append("")
    epilog.append(f"{name}:")
    for name, subcmd in subcmds.items():
        descr = subcmd.description or ""
        if "\n" in descr:
            descr = descr[: descr.index("\n")]
        epilog.append(f"  {name:<24}  {descr}")
cli.epilog = "\n".join(epilog)


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

    # Dispatch subcommand
    args.handler(args)


if __name__ == "__main__":
    main()
