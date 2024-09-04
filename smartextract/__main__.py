"""CLI for the smartextract SDK."""

import argparse
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
    Client,
    ClientError,
    _get_jwt_token,
)


def handler(subcommand: argparse.ArgumentParser):
    """Define a handler for a subcommand."""

    def register(f: Callable[[Client, argparse.Namespace], None]):
        subcommand.set_defaults(handler=f)
        return f

    return register


def print_obj(v: Any):
    """Print object content in readable format."""
    v = TypeAdapter(Any).dump_python(v, mode="json")
    print(json.dumps(v, indent=2))


def do_login(base_url, username) -> str:
    """Retrieve access token based on username and password."""
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
    help="base URL of the API",
)
cli.add_argument(
    "--timeout",
    default=DEFAULT_TIMEOUT,
    type=int,
    help="network timeout in seconds (0 for no timeout)",
)

subcommands = cli.add_subparsers(
    required=True,
    metavar="command",
    help="one of the subcommands listed below",
)
subcommand_groups = {}


def subcommand(name, *, group, **kwargs):
    """Define a subcommand."""
    subcmd = subcommands.add_parser(
        name,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        **kwargs,
    )
    if group not in subcommand_groups:
        subcommand_groups[group] = {}
    subcommand_groups[group][name] = subcmd
    return subcmd


optional_user_arg = dict(  # noqa: C408
    nargs="?",
    default="me",
    help="email or ID of the user (yourself if omitted)",
)

## Authentication

get_api_key = subcommand(
    "get-api-key",
    group="Authentication and user management",
    description="Print a temporary API key.",
)
get_api_key.add_argument(
    "username",
    nargs="?",
    help="user's email (if omitted, ask interactively or read from stdin)",
)
get_api_key.set_defaults(handler=do_login)

list_templates = subcommands.add_parser(
    "list-templates",
    description="List all templates available for extractions pipelines.",
)
list_templates.add_argument(
    "-l",
    "--lang",
    metavar="LANG",
    choices=["en", "de"],
    default="en",
    help="the template language, as a 2-character code (default: en)",
)


@handler(list_templates)
def _(client: Client, args: argparse.Namespace):
    print_obj(client.list_templates(args.lang))


## User Management

get_user_info = subcommand(
    "get-user-info",
    group="Authentication and user management",
    description="Display information about a user.",
)
get_user_info.add_argument("username", **optional_user_arg)


@handler(get_user_info)
def _(client: Client, args: argparse.Namespace):
    print_obj(client.get_user_info(args.username))


set_user_credits = subcommand(
    "set-user-credits",
    group="Authentication and user management",
    description="Add credits to a user's balance.",
)
set_user_credits.add_argument("username", help="email or ID of the user")
set_user_credits.add_argument("--balance", "-b", help="set a new balance")
set_user_credits.add_argument(
    "-c", "--new-credits", help="add credits to current balance"
)


@handler(set_user_credits)
def _(client: Client, args: argparse.Namespace):
    client.set_user_credits(
        args.username, new_credits=args.new_credits, balance=args.balance
    )
    print_obj(client.get_user_info(args.username))


list_user_jobs = subcommand(
    "list-user-jobs",
    group="Authentication and user management",
    description="List all pipeline runs triggered by user.",
)
list_user_jobs.add_argument("username", **optional_user_arg)


@handler(list_user_jobs)
def _(client: Client, args: argparse.Namespace):
    print_obj(client.list_user_jobs(args.username))


## Resource management

list_resources = subcommand(
    "list-resources",
    group="Resource management",
    description="List all resources available for pipelines.",
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
list_lua_pipelines = subcommands.add_parser(
    "list-lua-pipelines", description="List all lua pipelines of this user."
)
list_template_pipelines = subcommands.add_parser(
    "list-template-pipelines", description="List all template pipelines of this user."
)
list_inboxes = subcommands.add_parser(
    "list-inboxes", description="List all inboxes of this user."
)
list_inbox_documents = subcommands.add_parser(
    "list-inbox-documents", description="List all documents inside an inbox."
)
list_inbox_documents.add_argument(
    "inbox", help="Specify UUID of the inbox containing the documents."
)

get_resource_info = subcommand(
    "get-resource-info",
    group="Resource management",
    description="Get resource-type specific information.",
)
get_resource_info.add_argument("id_or_alias", help="Resource UUID or resource alias")

list_permissions = subcommand(
    "list-permissions",
    group="Resource management",
    description="See which users have access to the specified resource.",
)
list_permissions.add_argument("id_or_alias", help="Resource UUID or resource alias")


create_permission = subcommand(
    "create-permission",
    group="Resource management",
    description="See which users have access to the specified resource.",
)
create_permission.add_argument("id_or_alias", help="Resource UUID or resource alias")
create_permission.add_argument(
    "username", nargs="?", help="Give permission to this user"
)
create_permission.add_argument(
    "-l",
    "--level",
    nargs="?",
    help="Permission level",
    default="edit",
    choices=["own", "edit", "view", "list", "run", "none"],
)


@handler(list_resources)
def _(client: Client, args: argparse.Namespace):
    print_obj(client.list_resources(type=args.type))


@handler(list_lua_pipelines)
def _(client: Client, args: argparse.Namespace):
    print_obj(client.list_lua_pipelines())


@handler(list_template_pipelines)
def _(client: Client, args: argparse.Namespace):
    print_obj(client.list_template_pipelines())


@handler(list_inboxes)
def _(client: Client, args: argparse.Namespace):
    print_obj(client.list_inboxes())


@handler(list_inbox_documents)
def _(client: Client, args: argparse.Namespace):
    print_obj(client.list_inbox_documents(args.inbox))


@handler(get_resource_info)
def _(client: Client, args: argparse.Namespace):
    print_obj(client.get_resource_info(args.id_or_alias))


@handler(list_permissions)
def _(client: Client, args: argparse.Namespace):
    print_obj(client.list_permissions(args.id_or_alias))


@handler(create_permission)
def _(client: Client, args: argparse.Namespace):
    client.create_permission(args.id_or_alias, args.username, args.level)


## Pipelines


create_lua_pipeline = subcommand(
    "create-lua-pipeline",
    group="Pipelines",
    description="Create an extraction pipeline based on a Lua script.",
)
create_lua_pipeline.add_argument(
    "-n", "--name", default="Lua pipeline", help="name of the new pipeline"
)
create_lua_pipeline.add_argument(
    "script", help="path of the Lua script", type=argparse.FileType("r")
)


@handler(create_lua_pipeline)
def _(client: Client, args: argparse.Namespace):
    print_obj(client.create_lua_pipeline(args.name, args.script.read()))


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


@handler(create_template_pipeline)
def _(client: Client, args: argparse.Namespace):
    print_obj(
        client.create_template_pipeline(
            args.name,
            args.template,
            ocr_id=args.ocr,
            chat_id=args.chat,
        )
    )


modify_pipeline = subcommand(
    "modify-pipeline",
    group="Pipelines",
    description="""\
Change some details of the pipeline.

Any details not provided as a switch are left unchanged.
""",
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


@handler(modify_pipeline)
def _(client: Client, args: argparse.Namespace):
    client.modify_pipeline(
        pipeline_id=args.pipeline,
        name=args.name,
        code=args.script and args.script.read(),
        template=args.template,
        ocr_id=args.ocr or None,
        chat_id=args.chat or None,
    )


run_pipeline = subcommand(
    "run-pipeline",
    group="Pipelines",
    description="Run a pipeline, returning extraction data.",
)
run_pipeline.add_argument("pipeline", help="ID or alias of pipeline")
run_pipeline.add_argument(
    "document", type=argparse.FileType("rb"), help="path of document to be processed"
)


@handler(run_pipeline)
def _(client: Client, args: argparse.Namespace):
    print_obj(client.run_pipeline(args.pipeline, args.document))


run_anonymous_pipeline = subcommand(
    "run-anonymous-pipeline",
    group="Pipelines",
    description="Process document with a Lua script or extraction template.",
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


@handler(run_anonymous_pipeline)
def _(client: Client, args: argparse.Namespace):
    print_obj(
        client.run_anonymous_pipeline(
            document=args.document,
            code=args.script and args.script.read(),
            template=args.template,
        )
    )


list_pipeline_jobs = subcommand(
    "list-pipeline-jobs", group="Pipelines", description="List all pipeline runs."
)
list_pipeline_jobs.add_argument("pipeline", help="ID or alias of pipeline")


@handler(list_pipeline_jobs)
def _(client: Client, args: argparse.Namespace):
    print_obj(client.list_pipeline_jobs(args.pipeline))


## Inboxes

create_inbox = subcommand(
    "create-inbox",
    group="Inboxes",
    description="""Create inbox to to store document extractions,
generated by a given extraction pipeline.""",
)
create_inbox.add_argument("name", help="Name of the inbox.")
create_inbox.add_argument("pipeline", help="ID or alias of the extraction pipeline")
create_inbox.add_argument("--ocr", help="OCR used for document display in the web UI")


@handler(create_inbox)
def _(client: Client, args: argparse.Namespace):
    print_obj(client.create_inbox(args.name, args.pipeline, ocr_id=args.ocr))


modify_inbox = subcommand(
    "modify-inbox",
    group="Inboxes",
    description="""\
Change some details of the inbox.

Existing extractions of inbox documents are not automatically
recomputed.
""",
)
modify_inbox.add_argument("inbox", help="ID of the inbox")
modify_inbox.add_argument("--name", help="New name of the inbox")
modify_inbox.add_argument("--pipeline", help="ID of the extraction pipeline")
modify_inbox.add_argument("--ocr", help="OCR used in document display in frontend.")


@handler(modify_inbox)
def _(client: Client, args: argparse.Namespace):
    client.modify_inbox(
        args.inbox,
        name=args.name,
        ocr_id=args.ocr,
        pipeline_id=args.pipeline,
    )


list_inbox_jobs = subcommand(
    "list-inbox-jobs",
    group="Inboxes",
    description="List all pipeline jobs of a given inbox.",
)
list_inbox_jobs.add_argument("inbox", help="ID of the inbox.")


@handler(list_inbox_jobs)
def _(client: Client, args: argparse.Namespace):
    print_obj(client.list_inbox_jobs(args.inbox))


create_document = subcommand(
    "create-document", group="Inboxes", description="Upload document to inbox."
)
create_document.add_argument("inbox", help="ID of the inbox")
create_document.add_argument(
    "document",
    type=argparse.FileType("rb"),
    help="path of the document to be uploaded",
)


@handler(create_document)
def _(client: Client, args: argparse.Namespace):
    print_obj(client.create_document(args.inbox, args.document))


list_inbox_extraction = subcommand(
    "list-inbox-extraction",
    group="Inboxes",
    description="List all extraction results of an inbox.",
)
list_inbox_extraction.add_argument("inbox", help="ID of the inbox")


@handler(list_inbox_extraction)
def _(client: Client, args: argparse.Namespace):
    print_obj(client.list_inbox_extraction(args.inbox))


## Documents

get_document_info = subcommand(
    "get-document-info",
    group="Documents",
    description="Get information about a stored document.",
)
get_document_info.add_argument("document", help="ID of the document")


@handler(get_document_info)
def _(client: Client, args: argparse.Namespace):
    print_obj(client.get_document_info(args.document))


delete_document = subcommand(
    "delete-document",
    group="Documents",
    description="Delete document from database.",
)
delete_document.add_argument("document", help="ID of the document")


@handler(delete_document)
def _(client: Client, args: argparse.Namespace):
    client.delete_document(args.document)


get_document_bytes = subcommand(
    "get-document-bytes",
    group="Documents",
    description="Download the document itself.",
)
get_document_bytes.add_argument("document", help="ID of the document")
get_document_bytes.add_argument(
    "-o",
    "--output",
    type=argparse.FileType("wb"),
    default=sys.stdout.buffer,
    help="output file name (default: stdout)",
)


@handler(get_document_bytes)
def _(client: Client, args: argparse.Namespace):
    args.output.write(client.get_document_bytes(args.document))


get_document_extraction = subcommand(
    "get-document-extraction",
    group="Documents",
    description="Get document extraction.",
)
get_document_extraction.add_argument("document", help="ID of the document")


@handler(get_document_extraction)
def _(client: Client, args: argparse.Namespace):
    print_obj(client.get_document_extraction(args.document))


## Final considerations

# Construct epilog message
_: list = []  # type: ignore[no-redef]
for name, subcmds in subcommand_groups.items():
    if name:
        _.append("")
    _.append(f"{name}:")
    for name, subcmd in subcmds.items():
        descr = subcmd.description
        if "\n" in descr:
            descr = descr[: descr.index("\n")]
        _.append(f"  {name:<24}  {descr}")
cli.epilog = "\n".join(_)


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
