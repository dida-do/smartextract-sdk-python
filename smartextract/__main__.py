"""CLI for the smartextract SDK."""

import json
import logging
import os
import sys
from argparse import ArgumentParser, Namespace
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


def handler(subcommand: ArgumentParser):
    """Define a handler for a subcommand."""

    def register(f: Callable[[Client, Namespace, int], None]):
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

list_templates = subcommands.add_parser(
    "list-templates",
    description="List all templates available for extractions pipelines.",
)
list_templates.add_argument("--lang", "-l", nargs="?", choices=["en", "de"])


@handler(list_templates)
def _(client: Client, args: Namespace):
    print_obj(client.list_templates(args.lang or "en"))


# User Management

get_user_info = subcommands.add_parser(
    "get-user-info", description="Display information about a user."
)
get_user_info.add_argument("--username", "-u", nargs="?", help="Email of the user")


@handler(get_user_info)
def _(client: Client, args: Namespace):
    print_obj(client.get_user_info(args.username))


set_user_credits = subcommands.add_parser(
    "set-user-credits",
    description="Update a users's credits. Processing a document consumes credits.",
)
set_user_credits.add_argument("username", help="Email of the user")
set_user_credits.add_argument("--balance", "-b", nargs="?", help="Set a new balance.")
set_user_credits.add_argument(
    "-c",
    "--new-credits",
    nargs="?",
    help="Add credits to current balance.",
)


@handler(set_user_credits)
def _(client: Client, args: Namespace):
    client.set_user_credits(
        args.username, new_credits=args.new_credits, balance=args.balance
    )
    print_obj(client.get_user_info(args.username))


list_user_jobs = subcommands.add_parser(
    "list-jobs", description="List all pipeline runs."
)
list_user_jobs.add_argument(
    "--username", "-u", nargs="?", help="List jobs of this user."
)


@handler(list_user_jobs)
def _(client: Client, args: Namespace):
    print_obj(client.list_user_jobs(args.username or "me"))


# Resource Management

list_resources = subcommands.add_parser(
    "list-resources", description="List all resources available for pipelines."
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
    "inbox_id", help="Specify UUID of the inbox containing the documents."
)

get_resource_info = subcommands.add_parser(
    "get-resource-info", description="Get resource-type specific information."
)
get_resource_info.add_argument("id_or_alias", help="Resource UUID or resource alias")

list_permissions = subcommands.add_parser(
    "list-permissions",
    description="See which users have access to the specified resource.",
)
list_permissions.add_argument("id_or_alias", help="Resource UUID or resource alias")


create_permission = subcommands.add_parser(
    "create-permission",
    description="See which users have access to the specified resource.",
)
create_permission.add_argument("id_or_alias", help="Resource UUID or resource alias")
create_permission.add_argument(
    "username", nargs="?", help="Give permission to this user"
)
create_permission.add_argument(
    "--level",
    "-l",
    nargs="?",
    help="Permission level",
    default="edit",
    choices=["own", "edit", "view", "list", "run", "none"],
)


@handler(list_resources)
def _(client: Client, args: Namespace):
    print_obj(client.list_resources(type=args.type))


@handler(list_lua_pipelines)
def _(client: Client, args: Namespace):
    print_obj(client.list_lua_pipelines())


@handler(list_template_pipelines)
def _(client: Client, args: Namespace):
    print_obj(client.list_template_pipelines())


@handler(list_inboxes)
def _(client: Client, args: Namespace):
    print_obj(client.list_inboxes())


@handler(list_inbox_documents)
def _(client: Client, args: Namespace):
    print_obj(client.list_inbox_documents(args.inbox_id))


@handler(get_resource_info)
def _(client: Client, args: Namespace):
    print_obj(client.get_resource_info(args.id_or_alias))


@handler(list_permissions)
def _(client: Client, args: Namespace):
    print_obj(client.list_permissions(args.id_or_alias))


@handler(create_permission)
def _(client: Client, args: Namespace):
    client.create_permission(args.id_or_alias, args.username, args.level)


# Pipelines


def _prepare_template(template: str):
    if not template:
        return None

    if isinstance(template, str) and (".en" in template or ".de" in template):
        # Template is valid string
        return template

    elif os.path.exists(template):
        with open(template, "r") as file:
            return json.loads(file.read())
    else:
        raise ValueError("Not a valid template. See list-templates for reference.")


def _prepare_lua_script(code: str):
    if os.path.exists(code):
        with open(code, "r") as file:
            return file.read()

    return None


create_lua_pipeline = subcommands.add_parser(
    "create-lua-pipeline",
    description="Create extraction pipeline based on a lua script.",
)
create_lua_pipeline.add_argument("name", nargs="?", help="Name your new pipeline.")
create_lua_pipeline.add_argument(
    "lua_script", nargs="?", help="Path of the .lua script."
)


@handler(create_lua_pipeline)
def _(client: Client, args: Namespace):
    with open(args.lua_script, "r") as file:
        print_obj(client.create_lua_pipeline(args.name, file.read()))


create_template_pipeline = subcommands.add_parser(
    "create-template-pipeline",
    description="Create extraction pipeline based on a template.",
)
create_template_pipeline.add_argument("name", nargs="?", help="Name your new pipeline.")
create_template_pipeline.add_argument(
    "template", nargs="?", help="Either string of template.id or path to JSON template."
)
create_template_pipeline.add_argument("--ocr", help="Id or alias of ocr resource.")
create_template_pipeline.add_argument("--chat", help="Id or alias of chat resource.")


@handler(create_template_pipeline)
def _(client: Client, args: Namespace):
    print_obj(
        client.create_template_pipeline(
            args.name,
            _prepare_template(args.template),
            ocr_id=args.ocr or None,
            chat_id=args.chat or None,
        )
    )


modify_pipeline = subcommands.add_parser(
    "modify-pipeline",
    description="Change details of the pipeline.",
)
modify_pipeline.add_argument(
    "pipeline_id", help="Id or alias of pipeline to be changed."
)
modify_pipeline.add_argument("--name", help="New name of the pipeline.")
modify_pipeline.add_argument("--lua_script", nargs="?", help="Path of the .lua script.")
modify_pipeline.add_argument(
    "--template",
    nargs="?",
    help="Either string of template.id or path to JSON template.",
)
modify_pipeline.add_argument("--ocr", help="Id or alias of ocr resource.")
modify_pipeline.add_argument("--chat", help="Id or alias of chat resource.")


@handler(modify_pipeline)
def _(client: Client, args: Namespace):
    client.modify_pipeline(
        pipeline_id=args.pipeline_id,
        name=args.name,
        code=_prepare_lua_script(args.lua_script),
        template=_prepare_template(args.template),
        ocr_id=args.ocr or None,
        chat_id=args.chat or None,
    )


run_pipeline = subcommands.add_parser(
    "run-pipeline", description="Run document through this pipeline."
)
run_pipeline.add_argument("pipeline_id", help="Id or alias of pipeline.")
run_pipeline.add_argument("document_path", help="Path of document to be processed.")


@handler(run_pipeline)
def _(client: Client, args: Namespace):
    with open(args.document_path, "rb") as file:
        print_obj(client.run_pipeline(args.pipeline_id, file))


run_anonymous_pipeline = subcommands.add_parser(
    "run-anonymous-pipeline",
    description="""Process document by providing either
lua script or extraction template.""",
)
run_anonymous_pipeline.add_argument(
    "document_path", help="Path of document to be processed."
)
run_anonymous_pipeline.add_argument(
    "--lua_script", nargs="?", help="Path of the .lua script."
)
run_anonymous_pipeline.add_argument(
    "--template",
    nargs="?",
    help="Either string of template.id or path to JSON template.",
)


@handler(run_anonymous_pipeline)
def _(client: Client, args: Namespace):
    with open(args.document_path, "rb") as file:
        print_obj(
            client.run_anonymous_pipeline(
                file,
                code=_prepare_lua_script(args.lua_script),
                template=_prepare_template(args.template),
            )
        )


list_pipeline_jobs = subcommands.add_parser(
    "list-pipline-jobs", description="List all pipeline runs."
)
list_pipeline_jobs.add_argument("pipeline_id", help="Id or alias of pipeline.")


@handler(list_pipeline_jobs)
def _(client: Client, args: Namespace):
    print_obj(client.list_pipeline_jobs(args.pipeline_id))


# Inboxes

create_inbox = subcommands.add_parser(
    "create-inbox",
    description="""Create inbox to to store document extractions,
generated by a given extraction pipeline.""",
)
create_inbox.add_argument("name", help="Name of the inbox.")
create_inbox.add_argument("pipeline_id", help="Id of the extraction pipeline")
create_inbox.add_argument("--ocr_id", help="Ocr used in document display in frontend.")


@handler(create_inbox)
def _(client: Client, args: Namespace):
    print_obj(client.create_inbox(args.name, args.pipeline_id, ocr_id=args.ocr_id))


modify_inbox = subcommands.add_parser(
    "modify-inbox",
    description="Change name or pipeline of an inbox. Doesn't recompute extractions.",
)
modify_inbox.add_argument("inbox_id", help="Id of the inbox")
modify_inbox.add_argument("--name", help="Name of the inbox.")
modify_inbox.add_argument("--pipeline_id", help="Id of the extraction pipeline")
modify_inbox.add_argument("--ocr_id", help="Ocr used in document display in frontend.")


@handler(modify_inbox)
def _(client: Client, args: Namespace):
    client.modify_inbox(
        args.inbox_id,
        pipeline_id=args.pipeline_id,
        name=args.name,
        ocr_id=args.ocr_id,
    )


list_inbox_jobs = subcommands.add_parser(
    "list-inbox-jobs", description="List all pipeline jobs of a given inbox."
)
list_inbox_jobs.add_argument("inbox_id", help="Id of the inbox.")


@handler(list_inbox_jobs)
def _(client: Client, args: Namespace):
    print_obj(client.list_inbox_jobs(args.inbox_id))


create_document = subcommands.add_parser(
    "create-document", description="Upload document to inbox."
)
create_document.add_argument("inbox_id", help="Id of the inbox.")
create_document.add_argument(
    "document_path", help="Path of the document to be uploaded."
)


@handler(create_document)
def _(client: Client, args: Namespace):
    with open(args.document_path, "rb") as file:
        print_obj(client.create_document(args.inbox_id, file))


list_inbox_extraction = subcommands.add_parser(
    "list-inbox-extraction", description="List all extraction results of an inbox."
)
list_inbox_extraction.add_argument("inbox_id", help="Id of the inbox.")


@handler(list_inbox_extraction)
def _(client: Client, args: Namespace):
    print_obj(client.list_inbox_extraction(args.inbox_id))


# Documents

get_document_info = subcommands.add_parser(
    "get-document-info", description="Get information about a stored document."
)
get_document_info.add_argument("document_id", help="Id of the document.")


@handler(get_document_info)
def _(client: Client, args: Namespace):
    print_obj(client.get_document_info(args.document_id))


delete_document = subcommands.add_parser(
    "delete-document", description="Delete document from database."
)
delete_document.add_argument("document_id", help="Id of the document.")


@handler(delete_document)
def _(client: Client, args: Namespace):
    client.delete_document(args.document_id)


get_document_bytes = subcommands.add_parser(
    "get-document-bytes", description="Get document content"
)
get_document_bytes.add_argument("document_id", help="Id of the document.")


@handler(get_document_bytes)
def _(client: Client, args: Namespace):
    print(client.get_document_bytes(args.document_id))


get_document_extraction = subcommands.add_parser(
    "get-document-extraction", description="Get extraction from document in inbox."
)
get_document_extraction.add_argument("document_id", help="Id of the document.")


@handler(get_document_extraction)
def _(client: Client, args: Namespace):
    print_obj(client.get_document_extraction(args.document_id))


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
