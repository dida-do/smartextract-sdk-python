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

from pydantic import JsonValue, TypeAdapter

from smartextract import (
    DEFAULT_BASE_URL,
    DEFAULT_TIMEOUT,
    AccessLevel,
    BillingScheme,
    Client,
    ClientError,
    Language,
    _get_jwt_token,
    drop_none,
)

logger = logging.getLogger("smartextract")


## Helper functions


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
            json.dump(jsonify(v), stream, indent=2, ensure_ascii=False)
            stream.write("\n")

    elif args.output_format == "yaml":
        try:
            import yaml
        except ModuleNotFoundError:
            raise RuntimeError("YAML output requires the PyYAML package") from None

        def dump(v: Any):
            yaml.safe_dump(jsonify(v), stream, sort_keys=False, allow_unicode=True)

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


def json_argument(data_or_file: str) -> JsonValue:
    """A CLI argument type accepting a file name and returning its content as JSON."""
    if data_or_file.startswith("@"):
        file = argparse.FileType("r")(data_or_file[1:])
    else:
        file = None
    try:
        return json.load(file) if file else json.loads(data_or_file)
    except Exception as e:
        where = file.name if file else "command line"
        raise argparse.ArgumentTypeError(
            f"Error reading JSON data from {where}: {e}"
        ) from e


json_argument_help = "either a literal JSON value or @FILENAME to read from a file"


def template_argument(template: str) -> JsonValue:
    """CLI type for extraction templates (template ID of JSON file name)."""
    return template[1:] if template.startswith("#") else json_argument(template)


template_argument_help = (
    "extraction template (literal JSON value or #NAME.LANG to use"
    " a predefined template or @FILENAME to read from a file)"
)


def key_value_argument(s: str) -> tuple[str, str]:
    """A CLI argument type of the form KEY=VALUE."""
    k, sep, v = s.partition("=")
    if sep != "=":
        raise argparse.ArgumentTypeError("Argument should be of the form KEY=VALUE")
    return (k, v)


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
        args.username,
        new_credits=args.new_credits,
        balance=args.balance,
        billing_scheme=args.billing_scheme,
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
    "-c",
    "--new-credits",
    help="add credits to current balance",
)
set_user_credits.add_argument(
    "-s",
    "--billing-scheme",
    help="change the user's billing scheme",
    type=BillingScheme,
)


list_user_jobs = subcommand(
    "list-user-jobs",
    group="User management",
    description="List pipeline runs triggered by the user.",
    handler=lambda args: get_dumper(args)(
        get_client(args).list_user_jobs(args.username, errors_only=args.errors_only)
    ),
)
list_user_jobs.add_argument("username", **optional_user_arg)
list_user_jobs.add_argument(
    "-e",
    "--errors-only",
    action="store_true",
    help="list only failed jobs",
)

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


def _do_create_permission(args):
    client, is_error = get_client(args), False
    for res in args.resource:
        for lv in AccessLevel:
            for user in getattr(args, lv.name) or ():
                try:
                    client.create_permission(res, user, lv)
                except ClientError as err:
                    is_error = True
                    logger.error(
                        "Can't give %s '%s' permission to %s: %s",
                        user,
                        lv.name,
                        res,
                        err.args[1],
                    )
    if is_error:
        raise SystemExit(1)


create_permission = subcommand(
    "create-permission",
    group="Resource management",
    description="Grant users permission to access the given resources.",
    handler=_do_create_permission,
)
create_permission.add_argument("resource", help="resource ID or alias", nargs="+")
for lv in AccessLevel:
    create_permission.add_argument(
        f"-{lv.name[0]}",
        f"--{lv.name}",
        help=f"user to be granted '{lv.name}' permission",
        action="append",
        metavar="USER",
    )

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
    type=template_argument,
    help=template_argument_help,
)
create_template_pipeline.add_argument("--ocr", help="ID or alias of OCR resource")
create_template_pipeline.add_argument("--chat", help="ID or alias of extraction LLM")


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
        ocr_id=args.ocr,
        chat_id=args.chat,
        location_chat_id=args.location_chat,
        use_vision=args.use_vision,
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
    type=template_argument,
    help=template_argument_help,
)
modify_pipeline.add_argument("--ocr", help="ID or alias of OCR resource")
modify_pipeline.add_argument("--chat", help="ID or alias of extraction LLM")
modify_pipeline.add_argument(
    "--location-chat", help="ID or alias of location analysis LLM"
)
modify_pipeline.add_argument(
    "--use-vision",
    action=argparse.BooleanOptionalAction,
    help="Enable or disable LLM vision.",
)


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
    type=template_argument,
    help=template_argument_help,
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
        get_client(args).get_document_extraction(
            args.document,
            recompute=args.recompute,
        )
    ),
)
get_document_extraction.add_argument("document", help="ID of the document")
get_document_extraction.add_argument(
    "-r",
    "--recompute",
    help="recompute extraction instead of returning a previously computed one",
    action="store_true",
)


set_document_extraction = subcommand(
    "set-document-extraction",
    group="Documents",
    description="Set document extraction.",
    handler=lambda args: get_client(args).set_document_extraction(
        args.document, args.extraction
    ),
)
set_document_extraction.add_argument("document", help="ID of the document")
set_document_extraction.add_argument(
    "extraction",
    type=json_argument,
    help=f"new extraction data, {json_argument_help}",
)


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


def do_request(args: argparse.Namespace) -> None:
    """Perform an arbitrary API request."""
    client = get_client(args)
    dump = get_dumper(args)
    if "://" in args.endpoint:
        cli.print_usage()
        raise SystemExit(
            f"{cli.prog} request: error: argument endpoint: provide a relative path "
            f"excluding the initial {args.base_url}"
        )
    method = args.method or ("POST" if (args.file or args.json) else "GET")
    params = dict(args.param) if args.param else None
    files = dict(args.file) if args.file else None
    r = client._request(
        method,
        args.endpoint,
        params=params,
        files=files,
        json=args.json,
    )
    if r.headers.get("content-type") == "application/json":
        dump(r.json())


login = subcommand(
    "request",
    group="Miscellaneous",
    description="""\
Make an arbitrary request to the API.

This should be used only for debugging purposes.
""",
    handler=do_request,
)
login.add_argument(
    "endpoint",
)
login.add_argument(
    "-m",
    "--method",
    help="request method, such as GET, POST, PUT, PATCH, DELETE"
    " (default: GET, or POST if a request body is included)",
)
login.add_argument(
    "-p",
    "--param",
    help="query parameters to include in the request URL",
    action="append",
    metavar="KEY=VALUE",
    type=key_value_argument,
)
login.add_argument(
    "-f",
    "--file",
    help="form file to include in the request body",
    action="append",
    metavar="NAME=FILENAME",
    type=lambda arg: (
        (kv := key_value_argument(arg)) and (kv[0], argparse.FileType("rb")(kv[1]))
    ),
)
login.add_argument(
    "-j",
    "--json",
    help=f"request body data, {json_argument_help}",
    type=json_argument,
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
    try:
        args.handler(args)
    except ClientError as err:
        logger.error("%s", err.args[1])
        raise SystemExit(1) from err


if __name__ == "__main__":
    main()
