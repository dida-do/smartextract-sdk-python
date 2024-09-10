#!/usr/bin/env python
import argparse
import os
import re
import subprocess
import sys
from pathlib import Path
from tempfile import NamedTemporaryFile

patt = re.compile(r"\ba(sync|wait) +")

parser = argparse.ArgumentParser(description="Generate sync code from async code.")
parser.add_argument(
    "--check",
    action="store_true",
    help="Don't modify the input file, just check not changes would happen.",
)
parser.add_argument("file", type=argparse.FileType())
args = parser.parse_args()

# with open(code_dir / "__init__.py") as infile:
def generate_code(infile, outfile):
        for line in infile:
            outfile.write(line)
            if "# start of generated code" in line:
                break
        else:
            raise SystemExit("Can't find start of generated code block")

        infile.seek(0)
        for line in infile:
            if "# start of code template" in line:
                break
        else:
            raise SystemExit("Can't find start of template code block")

        for line in infile:
            if "# end of code template" in line:
                break
            line = patt.sub("", line)
            outfile.write(line)
        else:
            raise SystemExit("Can't find end of template code block")

        for line in infile:
            if "# end of generated code" in line:
                outfile.write(line)
                break
        else:
            raise SystemExit("Can't find end of generated code block")

        for line in infile:
            outfile.write(line)

infile = args.file
outfile = NamedTemporaryFile("r+t", dir=Path(infile.name).parent)
generate_code(infile, outfile)
outfile.flush()
subprocess.check_call(["hatch", "fmt", "-f", "--", "-q", outfile.name])

if args.check:
    infile.seek(0)
    outfile.seek(0)
    for i, (l1, l2) in enumerate(zip(infile, outfile, strict=True)):
        if l1 != l2:
            raise SystemExit(f"""\
{infile.name}:{i+1}: error: code generation would make a change
  from: {l1.rstrip()}
    to: {l2.rstrip()}""")
else:
    os.replace(outfile.name, infile.name)
