#!/usr/bin/env python3
# License: CC0 1.0 Universal
# Author: opatuo
import binaryninja
import argparse

parser = argparse.ArgumentParser(
    prog="Find Open Ports", description="Search a binary open ports"
)
parser.add_argument("filename")
args = parser.parse_args()

with binaryninja.load(args.filename) as bv:
    print(f"Opening {bv.file.filename} which has {len(list(bv.functions))} functions")
