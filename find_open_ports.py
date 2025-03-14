#!/usr/bin/env python3
# License: CC0 1.0 Universal
# Author: opatuo
import binaryninja
import argparse


def get_calls_to(binary_view, function_name: str):
    symbol = binary_view.get_symbol_by_raw_name(function_name)
    if not symbol:
        return iter(())
    return binary_view.get_code_refs(symbol.address)


parser = argparse.ArgumentParser(
    prog="Find Open Ports", description="Search a binary for open ports"
)
parser.add_argument("filename")
parser.add_argument("--verbose", action="store_true")
args = parser.parse_args()

if not args.verbose:
    disable_default_log()

with binaryninja.load(args.filename) as binary_view:
    for reference in get_calls_to(binary_view, "bind"):
        callers = binary_view.get_functions_containing(reference.address)
        for caller in callers:
            pass
