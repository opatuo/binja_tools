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


def get_variables_passed_to(function, reference):
    function_mlil = function.mlil
    call_instruction = function_mlil[
        function_mlil.get_instruction_start(reference.address)
    ].ssa_form
    return call_instruction.params


def perform_backward_slice(variable, function):
    variable_definition = function.mlil.get_ssa_var_definition(variable.ssa_form)
    for operand in variable_definition.detailed_operands:
        string, variable_read, variable_type = operand
        # if string == 'src':
        # could be the address of another variable or function call
    return variable_read
    perform_backward_slice(variable_list[0], function)


parser = argparse.ArgumentParser(
    prog="Find Open Ports", description="Search a binary for open ports"
)
parser.add_argument("filename")
parser.add_argument("--verbose", action="store_true")
args = parser.parse_args()

if not args.verbose:
    binaryninja.disable_default_log()

with binaryninja.load(args.filename) as binary_view:
    for reference in get_calls_to(binary_view, "bind"):
        callers = binary_view.get_functions_containing(reference.address)
        for caller in callers:
            socket_fd, sockaddr, sockaddr_size = get_variables_passed_to(
                caller, reference
            )
            original_sockaddr = perform_backward_slice(sockaddr, caller)
            # retype variable to sockaddr_in if sockaddr_size is 0x10
            # get references to sockaddr_in.sin_port within the function
            # do another backward slice to determine the value of sin_port
            # repeat above with sin_addr
            # find assignment to socket_fd
            # get arguments to socket(3) call
            # print results
