#!/usr/bin/env python3
# License: CC0 1.0 Universal
# Author: opatuo
import binaryninja
import argparse


def get_calls_to(binary_view: binaryninja.binaryview.BinaryView, function_name: str):
    symbol = binary_view.get_symbol_by_raw_name(function_name)
    if not symbol:
        return iter(())
    return binary_view.get_code_refs(symbol.address)


def get_variables_at(
    function: binaryninja.function.Function,
    reference: binaryninja.binaryview.ReferenceSource,
):
    function_mlil = function.mlil
    instruction = function_mlil[
        function_mlil.get_instruction_start(reference.address)
    ].ssa_form
    return instruction.params


# Return the variable that initializes the type in function
def get_initialization_of_type(
    binary_view: binaryninja.binaryview.BinaryView,
    function: binaryninja.function.Function,
    name: str,
) -> binaryninja.mediumlevelil.SSAVariable:
    type_reference = binary_view.types[name]
    for reference in binary_view.get_code_refs_for_type(name):
        for variable in reference.mlil.ssa_form.vars_read:
            if variable.type == type_reference and variable.function == function:
                return variable
    raise binaryninja.exceptions.ILException


def perform_backward_slice(
    variable: binaryninja.mediumlevelil.SSAVariable,
    function: binaryninja.function.Function,
):
    variable_definition = function.mlil.get_ssa_var_definition(variable.ssa_form)
    for operand in variable_definition.detailed_operands:
        string, variable_read, variable_type = operand
        if string == "src":
            # could be the address of another variable or function call
            if (
                variable_read.ssa_form.operation
                == binaryninja.enums.MediumLevelILOperation.MLIL_ADDRESS_OF
            ):
                return variable_read.src
            # if variable_read.is_parameter_variable:


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
            socket_fd, sockaddr, sockaddr_size = get_variables_at(caller, reference)
            original_sockaddr = perform_backward_slice(sockaddr, caller)
            # TODO: retype variable to sockaddr_in if sockaddr_size is 0x10
            original_sockaddr.type, _ = binary_view.parse_type_string("sockaddr_in")
            in_port_t = get_initialization_of_type(binary_view, caller, "in_port_t")
            print(in_port_t)
            # do another backward slice to determine the value of sin_port
            # repeat above with sin_addr
            # find assignment to socket_fd
            # get arguments to socket(3) call
            # print results
