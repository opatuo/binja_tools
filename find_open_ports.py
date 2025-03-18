#!/usr/bin/env python3
# License: CC0 1.0 Universal
# Author: opatuo
import binaryninja
import argparse
import ipaddress
import sys
from collections.abc import Iterable
import socket
from pathlib import Path


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
    names: list[str],
) -> binaryninja.mediumlevelil.SSAVariable:
    for name in names:
        type_reference = binary_view.types[name]
        for reference in binary_view.get_code_refs_for_type(name):
            for variable in reference.mlil.ssa_form.vars_read:
                if variable.type == type_reference and variable.function == function:
                    return variable
    raise binaryninja.exceptions.ILException


def get_initialization_of_type_at(
    binary_view: binaryninja.binaryview.BinaryView,
    function: binaryninja.function.Function,
    name: str,
    offset: int,
):
    for reference in binary_view.get_code_refs_for_type_field(name, offset):
        instruction = function.mlil[
            function.mlil.get_instruction_start(reference.address)
        ].ssa_form
        return instruction.src
    raise Exception(f"Unable to find a reference to {name} at {offset}")


def perform_backward_slice(
    variable: binaryninja.mediumlevelil.SSAVariable,
    function: binaryninja.function.Function,
) -> binaryninja.variable.Variable:
    variable_definition = function.mlil.get_ssa_var_definition(variable)

    for variable in variable_definition.ssa_form.vars_read:
        if isinstance(variable, binaryninja.mediumlevelil.SSAVariable):
            next_variable = perform_backward_slice(variable, function)
            if not isinstance(next_variable, binaryninja.mediumlevelil.SSAVariable):
                return next_variable

    for operand in variable_definition.detailed_operands:
        string, variable_read, variable_type = operand
        if string == "src":
            # could be the address of another variable or function call
            # TODO: need to find the SSAVariable that is the source
            if (
                variable_read.ssa_form.operation
                == binaryninja.enums.MediumLevelILOperation.MLIL_ADDRESS_OF
            ):
                return variable_read.src
            # if variable_read.is_parameter_variable:
            return variable

    # No more src variables, parse expression for output
    for operand in variable_definition.detailed_operands:
        string, variable_read, variable_type = operand
        if string == "output":
            return variable_read[0]  # TODO: could be multiple outputs


def find_constant(instruction: binaryninja.mediumlevelil.MediumLevelILInstruction):
    if isinstance(instruction, binaryninja.mediumlevelil.MediumLevelILConst):
        return str(instruction)


def get_function_parameter_at_initialization_of(
    variable: binaryninja.variable.Variable,
    function: binaryninja.function.Function,
    index: int,
) -> str:
    variable_definitions = function.mlil.get_var_definitions(variable)
    counter = 0
    for definition in variable_definitions:
        for operand in definition.detailed_operands:
            string, variables, variable_type = operand
            if string == "params":
                if index >= len(variables):
                    raise Exception(
                        f"Function only has {len(variables)} parameters where index is {index}"
                    )
                variable = variables[index]
                if not isinstance(
                    variable, binaryninja.mediumlevelil.MediumLevelILConst
                ):
                    raise Exception(
                        f"Function parameter at index {index} is not a constant."
                    )
                return int(variable.value.value)


def socket_type_to_string(sock_type: int):
    if sock_type == socket.SOCK_STREAM:
        return "TCP"
    if sock_type == socket.SOCK_DGRAM:
        return "UDP"
    if sock_type == socket.SOCK_RAW:
        return "RAW"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="Find Open Ports", description="Search a binary for open ports"
    )
    parser.add_argument("filename")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    if not args.verbose:
        binaryninja.disable_default_log()

    with binaryninja.load(args.filename) as binary_view:
        print(f"{Path(args.filename).stem}:")
        for reference in get_calls_to(binary_view, "bind"):
            callers = binary_view.get_functions_containing(reference.address)
            for caller in callers:
                socket_fd, sockaddr, sockaddr_size = get_variables_at(caller, reference)

                # TODO: original_sockaddr should be a SSAVariable
                original_sockaddr = perform_backward_slice(sockaddr.ssa_form, caller)

                sockaddr_len = int(str(sockaddr_size), 16)
                if sockaddr_len == 16:
                    # Find socket call
                    original_socket_fd = perform_backward_slice(socket_fd, caller)
                    socket_type_value = get_function_parameter_at_initialization_of(
                        original_socket_fd, caller, 1
                    )
                    socket_type = socket_type_to_string(socket_type_value)

                    original_sockaddr.type, _ = binary_view.parse_type_string(
                        "sockaddr_in"
                    )

                    in_port_t = get_initialization_of_type(
                        binary_view, caller, ["in_port_t"]
                    )
                    original_port_t = perform_backward_slice(in_port_t, caller)
                    port_value = get_function_parameter_at_initialization_of(
                        original_port_t, caller, 0
                    )
                    print(f"\t{socket_type} PORT == {port_value}")

                    sin_addr = get_initialization_of_type_at(
                        binary_view, caller, "sockaddr_in", 4
                    )
                    original_sin_addr = perform_backward_slice(sin_addr, caller)
                    address_value = get_function_parameter_at_initialization_of(
                        original_sin_addr, caller, 0
                    )
                    print(f"\tADDRESS  == {str(ipaddress.IPv4Address(address_value))}")
                else:
                    raise Exception(f"Unknown sockaddr length: {sockaddr_len}")
