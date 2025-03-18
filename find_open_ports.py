#!/usr/bin/env python3
# License: CC0 1.0 Universal
# Author: opatuo
import binaryninja
import argparse
import ipaddress


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
):
    variable_definition = function.mlil.get_ssa_var_definition(variable)

    for variable in variable_definition.ssa_form.vars_read:
        if isinstance(variable, binaryninja.mediumlevelil.SSAVariable):
            perform_backward_slice(variable, function)
    print(variable_definition)
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


def find_constant(instruction: binaryninja.mediumlevelil.MediumLevelILInstruction):
    if isinstance(instruction, binaryninja.mediumlevelil.MediumLevelILConst):
        return str(instruction)


def get_value_assigned_to(
    variable: binaryninja.mediumlevelil.SSAVariable,
    function: binaryninja.function.Function,
) -> str:
    variable_definition = function.mlil.get_ssa_var_definition(variable)
    for result in variable_definition.traverse(find_constant):
        return str(result)


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
                    print(original_socket_fd)
                    original_sockaddr.type, _ = binary_view.parse_type_string(
                        "sockaddr_in"
                    )

                    in_port_t = get_initialization_of_type(
                        binary_view, caller, ["in_port_t"]
                    )
                    original_port_t = perform_backward_slice(in_port_t, caller)
                    port_value = get_value_assigned_to(original_port_t, caller)
                    print(f"\tPORT    == {int(port_value, 16)}")

                    sin_addr = get_initialization_of_type_at(
                        binary_view, caller, "sockaddr_in", 4
                    )
                    original_sin_addr = perform_backward_slice(sin_addr, caller)
                    if original_sin_addr is None:  # TODO
                        original_sin_addr = sin_addr
                    address_value = get_value_assigned_to(original_sin_addr, caller)
                    address_value = int(address_value, 16)
                    print(f"\tADDRESS == {str(ipaddress.IPv4Address(address_value))}")
                else:
                    raise Exception(f"Unknown sockaddr length: {sockaddr_len}")
