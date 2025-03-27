import binaryninja
from binjalib import varslice


def calls_to(binary_view: binaryninja.binaryview.BinaryView, function_name: str):
    symbol = binary_view.get_symbol_by_raw_name(function_name)
    if not symbol:
        return iter(())
    return binary_view.get_code_refs(symbol.address)


def variables_at(reference: binaryninja.binaryview.ReferenceSource):
    function_mlil = reference.function.mlil
    instruction = function_mlil[
        function_mlil.get_instruction_start(reference.address)
    ].ssa_form
    return instruction.params


# Return the variable that initializes the type in function
def initialization_of_type(
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
    raise Exception(f"Unable to find the initialization of {name} in the binary")


def initialization_of_type_at(
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


def function_parameter_at_initialization_of(
    variable: binaryninja.variable.Variable,
    function: binaryninja.function.Function,
    index: int,
) -> int:
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


def function_parameter_initialization_of(
    variable: binaryninja.mediumlevelil.SSAVariable,
    function: binaryninja.function.Function,
    index: int,
) -> int:
    function, original = varslice.backward(function, variable)
    return function_parameter_at_initialization_of(original, function, index)
