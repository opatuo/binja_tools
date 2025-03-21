# License: CC0 1.0 Universal
# Author: opatuo
import binaryninja


def backward(
    function: binaryninja.function.Function,
    variable: binaryninja.mediumlevelil.SSAVariable,
) -> tuple[binaryninja.function.Function, binaryninja.variable.Variable]:
    variable_definition = function.mlil.get_ssa_var_definition(variable)

    if variable_definition is None:
        print(variable)
        return function, variable

    for variable in variable_definition.ssa_form.vars_read:
        if isinstance(variable, binaryninja.mediumlevelil.SSAVariable):
            function, next_variable = backward(function, variable)
            if not isinstance(next_variable, binaryninja.mediumlevelil.SSAVariable):
                return function, next_variable

    for operand in variable_definition.detailed_operands:
        string, variable_read, variable_type = operand
        if string == "src":
            # could be the address of another variable or function call
            if (
                variable_read.ssa_form.operation
                == binaryninja.enums.MediumLevelILOperation.MLIL_ADDRESS_OF
            ):
                return function, variable_read.src
            return function, variable

    # No more src variables, parse expression for output
    for operand in variable_definition.detailed_operands:
        string, variable_read, variable_type = operand
        if string == "output":
            return function, variable_read[0]  # TODO: could be multiple outputs
