# License: CC0 1.0 Universal
# Author: opatuo
import binaryninja


def backward(
    variable: binaryninja.mediumlevelil.SSAVariable,
    function: binaryninja.function.Function,
) -> binaryninja.variable.Variable:
    variable_definition = function.mlil.get_ssa_var_definition(variable)

    for variable in variable_definition.ssa_form.vars_read:
        if isinstance(variable, binaryninja.mediumlevelil.SSAVariable):
            next_variable = backward(variable, function)
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
