# License: CC0 1.0 Universal
# Author: opatuo
import binaryninja


def is_function_parameter(variable: binaryninja.mediumlevelil.SSAVariable):
    assert isinstance(variable, binaryninja.mediumlevelil.SSAVariable)
    return variable.var.is_parameter_variable


def find_last_ssa_variable_backward(variable: binaryninja.mediumlevelil.SSAVariable):
    assert isinstance(variable, binaryninja.mediumlevelil.SSAVariable)

    while variable.def_site is not None:
        if len(variable.def_site.vars_read) == 0:
            break
        new_variable = variable.def_site.vars_read[0]
        if not isinstance(new_variable, binaryninja.mediumlevelil.SSAVariable):
            break
        variable = new_variable
    return variable


def backward(
    function: binaryninja.function.Function,
    variable: binaryninja.mediumlevelil.SSAVariable,
) -> tuple[binaryninja.function.Function, binaryninja.variable.Variable]:

    variable = find_last_ssa_variable_backward(variable)

    if is_function_parameter(variable):
        return function, variable

    for operand in variable.def_site.detailed_operands:
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
    for operand in variable.def_site.detailed_operands:
        string, variable_read, variable_type = operand
        if string == "output":
            # TODO: variable_read[0] might be a SSAVariable
            return function, variable_read[0].var  # TODO: could be multiple outputs
