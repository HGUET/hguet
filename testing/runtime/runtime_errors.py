"""Verify the exact expected runtime rejection, not just any failure."""
from solders.transaction_status import InstructionErrorCustom, TransactionErrorInstructionError


def assert_instruction_error(result, index, custom_code):
    error = result.err()
    assert isinstance(error, TransactionErrorInstructionError), repr(error)
    assert error.index == index, repr(error)
    assert isinstance(error.err, InstructionErrorCustom), repr(error)
    assert error.err.code == custom_code, repr(error)
    return {"instruction_index": index, "custom_error": custom_code}
