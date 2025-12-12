"""
Mutation strategies for ALF.

Reusable mutation helpers for agents and breakpoint scripts.
"""

from __future__ import annotations

import random
import struct
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass

# Python 3.10+ supports slots=True, Python 3.9 doesn't
_dataclass_kwargs = {"slots": True} if sys.version_info >= (3, 10) else {}


@dataclass(**_dataclass_kwargs)
class MutationResult:
    data: bytearray
    description: str
    highlight_offset: int | None
    highlight_length: int


MutationStrategy = Callable[[bytearray], MutationResult]


INTERESTING_VALUES: list[int] = [
    0x7FFFFFFF,
    0x80000000,
    0x7FFFFFFFFFFFFFFF,
    0x8000000000000000,
    0xFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    2**32,
    2**64,
    -(2**31),
    -(2**63),
    0xDEADBEEF,
    0xCAFEBABE,
    0x41414141,
    0x42424242,
    0xFF,
    0x7F,
    0x80,
    1,
    -1,
    0x40000000,
    0x80000000,
    0xFFFFFFFF,
    0,
]


FORMAT_STRINGS: list[bytes] = [
    b"%s%n%x%d",
    b"%p%p%p%p",
    b"%x%x%x%x",
    b"%d%d%d%d",
    b"%s%s%s%s",
    b"A" * 4 + b"%n%n%n%n",
    b"%1$s%2$s%3$s%4$s",
]


def bit_flip_mutation(data: bytearray) -> MutationResult:
    if not data:
        return MutationResult(data, "Bit flip not performed (empty data)", None, 0)
    offset = random.randint(0, len(data) - 1)
    original_byte = data[offset]
    if original_byte in (0x00, 0xFF):
        num_bits = random.randint(2, 4)
        bits = random.sample(range(8), num_bits)
        for bit in bits:
            data[offset] ^= 1 << bit
    else:
        bit = random.randint(0, 7)
        data[offset] ^= 1 << bit
    if data[offset] == original_byte:
        data[offset] = random.randint(1, 255)
    desc = f"Bit flip at offset {offset}.\n\tOriginal: 0x{original_byte:02x}, Modified: 0x{data[offset]:02x}"
    return MutationResult(data, desc, offset, 1)


def byte_flip_mutation(data: bytearray) -> MutationResult:
    if not data:
        return MutationResult(data, "Byte flip not performed (empty data)", None, 0)
    offset = random.randint(0, len(data) - 1)
    original_byte = data[offset]
    new_byte = random.randint(1, 255)
    if new_byte == original_byte:
        new_byte = (new_byte + 1) % 256
    data[offset] = new_byte
    desc = f"Byte flip at offset {offset}.\n\tOriginal: 0x{original_byte:02x}, Modified: 0x{new_byte:02x}"
    return MutationResult(data, desc, offset, 1)


def interesting_value_mutation(data: bytearray) -> MutationResult:
    if len(data) < 8:
        return MutationResult(data, "Interesting value mutation not performed (data too small)", None, 0)
    offset = random.randint(0, len(data) - 8)
    original_bytes = data[offset : offset + 8]
    value = random.choice(INTERESTING_VALUES)
    attempts = 0
    while value == int.from_bytes(original_bytes[:8], "little") and attempts < 5:
        value = random.choice(INTERESTING_VALUES)
        attempts += 1
    struct.pack_into("<Q", data, offset, value & 0xFFFFFFFFFFFFFFFF)
    new_bytes = data[offset : offset + 8]
    desc = (
        f"Interesting value 0x{value:x} inserted at offset {offset}.\n\t"
        f"Original: {original_bytes.hex()}, Modified: {new_bytes.hex()}"
    )
    return MutationResult(data, desc, offset, 8)


def block_swap_mutation(data: bytearray) -> MutationResult:
    if len(data) <= 8:
        return MutationResult(data, "Block swap not performed (data too small)", None, 0)
    for _ in range(10):
        swap_size = random.randint(1, min(8, len(data) // 2))
        offset1 = random.randint(0, len(data) - swap_size)
        offset2 = random.randint(0, len(data) - swap_size)
        if (
            abs(offset1 - offset2) >= swap_size
            and data[offset1 : offset1 + swap_size] != data[offset2 : offset2 + swap_size]
        ):
            temp = data[offset1 : offset1 + swap_size].copy()
            data[offset1 : offset1 + swap_size] = data[offset2 : offset2 + swap_size]
            data[offset2 : offset2 + swap_size] = temp
            desc = f"Block swap: {swap_size} bytes swapped between offsets {offset1} and {offset2}"
            return MutationResult(data, desc, min(offset1, offset2), swap_size * 2)
    offset = random.randint(0, len(data) - 4)
    for i in range(4):
        data[offset + i] = random.randint(1, 255)
    desc = f"Block modification at offset {offset} (no suitable swap found)"
    return MutationResult(data, desc, offset, 4)


def boundary_value_mutation(data: bytearray) -> MutationResult:
    if len(data) < 4:
        return MutationResult(data, "Boundary value mutation not performed (data too small)", None, 0)
    boundary_values = [0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, 0]
    offset = random.randint(0, len(data) - 4)
    original_bytes = data[offset : offset + 4]
    original_value = struct.unpack("<I", original_bytes)[0]
    new_values = [v for v in boundary_values if v != original_value]
    new_value = random.choice(new_values) if new_values else original_value ^ 0xFFFFFFFF
    struct.pack_into("<I", data, offset, new_value)
    desc = (
        f"Boundary value 0x{new_value:x} at offset {offset}.\n\t"
        f"Original: 0x{original_value:08x}, Modified: 0x{new_value:08x}"
    )
    return MutationResult(data, desc, offset, 4)


def byte_increment_mutation(data: bytearray) -> MutationResult:
    if not data:
        return MutationResult(data, "Byte increment not performed (empty data)", None, 0)
    offset = random.randint(0, len(data) - 1)
    original_byte = data[offset]
    increment = random.randint(1, 32) if original_byte in (0x00, 0xFF) else 1
    data[offset] = (original_byte + increment) & 0xFF
    desc = (
        f"Byte increment by {increment} at offset {offset}.\n\t"
        f"Original: 0x{original_byte:02x}, Modified: 0x{data[offset]:02x}"
    )
    return MutationResult(data, desc, offset, 1)


def byte_decrement_mutation(data: bytearray) -> MutationResult:
    if not data:
        return MutationResult(data, "Byte decrement not performed (empty data)", None, 0)
    offset = random.randint(0, len(data) - 1)
    original_byte = data[offset]
    decrement = random.randint(1, 32) if original_byte in (0x00, 0xFF) else 1
    data[offset] = (original_byte - decrement) & 0xFF
    desc = (
        f"Byte decrement by {decrement} at offset {offset}.\n\t"
        f"Original: 0x{original_byte:02x}, Modified: 0x{data[offset]:02x}"
    )
    return MutationResult(data, desc, offset, 1)


def byte_random_add_mutation(data: bytearray) -> MutationResult:
    if not data:
        return MutationResult(data, "Byte random add not performed (empty data)", None, 0)
    offset = random.randint(0, len(data) - 1)
    add_value = random.randint(1, 255)
    original_byte = data[offset]
    data[offset] = (original_byte + add_value) & 0xFF
    desc = (
        f"Byte random add at offset {offset}. Added: {add_value}\n\t"
        f"Original: 0x{original_byte:02x}, Modified: 0x{data[offset]:02x}"
    )
    return MutationResult(data, desc, offset, 1)


def byte_random_subtract_mutation(data: bytearray) -> MutationResult:
    if not data:
        return MutationResult(data, "Byte random subtract not performed (empty data)", None, 0)
    offset = random.randint(0, len(data) - 1)
    subtract_value = random.randint(1, 255)
    original_byte = data[offset]
    data[offset] = (original_byte - subtract_value) & 0xFF
    desc = (
        f"Byte random subtract at offset {offset}. Subtracted: {subtract_value}\n\t"
        f"Original: 0x{original_byte:02x}, Modified: 0x{data[offset]:02x}"
    )
    return MutationResult(data, desc, offset, 1)


def byte_negate_mutation(data: bytearray) -> MutationResult:
    if not data:
        return MutationResult(data, "Byte negate not performed (empty data)", None, 0)
    offset = random.randint(0, len(data) - 1)
    original_byte = data[offset]
    data[offset] = (~original_byte) & 0xFF
    desc = f"Byte negate at offset {offset}.\n\tOriginal: 0x{original_byte:02x}, Modified: 0x{data[offset]:02x}"
    return MutationResult(data, desc, offset, 1)


def word_swap_mutation(data: bytearray) -> MutationResult:
    if len(data) < 4:
        return MutationResult(data, "Word swap not performed (data too small)", None, 0)
    offset = random.randint(0, len(data) - 4)
    original_word = struct.unpack("<I", data[offset : offset + 4])[0]
    swapped_word = struct.pack("<I", ((original_word & 0xFFFF) << 16) | ((original_word & 0xFFFF0000) >> 16))
    data[offset : offset + 4] = swapped_word
    desc = (
        f"Word swap at offset {offset}.\n\t"
        f"Original: 0x{original_word:08x}, Modified: 0x{struct.unpack('<I', swapped_word)[0]:08x}"
    )
    return MutationResult(data, desc, offset, 4)


def byte_repeat_mutation(data: bytearray) -> MutationResult:
    if len(data) < 2:
        return MutationResult(data, "Byte repeat not performed (data too small)", None, 0)
    offset = random.randint(0, len(data) - 2)
    repeat_byte = data[offset]
    data[offset + 1] = repeat_byte
    desc = f"Byte repeat at offset {offset}.\n\tRepeated byte: 0x{repeat_byte:02x}"
    return MutationResult(data, desc, offset, 2)


def null_byte_insertion_mutation(data: bytearray) -> MutationResult:
    if len(data) < 2:
        return MutationResult(data, "Null byte insertion not performed (data too small)", None, 0)
    offset = random.randint(0, len(data) - 1)
    data.insert(offset, 0)
    data.pop()
    desc = f"Null byte inserted at offset {offset}."
    return MutationResult(data, desc, offset, 1)


def string_mutation(data: bytearray) -> MutationResult:
    if len(data) < 4:
        return MutationResult(data, "String mutation not performed (data too small)", None, 0)
    offset = random.randint(0, len(data) - 4)
    length = min(random.randint(4, 20), len(data) - offset)
    original = data[offset : offset + length]
    mutation_type = random.choice(["format", "special_chars", "random_ascii", "overflow"])

    if mutation_type == "format":
        format_string = random.choice(FORMAT_STRINGS)
        mutation_len = min(len(format_string), length)
        data[offset : offset + mutation_len] = format_string[:mutation_len]
    elif mutation_type == "special_chars":
        special_chars = bytes(
            [random.choice([0x27, 0x22, 0x5C, 0x2F, 0x2E, 0x2D, 0x7C, 0x3C, 0x3E]) for _ in range(length)]
        )
        data[offset : offset + length] = special_chars
    elif mutation_type == "random_ascii":
        ascii_bytes = bytes([random.randint(0x21, 0x7E) for _ in range(length)])
        data[offset : offset + length] = ascii_bytes
    else:
        pattern_choices = [
            bytes([x % 256 for x in range(length)]),
            bytes([random.randint(0x41, 0x5A) for _ in range(length)]),
            b"A" * length,
            bytes([length % 256] * length),
        ]
        data[offset : offset + length] = random.choice(pattern_choices)

    desc = (
        f"String {mutation_type} at offset {offset}.\n\t"
        f"Original: {bytes(original)}, Modified: {bytes(data[offset : offset + length])}"
    )
    return MutationResult(data, desc, offset, length)


DEFAULT_STRATEGIES: list[MutationStrategy] = [
    bit_flip_mutation,
    byte_flip_mutation,
    interesting_value_mutation,
    block_swap_mutation,
    boundary_value_mutation,
    byte_increment_mutation,
    byte_decrement_mutation,
    byte_random_add_mutation,
    byte_random_subtract_mutation,
    byte_negate_mutation,
    word_swap_mutation,
    byte_repeat_mutation,
    null_byte_insertion_mutation,
    string_mutation,
]


def apply_random_mutation(
    data: bytes | bytearray,
    strategies: Sequence[MutationStrategy] = DEFAULT_STRATEGIES,
) -> MutationResult:
    """Choose a random strategy and apply it to a copy of `data`."""
    buf = data if isinstance(data, bytearray) else bytearray(data)
    strategy = random.choice(list(strategies))
    return strategy(buf)
