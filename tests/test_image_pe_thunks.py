"""Test find_incremental_thunks: the thunk table of an incremental link"""

import struct
from reccmp.formats.pe import find_incremental_thunks

BASE = 0x401000


def jmp(src: int, dest: int) -> bytes:
    """A 5-byte relative JMP at address src to address dest."""
    return b"\xe9" + struct.pack("<i", dest - (src + 5))


def thunk_table(dests: list[int]) -> bytes:
    return b"".join(jmp(BASE + 5 * i, dest) for i, dest in enumerate(dests))


def test_table():
    code = thunk_table([0x401040, 0x401050]) + b"\xcc" * 0x36 + b"\x55" * 0x20
    expected = [(0x401000, 0x401040), (0x401005, 0x401050)]
    assert find_incremental_thunks(code, BASE) == expected
    assert find_incremental_thunks(code, BASE, strict=True) == expected


def test_no_table():
    code = b"\x55\x8b\xec" + b"\xcc" * 0x20
    assert not find_incremental_thunks(code, BASE)
    assert not find_incremental_thunks(code, BASE, strict=True)


def test_table_at_end_of_section():
    """The table fills the section: no padding to check, and no partial read."""
    code = thunk_table([0x401000]) + b"\xe9\x00"
    assert find_incremental_thunks(code, BASE) == [(0x401000, 0x401000)]
    assert not find_incremental_thunks(code, BASE, strict=True)


def test_strict_requires_padding():
    """A function that starts with a JMP is not a thunk table."""
    code = thunk_table([0x401010]) + b"\x90" * 0x0B + b"\xc3" + b"\xcc" * 0x10
    assert len(find_incremental_thunks(code, BASE)) == 1
    assert not find_incremental_thunks(code, BASE, strict=True)


def test_strict_requires_targets_in_section():
    code = thunk_table([0x401020, 0x500000]) + b"\xcc" * 0x40
    assert len(find_incremental_thunks(code, BASE)) == 2
    assert not find_incremental_thunks(code, BASE, strict=True)


def test_strict_requires_targets_past_table():
    code = thunk_table([0x401020, 0x401000]) + b"\xcc" * 0x40
    assert len(find_incremental_thunks(code, BASE)) == 2
    assert not find_incremental_thunks(code, BASE, strict=True)


def test_memoryview():
    """Code regions hand out memoryviews of the image."""
    code = thunk_table([0x401010]) + b"\xcc" * 0x20
    assert find_incremental_thunks(memoryview(code), BASE, strict=True) == [
        (0x401000, 0x401010)
    ]
