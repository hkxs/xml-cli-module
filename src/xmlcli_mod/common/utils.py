#
#  Copyright 2024 Hkxs
#
#  Permission is hereby granted, free of charge, to any person obtaining a copy
#  of this software and associated documentation files (the “Software”), to deal
#  in the Software without restriction, including without limitation the rights
#  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#  copies of the Software, and to permit persons to whom the Software is
#  furnished to do so, subject to the following conditions:
#
#  The above copyright notice and this permission notice shall be included in
#  all copies or substantial portions of the Software.
#
#  THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#  SOFTWARE.

import binascii
import os

from xmlcli_mod.common import constants as const


def is_root():
    return os.geteuid() == 0


def byte_to_int(data):
    return int(binascii.hexlify(bytearray(data)[::-1]), 16)


def int_to_byte(data, size):
    data_dump = data.to_bytes(size, byteorder="little", signed=False)
    return data_dump


def str_to_int(value: str) -> int:
    """Convert a string to an integer checking if it's a hex value"""
    if value.startswith("0x"):
        return int(value, 16)
    else:
        return int(value)


def read_buffer(input_buffer: bytearray, offset, size, input_type):
    """
    This function reads the desired format of data of specified size
    from the given offset of buffer.

    > Input buffer is in big endian ASCII format

    :param input_buffer: buffer from which data to be read
    :param offset: start offset from which data to be read
    :param size: size to be read from buffer
    :param input_type: format in which data can be read (ascii or hex)

    :return: buffer read from input
    """
    value_buffer = input_buffer[offset:offset + size]
    value_string = ""
    if not value_buffer or input_type not in [const.ASCII, const.HEX]:
        return 0
    if input_type == const.ASCII:
        value_string = "".join(chr(value) for value in value_buffer)
        return value_string
    if input_type == const.HEX:
        for value in value_buffer:
            value_string = f"{value:02x}" + value_string
        return int(value_string, 16)


def un_hex_li_fy(value):  # pragma: no cover, not used for now
    return binascii.unhexlify((hex(value)[2:]).strip("L")).decode()
