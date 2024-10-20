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

import os
import platform
import pytest

from pathlib import Path

from xmlcli_mod import xmlcli
from xmlcli_mod.access.linux import linux
from xmlcli_mod.common import constants as const


@pytest.fixture
def valid_xml_file():
    return  """<SYSTEM>
             <biosknobs>
             <knob type='scalar' name='TestKnob' description='Test Description' CurrentVal='1' default='0' size='1' offset='0x10' />
             <knob type='string' name='StringKnob' description='Test Description' CurrentVal='b' default='a' size='1' offset='0x20' />
             </biosknobs>
             </SYSTEM>
             """


@pytest.fixture
def io_data():
    io_data = [
        0xde,  # LSB dram_shared_mb_addr
        0xc0,  # MSB dram_shared_mb_addr
        # repeat because we call get_dram_mb_addr during verification and during reading xml, remove when refactoring
        0xde,  # LSB dram_shared_mb_addr
        0xc0,  # MSB dram_shared_mb_addr
    ]
    return io_data


@pytest.fixture
def mem_data():
    mem_data = [
        const.SHAREDMB_SIG1,  # dram_shared_mb_signature_1
        const.SHAREDMB_SIG2,  # dram_shared_mb_signature_2
        0x1,  # CliSpecRelVersion
        0x2,  # CliSpecMajorVersion
        0x3,  # CliSpecMinorVersion
        const.LEGACYMB_SIG+1,  # not legacy signature, so no fix leg
        # repeat because we call get_dram_mb_addr during verification and during reading xml, remove when refactoring
        const.SHAREDMB_SIG1,  # dram_shared_mb_signature_1
        const.SHAREDMB_SIG2,  # dram_shared_mb_signature_2
        0x1,  # CliSpecRelVersion
        0x2,  # CliSpecMajorVersion
        0x3,  # CliSpecMinorVersion
        const.LEGACYMB_SIG + 1,  # not legacy signature, so no fix leg
        #
        const.SHAREDMB_SIG1,
        const.SHAREDMB_SIG2,
    ]
    return mem_data


@pytest.fixture
def mem_block_data(valid_xml_file):
    mem_block_data = [
        bytearray([0x11, 0xba, 0x5e, 0xba,  # SHAREDMB_SIG1
                   0, 0, 0, 0,
                   0x11, 0xba, 0x5e, 0xba,  # SHAREDMB_SIG1
                   0, 0, 0, 0,
                   0, 0, 0, 0,
                   0, 0, 0, 0,
                   0, 0, 0, 0,
                   0, 0, 0, 0,
                   0xfe, 0xca, 0x7e, 0x5a]),  # LEGACYMB_SIG
        b"<SYSTEM>",
        b"</SYSTEM>",
        bytearray(valid_xml_file.encode())
    ]

    return mem_block_data

@pytest.fixture
def xmlcli_obj(io_data, mem_data, mem_block_data, mocker):
    access_path = Path(linux.__file__)
    access_path.with_name("port.so").touch()
    access_path.with_name("mem.so").touch()
    mocker.patch.object(platform, "system", return_value="Linux")
    mocker.patch.object(xmlcli, "is_root", return_value=True)
    mocker.patch.object(linux.LinuxAccess, "_setup_mem_library")
    mocker.patch.object(linux.LinuxAccess, "_setup_port_library")
    mocker.patch.object(linux.LinuxAccess, "write_io")
    mocker.patch.object(linux.LinuxAccess, "read_io", side_effect=io_data)
    mocker.patch.object(linux.LinuxAccess, "mem_read", side_effect=mem_data)
    mocker.patch.object(linux.LinuxAccess, "mem_read", side_effect=mem_data)
    mocker.patch.object(linux.LinuxAccess, "mem_block", side_effect=mem_block_data)
    yield xmlcli.XmlCli()
    os.remove(access_path.with_name("port.so"))
    os.remove(access_path.with_name("mem.so"))
