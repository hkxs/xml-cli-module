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

#
#  Permission is hereby granted, free of charge, to any person obtaining a copy
#  of this software and associated documentation files (the “Software”), to deal
#  in the Software without restriction, including without limitation the rights
#  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#  copies of the Software, and to permit persons to whom the Software is
#  furnished to do so, subject to the following conditions:
#
#
import platform
from binascii import hexlify


import pytest

import xmlcli_mod.common.constants as const
from xmlcli_mod import xmlclilib

class TestIsLegValid:
    def test_is_leg_mb_sig_valid_not_valid(self, mocker):
        xmlclilib.CliSpecRelVersion = 0x0
        xmlclilib.CliSpecMajorVersion = 0x0

        mocker.patch.object(xmlclilib, "mem_read", side_effect=[0x0, 0x0])
        assert not xmlclilib.is_leg_mb_sig_valid(0xc0de)

        mocker.patch.object(xmlclilib, "mem_read", side_effect=[const.SHAREDMB_SIG1, 0x0])
        assert not xmlclilib.is_leg_mb_sig_valid(0xc0de)

        mocker.patch.object(xmlclilib, "mem_read", side_effect=[0x0, const.SHAREDMB_SIG2])
        assert not xmlclilib.is_leg_mb_sig_valid(0xc0de)


    def test_is_leg_mb_sig_valid_valid(self, mocker):
        xmlclilib.CliSpecRelVersion = 0x0
        xmlclilib.CliSpecMajorVersion = 0x0

        mocked_version = 0xbadc0de
        mocker.patch.object(xmlclilib, "get_cli_spec_version", return_value=mocked_version)
        mocker.patch.object(xmlclilib, "mem_read", side_effect=[const.SHAREDMB_SIG1, const.SHAREDMB_SIG2, mocked_version])

        assert xmlclilib.is_leg_mb_sig_valid(0xc0de) == mocked_version

    def test_is_leg_mb_sig_valid_legacy(self, mocker):
        xmlclilib.CliSpecRelVersion = 0x0
        xmlclilib.CliSpecMajorVersion = 0x0

        mocked_version = 0xbadc0de
        mocker.patch.object(xmlclilib, "get_cli_spec_version", return_value=mocked_version)
        mocker.patch.object(xmlclilib, "mem_read", side_effect=[const.SHAREDMB_SIG1, const.SHAREDMB_SIG2, const.LEGACYMB_SIG])

        assert xmlclilib.is_leg_mb_sig_valid(0xc0de) == mocked_version


class TestReadBuffer:
    def test_read_buffer_no_read(self):
        assert not xmlclilib.read_buffer(bytearray(b"c0de"), 0, 0, const.ASCII)

    def test_read_buffer_ascii(self):
        assert xmlclilib.read_buffer(bytearray(b"c0de"), 0, 1, const.ASCII) == "c"
        assert xmlclilib.read_buffer(bytearray(b"c0de"), 0, 2, const.ASCII) == "c0"
        assert xmlclilib.read_buffer(bytearray(b"c0de"), 1, 3, const.ASCII) == "0de"
        assert xmlclilib.read_buffer(bytearray(b"c0de"), 1, 5, const.ASCII) == "0de"  # test size out of bounds

    def test_read_buffer_hex(self):
        assert xmlclilib.read_buffer(bytearray(b"c0de"), 0, 1, const.HEX) == int(hexlify(b"c"), 16)
        assert xmlclilib.read_buffer(bytearray(b"c0de"), 0, 2, const.HEX) == int(hexlify(b"0c"), 16)
        assert xmlclilib.read_buffer(bytearray(b"c0de"), 1, 3, const.HEX) == int(hexlify(b"ed0"), 16)
        assert xmlclilib.read_buffer(bytearray(b"c0de"), 1, 5, const.HEX) == int(hexlify(b"ed0"), 16) # test size out of bounds

    def test_read_buffer_invalid_type(self):
        assert not xmlclilib.read_buffer(bytearray(b"c0de"), 0, 1, "other thing")


class TestGetDramMbAddr:
    def test_get_dram_mb_addr_zero(self, mocker):
        xmlclilib.gDramSharedMbAddr = 0
        mocker.patch.object(xmlclilib, "read_io", return_value=0)
        mocker.patch.object(xmlclilib, "write_io")
        mocker.patch.object(xmlclilib, "is_leg_mb_sig_valid", return_value=False)
        assert not xmlclilib.get_dram_mb_addr()

    def test_get_dram_mb_addr_reuse(self, mocker):
        xmlclilib.gDramSharedMbAddr = 0xc0de
        mocker.patch.object(xmlclilib, "read_io", return_value=0)
        mocker.patch.object(xmlclilib, "write_io")
        mocker.patch.object(xmlclilib, "get_cli_spec_version")
        mocker.patch.object(xmlclilib, "is_leg_mb_sig_valid", side_effect=[False, False, False])
        assert not xmlclilib.get_dram_mb_addr()

        mocker.patch.object(xmlclilib, "is_leg_mb_sig_valid", side_effect=[False, False, True])
        assert xmlclilib.get_dram_mb_addr() == 0xc0de

    def test_get_dram_mb_addr_valid_first_try(self, mocker):
        xmlclilib.gDramSharedMbAddr = 0
        mocker.patch.object(xmlclilib, "write_io")
        mocker.patch.object(xmlclilib, "read_io", side_effect=[0xde, 0xc0])
        mocker.patch.object(xmlclilib, "is_leg_mb_sig_valid", return_value=True)
        assert xmlclilib.get_dram_mb_addr() == 0xc0de0000

    def test_get_dram_mb_addr_valid_second_try(self, mocker):
        xmlclilib.gDramSharedMbAddr = 0
        mocker.patch.object(xmlclilib, "write_io")
        mocker.patch.object(xmlclilib, "get_cli_spec_version")
        mocker.patch.object(xmlclilib, "read_io", side_effect=[0x0, 0x0, 0xde, 0xc0])
        mocker.patch.object(xmlclilib, "is_leg_mb_sig_valid", side_effect=[False, True])
        assert xmlclilib.get_dram_mb_addr() == 0xc0de0000


class TestXmlValid:
    def test_is_xml_valid_invalid(self, mocker):
        mocker.patch.object(xmlclilib, "read_mem_block", side_effect=[b"bad", b"c0de"])
        assert not xmlclilib.is_xml_valid(0, 1)

        mocker.patch.object(xmlclilib, "read_mem_block", side_effect=[b"<SYSTEM>", b"c0de"])
        assert not xmlclilib.is_xml_valid(0, 1)

        mocker.patch.object(xmlclilib, "read_mem_block", side_effect=[b"bad", b"</SYSTEM>"])
        assert not xmlclilib.is_xml_valid(0, 1)

        mocker.patch.object(xmlclilib, "read_mem_block", side_effect=Exception)
        assert not xmlclilib.is_xml_valid(0, 1)

    def test_is_xml_valid(self, mocker):
        mocker.patch.object(xmlclilib, "read_mem_block", side_effect=[b"<SYSTEM>", b"</SYSTEM>"])
        assert xmlclilib.is_xml_valid(0, 1)


class TestAccess:
    def test_load_os_specific_access_invalid(self, mocker):
        mocker.patch.object(platform, "system", return_value="INVALID")

        with pytest.raises(RuntimeError) as e:
            xmlclilib.load_os_specific_access()
        assert "INVALID" in str(e.value)

    def test_load_os_specific_access_alid(self, mocker):
        from xmlcli_mod.access.linux import linux
        mocker.patch.object(platform, "system", return_value="Linux")
        mocker.patch.object(linux, "LinuxAccess")

        assert xmlclilib.load_os_specific_access()  # just check that we can "load" it


class TestFixLeg:

    @pytest.fixture
    def reset_variables(self):
        xmlclilib.CliSpecRelVersion = 0
        xmlclilib.CliSpecMajorVersion = 0
        xmlclilib.CliSpecMinorVersion = 0
        const.LEGACYMB_XML_OFF = 0


    def test_fix_leg_xml_offset_legacy(self, reset_variables):
        xmlclilib.CliSpecRelVersion = 1
        xmlclilib.fix_leg_xml_offset(0)
        assert const.LEGACYMB_XML_OFF == 0x50

    def test_fix_leg_xml_offset_major_less_seven(self, reset_variables):
        xmlclilib.CliSpecMajorVersion = 6
        xmlclilib.fix_leg_xml_offset(0)
        assert const.LEGACYMB_XML_OFF == 0xc

    def test_fix_leg_xml_offset_seven_one(self, reset_variables):
        xmlclilib.CliSpecMajorVersion = 7
        xmlclilib.CliSpecMinorVersion = 1
        xmlclilib.fix_leg_xml_offset(0)
        assert const.LEGACYMB_XML_OFF == 0x50

        xmlclilib.CliSpecMajorVersion = 8
        xmlclilib.CliSpecMinorVersion = 0
        xmlclilib.fix_leg_xml_offset(0)
        assert const.LEGACYMB_XML_OFF == 0x50

    def test_fix_leg_xml_offset_seven_zero(self, reset_variables, mocker):
        xmlclilib.CliSpecMajorVersion = 7
        xmlclilib.CliSpecMinorVersion = 0
        mocker.patch.object(xmlclilib, "mem_read", side_effect=[0, 0])
        xmlclilib.fix_leg_xml_offset(0)
        assert const.LEGACYMB_XML_OFF == 0x50

        mocker.patch.object(xmlclilib, "mem_read", side_effect=[0, 1])
        xmlclilib.fix_leg_xml_offset(0)
        assert const.LEGACYMB_XML_OFF == 0x4c

def test_get_version(mocker):
    xmlclilib.CliSpecRelVersion = 0
    xmlclilib.CliSpecMajorVersion = 0
    xmlclilib.CliSpecMinorVersion = 0
    mocker.patch.object(xmlclilib, "mem_read", side_effect=[1, 2, 3])
    assert "1.2.3" == xmlclilib.get_cli_spec_version(0)
    assert xmlclilib.CliSpecRelVersion == 1
    assert xmlclilib.CliSpecMajorVersion == 2
    assert xmlclilib.CliSpecMinorVersion == 3
