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

import platform
from binascii import hexlify

import pytest

import xmlcli_mod.common.constants as const
import xmlcli_mod.common.errors as err
from xmlcli_mod.common import utils
from xmlcli_mod import xmlclilib
from xmlcli_mod.dataclasses.spec_version import CliSpecVersion


@pytest.fixture()
def xmlcli_lib(mocker):
    mocker.patch.object(xmlclilib, "_load_os_specific_access")
    xmlcli_obj = xmlclilib.XmlCliLib()
    xmlcli_obj._dram_shared_mb_address = 0xbadc0de
    return xmlcli_obj


class TestIsLegValid:

    def test_is_leg_mb_sig_valid_not_valid(self, xmlcli_lib, mocker):
        mocker.patch.object(xmlcli_lib, "mem_read", side_effect=[0x0, 0x0])
        assert not xmlcli_lib.is_leg_mb_sig_valid(0xc0de)

        mocker.patch.object(xmlcli_lib, "mem_read", side_effect=[const.SHAREDMB_SIG1, 0x0])
        assert not xmlcli_lib.is_leg_mb_sig_valid(0xc0de)

        mocker.patch.object(xmlcli_lib, "mem_read", side_effect=[0x0, const.SHAREDMB_SIG2])
        assert not xmlcli_lib.is_leg_mb_sig_valid(0xc0de)

    def test_is_leg_mb_sig_valid_valid(self, xmlcli_lib, mocker):
        mocker.patch.object(xmlcli_lib, "mem_read", side_effect=[const.SHAREDMB_SIG1, const.SHAREDMB_SIG2, 0xc0de])
        assert xmlcli_lib.is_leg_mb_sig_valid(0xc0de)

    def test_is_leg_mb_sig_valid_legacy(self, xmlcli_lib, mocker):
        mocker.patch.object(xmlcli_lib, "fix_leg_xml_offset")
        mocker.patch.object(xmlcli_lib, "mem_read", side_effect=[const.SHAREDMB_SIG1, const.SHAREDMB_SIG2, const.LEGACYMB_SIG])
        assert xmlcli_lib.is_leg_mb_sig_valid(0xc0de)


class TestReadBuffer:
    def test_read_buffer_no_read(self):
        assert not utils.read_buffer(bytearray(b"c0de"), 0, 0, const.ASCII)

    def test_read_buffer_ascii(self):
        assert utils.read_buffer(bytearray(b"c0de"), 0, 1, const.ASCII) == "c"
        assert utils.read_buffer(bytearray(b"c0de"), 0, 2, const.ASCII) == "c0"
        assert utils.read_buffer(bytearray(b"c0de"), 1, 3, const.ASCII) == "0de"
        assert utils.read_buffer(bytearray(b"c0de"), 1, 5, const.ASCII) == "0de"  # test size out of bounds

    def test_read_buffer_hex(self):
        assert utils.read_buffer(bytearray(b"c0de"), 0, 1, const.HEX) == int(hexlify(b"c"), 16)
        assert utils.read_buffer(bytearray(b"c0de"), 0, 2, const.HEX) == int(hexlify(b"0c"), 16)
        assert utils.read_buffer(bytearray(b"c0de"), 1, 3, const.HEX) == int(hexlify(b"ed0"), 16)
        assert utils.read_buffer(bytearray(b"c0de"), 1, 5, const.HEX) == int(hexlify(b"ed0"), 16) # test size out of bounds

    def test_read_buffer_invalid_type(self):
        assert not utils.read_buffer(bytearray(b"c0de"), 0, 1, "other thing")


class TestGetDramMbAddr:
    def test_get_dram_mb_addr_zero(self, xmlcli_lib, mocker):
        xmlcli_lib._dram_shared_mb_address = 0
        mocker.patch.object(xmlcli_lib, "read_io", return_value=0)
        mocker.patch.object(xmlcli_lib, "write_io")
        mocker.patch.object(xmlcli_lib, "is_leg_mb_sig_valid", return_value=False)
        with pytest.raises(err.XmlCliNotSupported):
            _ = xmlcli_lib.dram_shared_mb_address

    def test_get_dram_mb_addr_reuse(self, xmlcli_lib, mocker):
        xmlcli_lib._dram_shared_mb_address = 0xc0de
        assert xmlcli_lib.dram_shared_mb_address == 0xc0de

    def test_get_dram_mb_addr_valid_first_try(self, xmlcli_lib, mocker):
        xmlcli_lib._dram_shared_mb_address = 0
        mocker.patch.object(xmlcli_lib, "write_io")
        mocker.patch.object(xmlcli_lib, "read_io", side_effect=[0xde, 0xc0])
        mocker.patch.object(xmlcli_lib, "is_leg_mb_sig_valid", return_value=True)
        assert xmlcli_lib.dram_shared_mb_address == 0xc0de0000

    def test_get_dram_mb_addr_valid_second_try(self, xmlcli_lib, mocker):
        xmlcli_lib._dram_shared_mb_address = 0
        mocker.patch.object(xmlcli_lib, "write_io")
        mocker.patch.object(xmlcli_lib, "read_io", side_effect=[0x0, 0x0, 0xde, 0xc0])
        mocker.patch.object(xmlcli_lib, "is_leg_mb_sig_valid", side_effect=[False, True])
        assert xmlcli_lib.dram_shared_mb_address == 0xc0de0000


class TestXmlValid:
    def test_is_xml_valid_invalid(self, xmlcli_lib, mocker):
        mocker.patch.object(xmlcli_lib, "read_mem_block", side_effect=[b"bad", b"c0de"])
        assert not xmlcli_lib.is_xml_valid(0, 1)

        mocker.patch.object(xmlcli_lib, "read_mem_block", side_effect=[b"<SYSTEM>", b"c0de"])
        assert not xmlcli_lib.is_xml_valid(0, 1)

        mocker.patch.object(xmlcli_lib, "read_mem_block", side_effect=[b"bad", b"</SYSTEM>"])
        assert not xmlcli_lib.is_xml_valid(0, 1)

        mocker.patch.object(xmlcli_lib, "read_mem_block", side_effect=Exception)
        assert not xmlcli_lib.is_xml_valid(0, 1)

    def test_is_xml_valid(self, xmlcli_lib, mocker):
        mocker.patch.object(xmlcli_lib, "read_mem_block", side_effect=[b"<SYSTEM>", b"</SYSTEM>"])
        assert xmlcli_lib.is_xml_valid(0, 1)


class TestAccess:
    def test_load_os_specific_access_invalid(self, mocker):
        mocker.patch.object(platform, "system", return_value="INVALID")

        with pytest.raises(RuntimeError) as e:
            xmlclilib._load_os_specific_access()
        assert "INVALID" in str(e.value)

    def test_load_os_specific_access_alid(self, mocker):
        from xmlcli_mod.access.linux import linux
        mocker.patch.object(platform, "system", return_value="Linux")
        mocker.patch.object(linux, "LinuxAccess")

        assert xmlclilib._load_os_specific_access()  # just check that we can "load" it


class TestFixLeg:

    @pytest.fixture
    def reset_variables(self, xmlcli_lib):
        const.LEGACYMB_XML_OFF = 0
        xmlcli_lib._cli_spec_version = None

    def test_fix_leg_xml_offset_legacy(self, xmlcli_lib, reset_variables):
        xmlcli_lib._cli_spec_version = CliSpecVersion(1, 0, 0)
        xmlcli_lib.fix_leg_xml_offset(0)
        assert const.LEGACYMB_XML_OFF == 0x50

    def test_fix_leg_xml_offset_major_less_seven(self, xmlcli_lib, reset_variables):
        xmlcli_lib._cli_spec_version = CliSpecVersion(0, 6, 0)
        xmlcli_lib.fix_leg_xml_offset(0)
        assert const.LEGACYMB_XML_OFF == 0xc

    def test_fix_leg_xml_offset_seven_one(self, xmlcli_lib, reset_variables):
        xmlcli_lib._cli_spec_version = CliSpecVersion(0, 7, 1)
        xmlcli_lib.fix_leg_xml_offset(0)
        assert const.LEGACYMB_XML_OFF == 0x50

        xmlcli_lib._cli_spec_version = CliSpecVersion(0, 8, 0)
        xmlcli_lib.fix_leg_xml_offset(0)
        assert const.LEGACYMB_XML_OFF == 0x50

    def test_fix_leg_xml_offset_seven_zero(self, xmlcli_lib, reset_variables, mocker):
        xmlcli_lib._cli_spec_version = CliSpecVersion(0, 7, 0)
        mocker.patch.object(xmlcli_lib, "mem_read", side_effect=[0, 0])
        xmlcli_lib.fix_leg_xml_offset(0)
        assert const.LEGACYMB_XML_OFF == 0x50

        mocker.patch.object(xmlcli_lib, "mem_read", side_effect=[0, 1])
        xmlcli_lib.fix_leg_xml_offset(0)
        assert const.LEGACYMB_XML_OFF == 0x4c


class TestReadXmlDetails:
    def test_read_xml_details_invalid(self, xmlcli_lib, mocker):
        mocker.patch.object(xmlclilib, "read_buffer", side_effect=[0xc0de, 0xbad])
        address, size = xmlcli_lib.read_xml_details(0)
        assert not address
        assert not size

        mocker.patch.object(xmlclilib, "read_buffer", side_effect=[const.SHAREDMB_SIG1, 0xbad])
        address, size = xmlcli_lib.read_xml_details(0)
        assert not address
        assert not size

        mocker.patch.object(xmlclilib, "read_buffer", side_effect=[0xc0de, const.SHAREDMB_SIG2])
        address, size = xmlcli_lib.read_xml_details(0)
        assert not address
        assert not size

        mocker.patch.object(xmlclilib, "read_buffer", side_effect=[const.SHAREDMB_SIG1, const.SHAREDMB_SIG2, 0x0])
        address, size = xmlcli_lib.read_xml_details(0)
        assert not address
        assert not size

    def test_read_xml_details(self, xmlcli_lib, mocker):
        mocker.patch.object(xmlclilib, "read_buffer", side_effect=[const.SHAREDMB_SIG1, const.SHAREDMB_SIG2, const.LEGACYMB_SIG, 0xFFFFFFFF])
        mocker.patch.object(xmlcli_lib, "mem_read", side_effect=[0xc0de-4, 0xbad])
        address, size = xmlcli_lib.read_xml_details(0)
        assert address == 0xc0de
        assert size == 0xbad

        mocker.patch.object(xmlclilib, "read_buffer", side_effect=[const.SHAREDMB_SIG1, const.SHAREDMB_SIG2, const.LEGACYMB_SIG, 0x0, 0xc0de-4])
        mocker.patch.object(xmlcli_lib, "mem_read", side_effect=[0xbad])
        address, size = xmlcli_lib.read_xml_details(0)
        assert address == 0xc0de
        assert size == 0xbad


class TestGetXml:
    def test_get_xml_no_data(self, xmlcli_lib, mocker):
        mocker.patch.object(xmlcli_lib, "read_mem_block", return_value=0xc0ffee)
        mocker.patch.object(xmlcli_lib, "read_xml_details", return_value=(0, 0))
        with pytest.raises(err.BiosKnobsDataUnavailable):
            xmlcli_lib.get_xml()

    def test_get_xml_no_invalid_data(self, xmlcli_lib, mocker):
        mocker.patch.object(xmlcli_lib, "read_mem_block", return_value=0xc0ffee)
        mocker.patch.object(xmlcli_lib, "read_xml_details", return_value=(0xba5e, 0xba11))
        mocker.patch.object(xmlcli_lib, "is_xml_valid", return_value=False)

        with pytest.raises(err.InvalidXmlData):
            xmlcli_lib.get_xml()

    def test_get_xml(self, xmlcli_lib, mocker):
        mocker.patch.object(xmlcli_lib, "read_mem_block", return_value=0xc0ffee)
        mocker.patch.object(xmlcli_lib, "read_xml_details", return_value=(0xba5e, 0xba11))
        mocker.patch.object(xmlcli_lib, "is_xml_valid", return_value=True)
        mocker.patch.object(xmlcli_lib, "read_mem_block", return_value=b"<SYSTEM></SYSTEM>")
        assert xmlcli_lib.get_xml() == "<SYSTEM></SYSTEM>"


def test_get_version(xmlcli_lib, mocker):
    xmlcli_lib._cli_spec_version = None
    mocker.patch.object(xmlcli_lib, "mem_read", side_effect=[1, 2, 3])
    assert "1.2.3" == str(xmlcli_lib.cli_spec_version)
    assert xmlcli_lib.cli_spec_version.release == 1
    assert xmlcli_lib.cli_spec_version.major == 2
    assert xmlcli_lib.cli_spec_version.minor == 3
