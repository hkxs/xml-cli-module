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

import importlib
import logging
import platform

import xmlcli_mod.common.constants as const
from xmlcli_mod.common.errors import BiosKnobsDataUnavailable
from xmlcli_mod.common.errors import InvalidXmlData
from xmlcli_mod.common.errors import XmlCliNotSupported
from xmlcli_mod.common.utils import read_buffer
from xmlcli_mod.dataclasses.spec_version import CliSpecVersion

logger = logging.getLogger(__name__)

PAGE_SIZE = 0x1000


def _load_os_specific_access():
    os_name = platform.system()  # Get the name of the OS
    try:
        module_name = f"xmlcli_mod.access.{os_name.lower()}.{os_name.lower()}"
        module = importlib.import_module(module_name)
    except ImportError:
        raise RuntimeError(f"Unsupported OS: {os_name}")

    access_class = getattr(module, f"{os_name}Access")
    return access_class()


class XmlCliLib:
    def __init__(self):
        self._dram_shared_mb_address = 0
        self._cli_spec_version = None
        self._access = _load_os_specific_access()

    @property
    def cli_spec_version(self):
        if not self._cli_spec_version:
            self._cli_spec_version = self._get_cli_spec_version(self.dram_shared_mb_address)
        logger.debug(f"CLI Spec Version = {self._cli_spec_version}")
        return self._cli_spec_version

    @property
    def dram_shared_mb_address(self):
        """
        Read DRAM shared Mailbox from CMOS location 0xBB [23:16] & 0xBC [31:24]

        :return:
        """
        if not self._dram_shared_mb_address:
            self._dram_shared_mb_address = self._read_dram_mb_addr()
        logger.debug(f"DRAM_MbAddr = 0x{self._dram_shared_mb_address:X}")
        return self._dram_shared_mb_address

    def read_mem_block(self, address, size):  # pragma: no cover
        """
        Reads the data block of given size from target memory
        starting from given address.

        > The read data is in bit format.
        > It is converted in string/ASCII to allow manipulated on byte granularity.

        :param address: address from which memory block needs to be read
        :param size: size of block to be read
        :return:
        """

        return self._access.mem_block(address, size)

    def mem_save(self, filename, address, size):  # pragma: no cover
        """
        Saves the memory block of given byte size to desired file

        :param filename: destination file where fetched data will be stored
        :param address: address from which data is to be copied
        :param size: total amount of data to be read
        :return:
        """

        return self._access.mem_save(filename, address, size)

    def mem_read(self, address, size):  # pragma: no cover
        """
        This function reads data from specific memory.
        It can be used to read Maximum `8 bytes` of data.

        > This function cannot be used to read Blocks of data.

        :param address: source address from which data to be read
        :param size: size of the data to be read
        :return:
        """
        return int(self._access.mem_read(address, size))

    def mem_write(self, address, size, value):  # pragma: no cover
        """
        This function writes data to specific memory.
        It can be used to write Maximum `8 bytes` of data.

        > This function cannot be used to write Blocks of data.

        :param address: source address at which data to be written
        :param size: size of the data to be read
        :param value: value to be written
        :return:
        """
        return self._access.mem_write(address, size, value)

    def read_io(self, address, size):  # pragma: no cover
        """
        Read data from IO ports

        :param address: address of port from which data to be read
        :param size: size of data to be read
        :return: integer value read from address
        """
        return int(self._access.read_io(address, size))

    def write_io(self, address, size, value):  # pragma: no cover
        """
        Write requested value of data to specified IO port

        :param address: address of IO port where data to be written
        :param size: amount of data to be written
        :param value: value of data to write on specified address port
        :return:
        """
        return self._access.write_io(address, size, value)

    def _get_cli_spec_version(self, dram_mb_addr):
        rel_version = self.mem_read((dram_mb_addr + const.CLI_SPEC_VERSION_RELEASE_OFF), 1) & 0xF
        major_version = self.mem_read((dram_mb_addr + const.CLI_SPEC_VERSION_MAJOR_OFF), 2)
        minor_version = self.mem_read((dram_mb_addr + const.CLI_SPEC_VERSION_MINOR_OFF), 1)
        return CliSpecVersion(release=rel_version, major=major_version, minor=minor_version)

    def fix_leg_xml_offset(self, dram_mb_addr):
        cli_spec_version = self._get_cli_spec_version(dram_mb_addr)  # use the new address to find the version
        if cli_spec_version.release:
            const.LEGACYMB_XML_OFF = 0x50
        elif (cli_spec_version.major == 7) and (cli_spec_version.minor == 0):
            leg_mb_offset = self.mem_read((dram_mb_addr + const.LEGACYMB_OFF), 4)
            if leg_mb_offset < 0xFFFF:
                leg_mb_offset = dram_mb_addr + leg_mb_offset

            if self.mem_read((leg_mb_offset + 0x4C), 4):
                const.LEGACYMB_XML_OFF = 0x4C
            else:
                const.LEGACYMB_XML_OFF = 0x50
        elif cli_spec_version.major >= 7:
            const.LEGACYMB_XML_OFF = 0x50
        else:
            const.LEGACYMB_XML_OFF = 0x0C

    def is_leg_mb_sig_valid(self, dram_mb_addr):
        is_valid = False
        shared_mb_sig1 = self.mem_read((dram_mb_addr + const.SHAREDMB_SIG1_OFF), 4)
        shared_mb_sig2 = self.mem_read((dram_mb_addr + const.SHAREDMB_SIG2_OFF), 4)
        if (shared_mb_sig1 == const.SHAREDMB_SIG1) and (shared_mb_sig2 == const.SHAREDMB_SIG2):
            share_mb_entry1_sig = self.mem_read((dram_mb_addr + const.LEGACYMB_SIG_OFF), 4)
            is_valid = True
            if share_mb_entry1_sig == const.LEGACYMB_SIG:
                self.fix_leg_xml_offset(dram_mb_addr)
        return is_valid

    def _read_dram_mb_addr(self):
        self.write_io(0x72, 1, 0xF0)  # Write a byte to cmos offset 0xF0
        result0 = int(self.read_io(0x73, 1) & 0xFF)  # Read a byte from cmos offset 0xBB [23:16]
        self.write_io(0x72, 1, 0xF1)  # Write a byte to cmos offset 0xF1
        result1 = int(self.read_io(0x73, 1) & 0xFF)  # Read a byte from cmos offset 0xBC [31:24]
        dram_shared_mb_address = int((result1 << 24) | (result0 << 16))  # Get bits [31:24] of the Dram MB address
        if self.is_leg_mb_sig_valid(dram_shared_mb_address):
            return dram_shared_mb_address

        self.write_io(0x70, 1, 0x78)  # Write a byte to cmos offset 0x78
        result0 = int(self.read_io(0x71, 1) & 0xFF)  # Read a byte from cmos offset 0xBB [23:16]
        self.write_io(0x70, 1, 0x79)  # Write a byte to cmos offset 0x79
        result1 = int(self.read_io(0x71, 1) & 0xFF)  # Read a byte from cmos offset 0xBC [31:24]
        dram_shared_mb_address = int((result1 << 24) | (result0 << 16))  # Get bits [31:24] of the Dram MB address
        if self.is_leg_mb_sig_valid(dram_shared_mb_address):
            return dram_shared_mb_address

        raise XmlCliNotSupported()

    def read_xml_details(self, dram_shared_mailbox_buffer):
        """
        Get XML Base Address & XML size details from the Shared Mailbox temp buffer

        We will retrieve shared mailbox signature 1 and signature 2 through offsets
        `SHAREDMB_SIG1_OFF` and `SHAREDMB_SIG2_OFF`. If retrieved data matches with
        signatures then we will check for Shared Mailbox entry signature.
        If it matches we will collect XML base address and XML size details
        from `LEGACYMB_OFF` and `LEGACYMB_XML_OFF`.

        :param dram_shared_mailbox_buffer: Shared Mailbox temporary buffer address
        :return:
        """
        shared_mb_sig1 = read_buffer(dram_shared_mailbox_buffer, const.SHAREDMB_SIG1_OFF, 4, const.HEX)
        shared_mb_sig2 = read_buffer(dram_shared_mailbox_buffer, const.SHAREDMB_SIG2_OFF, 4, const.HEX)
        gbt_xml_addr = 0
        gbt_xml_size = 0
        if (shared_mb_sig1 == const.SHAREDMB_SIG1) and (shared_mb_sig2 == const.SHAREDMB_SIG2):
            share_mb_entry1_sig = read_buffer(dram_shared_mailbox_buffer, const.LEGACYMB_SIG_OFF, 4, const.HEX)
            if share_mb_entry1_sig == const.LEGACYMB_SIG:
                logger.debug(f"Legacy MB signature found: {share_mb_entry1_sig}")
                leg_mb_offset = read_buffer(dram_shared_mailbox_buffer, const.LEGACYMB_OFF, 4, const.HEX)
                if leg_mb_offset > 0xFFFF:
                    gbt_xml_addr = self.mem_read(leg_mb_offset + const.LEGACYMB_XML_OFF, 4) + 4
                else:
                    dram_shared_mb_offset = leg_mb_offset + const.LEGACYMB_XML_OFF
                    gbt_xml_addr = read_buffer(dram_shared_mailbox_buffer, dram_shared_mb_offset, 4, const.HEX) + 4
                gbt_xml_size = self.mem_read(gbt_xml_addr - 4, 4)
        return gbt_xml_addr, gbt_xml_size

    def is_xml_valid(self, gbt_xml_address, gbt_xml_size):
        """
        Check if Target XML is Valid or not

        :param gbt_xml_address: Address of GBT XML
        :param gbt_xml_size: Size of GBT XML
        :return:
        """
        try:
            temp_buffer = self.read_mem_block(gbt_xml_address, 0x08)  # Read/save parameter buffer
            system_start = read_buffer(temp_buffer, 0, 0x08, const.ASCII)
            temp_buffer = self.read_mem_block(gbt_xml_address + gbt_xml_size - 0xB, 0x09)  # Read/save parameter buffer
            system_end = read_buffer(temp_buffer, 0, 0x09, const.ASCII)
            is_valid = True if (system_start == "<SYSTEM>") and (system_end == "</SYSTEM>") else False
        except Exception as e:
            logger.error(f"Exception detected when determining if xml is valid.\n {e}")
            is_valid = False

        return is_valid

    def get_xml(self):
        dram_shared_memory_buf = self.read_mem_block(self.dram_shared_mb_address, 0x200)  # Read/save parameter buffer
        xml_addr, xml_size = self.read_xml_details(dram_shared_memory_buf)  # read GBTG XML address and Size

        logger.debug(f"XML Addr={xml_addr:#x}, XML Size={xml_size:#x}")
        if not xml_addr:
            raise BiosKnobsDataUnavailable()

        if self.is_xml_valid(xml_addr, xml_size):
            logger.debug("Valid XML data")
            xml_bytearray = self.read_mem_block(xml_addr, int(xml_size))
            xml_data = xml_bytearray.decode()
        else:
            raise InvalidXmlData(f"Invalid XML or not generated yet, xml_addr=0x{xml_addr:X}, xml_size=0x{xml_size:X}")

        return xml_data
