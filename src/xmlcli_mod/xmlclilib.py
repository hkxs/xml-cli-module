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
from xmlcli_mod.common.utils import read_buffer, un_hex_li_fy

logger = logging.getLogger(__name__)

CliSpecRelVersion = 0x00
CliSpecMajorVersion = 0x00
CliSpecMinorVersion = 0x00

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
        self._access = _load_os_specific_access()

    @property
    def dram_shared_mb_address(self):
        """
        Read DRAM shared Mailbox from CMOS location 0xBB [23:16] & 0xBC [31:24]

        :return:
        """
        if not self._dram_shared_mb_address:
            self._dram_shared_mb_address = self._read_dram_mb_addr()
        return self._dram_shared_mb_address

    def read_mem_block(self, address, size):  # pragma: no cover, this should go away with refactoring
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

    def mem_save(self, filename, address, size):  # pragma: no cover, this should go away with refactoring
        """
        Saves the memory block of given byte size to desired file

        :param filename: destination file where fetched data will be stored
        :param address: address from which data is to be copied
        :param size: total amount of data to be read
        :return:
        """

        return self._access.mem_save(filename, address, size)

    def mem_read(self, address, size):  # pragma: no cover, this should go away with refactoring
        """
        This function reads data from specific memory.
        It can be used to read Maximum `8 bytes` of data.

        > This function cannot be used to read Blocks of data.

        :param address: source address from which data to be read
        :param size: size of the data to be read
        :return:
        """
        return int(self._access.mem_read(address, size))

    def mem_write(self, address, size, value):  # pragma: no cover, this should go away with refactoring
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

    def read_io(self, address, size):  # pragma: no cover, this should go away with refactoring
        """
        Read data from IO ports

        :param address: address of port from which data to be read
        :param size: size of data to be read
        :return: integer value read from address
        """
        return int(self._access.read_io(address, size))

    def write_io(self, address, size, value):  # pragma: no cover, this should go away with refactoring
        """
        Write requested value of data to specified IO port

        :param address: address of IO port where data to be written
        :param size: amount of data to be written
        :param value: value of data to write on specified address port
        :return:
        """
        return self._access.write_io(address, size, value)

    def trigger_smi(self, smi_val):  # pragma: no cover, this should go away with refactoring
        """
        Triggers the software SMI of desired value. Triggering SMI involves writing
        desired value to port 0x72.
        Internally writing to port achieved by write io api

        :param smi_val: Value with which SMI should be triggered
        :return:
        """
        return self._access.trigger_smi(smi_val)

    def read_cmos(self, register_address):  # pragma: no cover, not used for now
        """
        Read CMOS register value

        :param register_address: CMOS register address
        :return:
        """
        upper_register_val = 0x0 if register_address < 0x80 else 0x2
        self.write_io(0x70 + upper_register_val, 1, register_address)
        value = self._access.read_io(0x71 + upper_register_val, 1)
        return value

    def write_cmos(self, register_address, value):  # pragma: no cover, not used for now
        """
        Write value to CMOS address register

        :param register_address: address of CMOS register
        :param value: value to be written on specified CMOS register
        :return:
        """
        if register_address < 0x80:
            self.write_io(0x70, 1, register_address)
            self.write_io(0x71, 1, value)

        if register_address >= 0x80:
            self.write_io(0x72, 1, register_address)
            self.write_io(0x73, 1, value)

    def clear_cmos(self):  # pragma: no cover, not used for now
        """
        Clear all CMOS locations to 0 and set CMOS BAD flag.

        Writing 0 to CMOS data port and writing register value to CMOS address port,
        CMOS clearing is achived

        CMOS are accessed through IO ports 0x70 and 0x71. Each CMOS values are
        accessed a byte at a time and each byte is individually accessible.

        :return:
        """
        logger.warning("Clearing CMOS")
        for i in range(0x0, 0x80, 1):
            self.write_io(0x70, 1, i)
            self.write_io(0x71, 1, 0)
            value = i | 0x80
            if value in (0xF0, 0xF1):
                # skip clearing the CMOS registers which hold Dram Shared MB address.
                continue
            self.write_io(0x72, 1, value)
            self.write_io(0x73, 1, 0)
        self.write_io(0x70, 1, 0x0E)
        self.write_io(0x71, 1, 0xC0)  # set CMOS BAD flag

        rtc_reg_pci_address = (1 << 31) + (0 << 16) + (31 << 11) + (0 << 8) + 0xA4
        self.write_io(0xCF8, 4, rtc_reg_pci_address)
        rtc_value = self.read_io(0xCFC, 2)
        rtc_value = rtc_value | 0x4
        self.write_io(0xCF8, 4, rtc_reg_pci_address)
        self.write_io(0xCFC, 2, rtc_value)  # set cmos bad in PCH RTC register

    def get_cli_spec_version(self, dram_mb_addr):
        global CliSpecRelVersion, CliSpecMajorVersion, CliSpecMinorVersion
        CliSpecRelVersion = self.mem_read((dram_mb_addr + const.CLI_SPEC_VERSION_RELEASE_OFF), 1) & 0xF
        CliSpecMajorVersion = self.mem_read((dram_mb_addr + const.CLI_SPEC_VERSION_MAJOR_OFF), 2)
        CliSpecMinorVersion = self.mem_read((dram_mb_addr + const.CLI_SPEC_VERSION_MINOR_OFF), 1)
        return f"{CliSpecRelVersion:d}.{CliSpecMajorVersion:d}.{CliSpecMinorVersion:d}"

    def fix_leg_xml_offset(self, dram_mb_addr):
        global CliSpecRelVersion, CliSpecMajorVersion, CliSpecMinorVersion  # just for reading

        if CliSpecRelVersion:
            const.LEGACYMB_XML_OFF = 0x50
        elif (CliSpecMajorVersion == 7) and (CliSpecMinorVersion == 0):
            leg_mb_offset = self.mem_read((dram_mb_addr + const.LEGACYMB_OFF), 4)
            if leg_mb_offset < 0xFFFF:
                leg_mb_offset = dram_mb_addr + leg_mb_offset

            if self.mem_read((leg_mb_offset + 0x4C), 4):
                const.LEGACYMB_XML_OFF = 0x4C
            else:
                const.LEGACYMB_XML_OFF = 0x50
        elif CliSpecMajorVersion >= 7:
            const.LEGACYMB_XML_OFF = 0x50
        else:
            const.LEGACYMB_XML_OFF = 0x0C

    def is_leg_mb_sig_valid(self, dram_mb_addr):
        shared_mb_sig1 = self.mem_read((dram_mb_addr + const.SHAREDMB_SIG1_OFF), 4)
        shared_mb_sig2 = self.mem_read((dram_mb_addr + const.SHAREDMB_SIG2_OFF), 4)
        if (shared_mb_sig1 == const.SHAREDMB_SIG1) and (shared_mb_sig2 == const.SHAREDMB_SIG2):
            cli_spec_version = self.get_cli_spec_version(dram_mb_addr)
            share_mb_entry1_sig = self.mem_read((dram_mb_addr + const.LEGACYMB_SIG_OFF), 4)
            if share_mb_entry1_sig == const.LEGACYMB_SIG:
                self.fix_leg_xml_offset(dram_mb_addr)
            return cli_spec_version
        return False

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
            logger.debug(f"CLI Spec Version = {self.get_cli_spec_version(dram_shared_mb_address)}")
            logger.debug(f"DRAM_MbAddr = 0x{dram_shared_mb_address:X}")
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

    # TODO this seems helpful in some way, it can/should be used to determine if
    # everything is setup properly on the platform
    def is_xml_generated(self):  # pragma: no cover, not used for now
        status = 0
        dram_mb_addr = self.dram_shared_mb_address  # Get DRam Mailbox Address from Cmos.
        logger.debug(f"CLI Spec Version = {self.get_cli_spec_version(dram_mb_addr)}")
        logger.debug(f"dram_mb_addr = 0x{dram_mb_addr:X}")
        if dram_mb_addr == 0x0:
            logger.error("Dram Shared Mailbox not Valid, hence exiting")
            return 1
        dram_shared_m_bbuf = self.read_mem_block(dram_mb_addr, 0x200)  # Read/save parameter buffer
        xml_addr, xml_size = self.read_xml_details(dram_shared_m_bbuf)  # read GBTG XML address and Size
        if xml_addr == 0:
            logger.error("Platform Configuration XML not yet generated, hence exiting")
            return 1
        if self.is_xml_valid(xml_addr, xml_size):
            logger.debug("Xml Is Generated and it is Valid")
        else:
            logger.error(f"XML is not valid or not yet generated ADDR = 0x{xml_addr:X}, SIZE = 0x{xml_size:X}")
            status = 1
        return status

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
            raise InvalidXmlData(f"Invalid XML or not generated yet, xml_addr = 0x{xml_addr:X}, xml_size = 0x{xml_size:X}")

        return xml_data
