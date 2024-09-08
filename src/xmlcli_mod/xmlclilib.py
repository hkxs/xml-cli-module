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

import os
import binascii
import importlib
import logging
import defusedxml.ElementTree as ET
from pathlib import Path
from xml.etree.ElementTree import ElementTree

from xmlcli_mod.common import utils
from xmlcli_mod.common import configurations
from xmlcli_mod.common.errors import BiosKnobsDataUnavailable
from xmlcli_mod.common.errors import InvalidAccessMethod
from xmlcli_mod.common.errors import InvalidXmlData
from xmlcli_mod.common.errors import XmlCliNotSupported


log = logging.getLogger(__name__)

cliaccess = None
FlexConCfgFile = False
ForceReInitCliAccess = False
UfsFlag = False
KnobsIniFile = configurations.BIOS_KNOBS_CONFIG
XmlCliToolsDir = configurations.TOOL_DIR
TianoCompressUtility = configurations.TIANO_COMPRESS_BIN
BrotliCompressUtility = configurations.BROTLI_COMPRESS_BIN

TempFolder = configurations.OUT_DIR

KnobsXmlFile = os.path.join(TempFolder, 'BiosKnobs.xml')
PlatformConfigXml = os.path.join(TempFolder, 'PlatformConfig.xml')
PlatformConfigLiteXml = os.path.join(TempFolder, 'PlatformConfigLite.xml')
SvXml = os.path.join(TempFolder, 'SvPlatformConfig.xml')

TmpKnobsIniFile = os.path.join(TempFolder, 'TmpBiosKnobs.ini')
JSON_OUT_FILE = os.path.join(TempFolder, 'json_output.json')
OutBinFile = ''
gDramSharedMbAddr = 0
MerlinxXmlCliEnableAddr = 0
InterfaceType = configurations.ACCESS_METHOD
XmlCliLogFile = os.path.join(TempFolder, 'XmlCli.log')
XmlCliRespFlags = {'Status': 0, 'CantExe': 0, 'WrongParam': 0, 'TimedOut': 0, 'SideEffect': 'NoSideEffect'}
LastErrorSig = 0x0000
LastErrorSigDict = {int(key, 16): value["msg"] for key, value in utils.STATUS_CODE_RECORD.items()}

CliRespFlags = 0

SHAREDMB_SIG1 = 0xBA5EBA11
SHAREDMB_SIG2 = 0xBA5EBA11
SHARED_MB_LEGMB_SIG_OFF = 0x20
SHARED_MB_LEGMB_ADDR_OFF = 0x24
LEGACYMB_SIG = 0x5A7ECAFE
XML_START = '<SYSTEM>'
XML_END = '</SYSTEM>'
SHAREDMB_SIG1_OFF = 0x00
SHAREDMB_SIG2_OFF = 0x08
CLI_SPEC_VERSION_MINOR_OFF = 0x14
CLI_SPEC_VERSION_MAJOR_OFF = 0x15
CLI_SPEC_VERSION_RELEASE_OFF = 0x17
LEGACYMB_SIG_OFF = 0x20
LEGACYMB_OFF = 0x24
LEGACYMB_XML_OFF = 0x0C
MERLINX_XML_CLI_ENABLED_OFF = 0x28
LEGACYMB_XML_CLI_TEMP_ADDR_OFF = 0x60
STRING = 0x51
ASCII = 0xA5
HEX = 0x16
SETUP_KNOBS_ADDR_OFF = 0x13C
SETUP_KNOBS_SIZE_OFF = 0x140
CPUSV_MAILBOX_ADDR_OFF = 0x14C
XML_CLI_DISABLED_SIG = 0xCD15A1ED
SHARED_MB_CLI_REQ_BUFF_SIG = 0xCA11AB1E
SHARED_MB_CLI_RES_BUFF_SIG = 0xCA11B0B0
SHARED_MB_CLI_REQ_BUFF_SIG_OFF = 0x30
SHARED_MB_CLI_RES_BUFF_SIG_OFF = 0x40
SHARED_MB_CLI_REQ_BUFF_ADDR_OFF = 0x34
SHARED_MB_CLI_RES_BUFF_ADDR_OFF = 0x44
SHARED_MB_CLI_REQ_BUFF_SIZE_OFF = 0x38
SHARED_MB_CLI_RES_BUFF_SIZE_OFF = 0x48
CLI_REQ_READY_SIG = 0xC001C001
CLI_RES_READY_SIG = 0xCAFECAFE
CLI_REQ_RES_READY_SIG_OFF = 0x00
CLI_REQ_RES_READY_CMD_OFF = 0x04
CLI_REQ_RES_READY_FLAGS_OFF = 0x06
CLI_REQ_RES_READY_STATUS_OFF = 0x08
CLI_REQ_RES_READY_PARAMSZ_OFF = 0x0C
CLI_REQ_RES_BUFF_HEADER_SIZE = 0x10
WRITE_MSR_OPCODE = 0x11
READ_MSR_OPCODE = 0x21
IO_READ_OPCODE = 0x31
IO_WRITE_OPCODE = 0x32
APPEND_BIOS_KNOBS_CMD_ID = 0x48
RESTOREMODIFY_KNOBS_CMD_ID = 0x49
READ_BIOS_KNOBS_CMD_ID = 0x4A
LOAD_DEFAULT_KNOBS_CMD_ID = 0x4B
PROG_BIOS_CMD_ID = 0xB4
FETCH_BIOS_CMD_ID = 0xB5
BIOS_VERSION_OPCODE = 0xB1
EXE_SV_SPECIFIC_CODE_OPCODE = 0x300
READ_BRT_OPCODE = 0x310
CREATE_FRESH_BRT_OPCODE = 0x311
ADD_BRT_OPCODE = 0x312
DEL_BRT_OPCODE = 0x313
DIS_BRT_OPCODE = 0x314
GET_SET_VARIABLE_OPCODE = 0x9E5E
CLI_KNOB_APPEND = 0x0
CLI_KNOB_RESTORE_MODIFY = 0x1
CLI_KNOB_READ_ONLY = 0x2
CLI_KNOB_LOAD_DEFAULTS = 0x3

CliSpecRelVersion = 0x00
CliSpecMajorVersion = 0x00
CliSpecMinorVersion = 0x00

MAXIMUM_BIOS_MEMORY_MAP = 0xFFFFFFFF
PAGE_SIZE = 0x1000
FIRMWARE_BASE_MASK_ALIGNMENT = (MAXIMUM_BIOS_MEMORY_MAP - PAGE_SIZE + 0x1)

CliCmdDict = {APPEND_BIOS_KNOBS_CMD_ID: 'APPEND_BIOS_KNOBS_CMD_ID',
              RESTOREMODIFY_KNOBS_CMD_ID: 'RESTOREMODIFY_KNOBS_CMD_ID',
              READ_BIOS_KNOBS_CMD_ID: 'READ_BIOS_KNOBS_CMD_ID', LOAD_DEFAULT_KNOBS_CMD_ID: 'LOAD_DEFAULT_KNOBS_CMD_ID',
              PROG_BIOS_CMD_ID: 'PROG_BIOS_CMD_ID', FETCH_BIOS_CMD_ID: 'FETCH_BIOS_CMD_ID',
              BIOS_VERSION_OPCODE: 'BIOS_VERSION_OPCODE', EXE_SV_SPECIFIC_CODE_OPCODE: 'EXE_SV_SPECIFIC_CODE_OPCODE',
              READ_MSR_OPCODE: 'READ_MSR_OPCODE', WRITE_MSR_OPCODE: 'WRITE_MSR_OPCODE',
              IO_READ_OPCODE: 'IO_READ_OPCODE', IO_WRITE_OPCODE: 'IO_WRITE_OPCODE',
              READ_BRT_OPCODE: 'READ_BRT_OPCODE', CREATE_FRESH_BRT_OPCODE: 'CREATE_FRESH_BRT_OPCODE',
              ADD_BRT_OPCODE: 'ADD_BRT_OPCODE',
              DEL_BRT_OPCODE: 'DEL_BRT_OPCODE', DIS_BRT_OPCODE: 'DIS_BRT_OPCODE'}

Xml_Sanitization_Mapping = {0x00: 0x20, 0x01: 0x20, 0x02: 0x20, 0x03: 0x20, 0x04: 0x20, 0x05: 0x20, 0x06: 0x20,
                            0x07: 0x20, 0x08: 0x20, 0x0B: 0x20, 0x0C: 0x20, 0x0E: 0x20, 0x0F: 0x20, 0x10: 0x20,
                            0x11: 0x20, 0x12: 0x20, 0x13: 0x20, 0x14: 0x20, 0x15: 0x20, 0x16: 0x20, 0x17: 0x20,
                            0x18: 0x20, 0x19: 0x20, 0x1A: 0x20, 0x1B: 0x20, 0x1C: 0x20, 0x1D: 0x20, 0x1E: 0x20,
                            0x1F: 0x20, 0x7F: 0x20, 0xB5: 0x75, 0x26: 0x6E, 0xA0: 0x2E, 0xB0: 0x20}

# Constants for Bitwise Knobs
BITWISE_KNOB_PREFIX = 0xC0000



class CliLib:
    def __init__(self, access_request):
        access_methods = self.get_available_access_methods()
        if access_request in access_methods:
            config_file_path = Path(configurations.XMLCLI_DIR, access_methods[access_request])

            self.access_config = configurations.config_read(config_file_path)
            access_file = self.access_config.get(access_request.upper(), "file")  # Source file of access method
            access_module_path = f"xmlcli_mod.access.{access_request}.{os.path.splitext(access_file)[0]}"
            access_file = importlib.import_module(access_module_path)  # Import access method
            method_class = self.access_config.get(access_request.upper(), "method_class")
            self.access_instance = getattr(access_file, method_class)(access_request)  # create instance of Access method class
        else:
            raise InvalidAccessMethod(access_request)

    @staticmethod
    def get_available_access_methods():
        """Gather all the available access method name and it's configuration file from defined in tool configuration file

        :return: dictionary structure {access_method_name: config_file}
        """
        return configurations.ACCESS_METHODS

    def set_cli_access(self, access_request=None):
        access_methods = self.get_available_access_methods()
        if access_request in access_methods:
            access_config = os.path.join(configurations.XMLCLI_DIR, access_methods[access_request])
            if os.path.exists(access_config):
                self.access_config = configurations.config_read(access_config)


def set_cli_access(req_access=None):
    global cliaccess
    if not req_access:
        req_access = InterfaceType
    if not cliaccess:
        cli_instance = CliLib(req_access.lower())
        cliaccess = cli_instance.access_instance


def _checkCliAccess():
    set_cli_access()


def InitInterface():
    global cliaccess
    _checkCliAccess()
    return cliaccess.initialize_interface()


def CloseInterface():
    global cliaccess
    _checkCliAccess()
    return cliaccess.close_interface()


def read_mem_block(address, size):
    """
    Reads the data block of given size from target memory
    starting from given address.

    > The read data is in bit format.
    > It is converted in string/ASCII to allow manipulated on byte granularity.

    :param address: address from which memory block needs to be read
    :param size: size of block to be read
    :return:
    """
    global cliaccess
    _checkCliAccess()
    return cliaccess.mem_block(address, size)


def memsave(filename, address, size):
    """
    Saves the memory block of given byte size to desired file

    :param filename: destination file where fetched data will be stored
    :param address: address from which data is to be copied
    :param size: total amount of data to be read
    :return:
    """
    global cliaccess
    _checkCliAccess()
    return cliaccess.mem_save(filename, address, size)



def memread(address, size):
    """
    This function reads data from specific memory.
    It can be used to read Maximum `8 bytes` of data.

    > This function cannot be used to read Blocks of data.

    :param address: source address from which data to be read
    :param size: size of the data to be read
    :return:
    """
    global cliaccess
    _checkCliAccess()
    return int(cliaccess.mem_read(address, size))


def memwrite(address, size, value):
    """
    This function writes data to specific memory.
    It can be used to write Maximum `8 bytes` of data.

    > This function cannot be used to write Blocks of data.

    :param address: source address at which data to be written
    :param size: size of the data to be read
    :return:
    """
    global cliaccess
    _checkCliAccess()
    return cliaccess.mem_write(address, size, value)



def readIO(address, size):
    """
    Read data from IO ports

    :param address: address of port from which data to be read
    :param size: size of data to be read
    :return: integer value read from address
    """
    global cliaccess
    _checkCliAccess()
    return int(cliaccess.read_io(address, size))


def writeIO(address, size, value):
    """
    Write requested value of data to specified IO port

    :param address: address of IO port where data to be written
    :param size: amount of data to be written
    :param value: value of data to write on specified address port
    :return:
    """
    global cliaccess
    _checkCliAccess()
    return cliaccess.write_io(address, size, value)


def triggerSMI(SmiVal):
    """
    Triggers the software SMI of desired value. Triggering SMI involves writing
    desired value to port 0x72.
    Internally writing to port achieved by write io api

    :param SmiVal: Value with which SMI should be triggered
    :return:
    """
    global cliaccess
    _checkCliAccess()
    return cliaccess.trigger_smi(SmiVal)



def readcmos(register_address):
    """
    Read CMOS register value

    :param register_address: CMOS register address
    :return:
    """
    upper_register_val = 0x0 if register_address < 0x80 else 0x2
    writeIO(0x70 + upper_register_val, 1, register_address)
    value = readIO(0x71 + upper_register_val, 1)
    return value


def writecmos(register_address, value):
    """
    Write value to CMOS address register

    :param register_address: address of CMOS register
    :param value: value to be written on specified CMOS register
    :return:
    """
    if register_address < 0x80:
        writeIO(0x70, 1, register_address)
        writeIO(0x71, 1, value)

    if register_address >= 0x80:
        writeIO(0x72, 1, register_address)
        writeIO(0x73, 1, value)


def clearcmos():
    """
    Clear all CMOS locations to 0 and set CMOS BAD flag.

    Writing 0 to CMOS data port and writing register value to CMOS address port,
    CMOS clearing is achived

    CMOS are accessed through IO ports 0x70 and 0x71. Each CMOS values are
    accessed a byte at a time and each byte is individually accessible.

    :return:
    """
    log.warning('Clearing CMOS')
    for i in range(0x0, 0x80, 1):
        writeIO(0x70, 1, i)
        writeIO(0x71, 1, 0)
        value = i | 0x80
        if value in (0xF0, 0xF1):
            # skip clearing the CMOS register's which hold Dram Shared MB address.
            continue
        writeIO(0x72, 1, value)
        writeIO(0x73, 1, 0)
    writeIO(0x70, 1, 0x0E)
    writeIO(0x71, 1, 0xC0)  # set CMOS BAD flag

    rtc_reg_pci_address = ((1 << 31) + (0 << 16) + (31 << 11) + (0 << 8) + 0xA4)
    writeIO(0xCF8, 4, rtc_reg_pci_address)
    rtc_value = readIO(0xCFC, 2)
    rtc_value = rtc_value | 0x4
    writeIO(0xCF8, 4, rtc_reg_pci_address)
    writeIO(0xCFC, 2, rtc_value)  # set cmos bad in PCH RTC register


def ReadBuffer(inBuffer, offset, size, inType):
    """
    This function reads the desired format of data of specified size
    from the given offset of buffer.

    > Input buffer is in big endian ASCII format

    :param inBuffer: buffer from which data to be read
    :param offset: start offset from which data to be read
    :param size: size to be read from buffer
    :param inType: format in which data can be read (ascii or hex)

    :return: buffer read from input
    """
    value_buffer = inBuffer[offset:offset + size]
    value_string = ''
    if len(value_buffer) == 0:
        return 0
    if inType == ASCII:
        value_string = "".join(chr(value_buffer[i]) for i in range(len(value_buffer)))
        return value_string
    if inType == HEX:
        # value_string = "".join(f"{value_buffer[i]:02x}" for i in range(len(value_buffer)))
        for count in range(len(value_buffer)):
            value_string = f"{value_buffer[count]:02x}" + value_string
        return int(value_string, 16)
    return 0


def UnHexLiFy(Integer):
    return binascii.unhexlify((hex(Integer)[2:]).strip('L')).decode()


def GetCliSpecVersion(DramMbAddr):
    global CliSpecRelVersion, CliSpecMajorVersion, CliSpecMinorVersion, CLI_REQ_READY_SIG, CLI_RES_READY_SIG
    CliSpecRelVersion = memread((DramMbAddr + CLI_SPEC_VERSION_RELEASE_OFF), 1) & 0xF
    CliSpecMajorVersion = memread((DramMbAddr + CLI_SPEC_VERSION_MAJOR_OFF), 2)
    CliSpecMinorVersion = memread((DramMbAddr + CLI_SPEC_VERSION_MINOR_OFF), 1)
    CLI_REQ_READY_SIG = 0xC001C001
    CLI_RES_READY_SIG = 0xCAFECAFE
    if (CliSpecRelVersion == 0):
        if (CliSpecMajorVersion >= 7):
            CLI_REQ_READY_SIG = 0xD055C001
            CLI_RES_READY_SIG = 0xD055CAFE
    else:
        LEGACYMB_XML_OFF = 0x50
        CLI_REQ_READY_SIG = 0xD055C001
        CLI_RES_READY_SIG = 0xD055CAFE
    return f'{CliSpecRelVersion:d}.{CliSpecMajorVersion:d}.{CliSpecMinorVersion:d}'


def FixLegXmlOffset(DramMbAddr):
    global CliSpecRelVersion, CliSpecMajorVersion, CliSpecMinorVersion, LEGACYMB_XML_OFF
    LEGACYMB_XML_OFF = 0x0C
    if (CliSpecRelVersion == 0):
        if (CliSpecMajorVersion >= 7):
            LEGACYMB_XML_OFF = 0x50
            if ((CliSpecMajorVersion == 7) and (CliSpecMinorVersion == 0)):
                LegMbOffset = memread((DramMbAddr + LEGACYMB_OFF), 4)
                if (LegMbOffset < 0xFFFF):
                    LegMbOffset = DramMbAddr + LegMbOffset
                if (memread((LegMbOffset + 0x4C), 4) == 0):
                    LEGACYMB_XML_OFF = 0x50
                else:
                    LEGACYMB_XML_OFF = 0x4C
    else:
        LEGACYMB_XML_OFF = 0x50


def IsLegMbSigValid(DramMbAddr):
    global CliSpecRelVersion, CliSpecMajorVersion, MerlinxXmlCliEnableAddr
    SharedMbSig1 = memread((DramMbAddr + SHAREDMB_SIG1_OFF), 4)
    SharedMbSig2 = memread((DramMbAddr + SHAREDMB_SIG2_OFF), 4)
    if ((SharedMbSig1 == SHAREDMB_SIG1) and (SharedMbSig2 == SHAREDMB_SIG2)):
        cli_spec_version = GetCliSpecVersion(DramMbAddr)
        ShareMbEntry1Sig = memread((DramMbAddr + LEGACYMB_SIG_OFF), 4)
        if (ShareMbEntry1Sig == LEGACYMB_SIG):
            FixLegXmlOffset(DramMbAddr)
            if ((CliSpecRelVersion >= 0) and (CliSpecMajorVersion >= 8)):
                LegMbOffset = int(memread(DramMbAddr + LEGACYMB_OFF, 4))
                if (LegMbOffset > 0xFFFF):
                    MerlinxXmlCliEnableAddr = LegMbOffset + MERLINX_XML_CLI_ENABLED_OFF
                else:
                    MerlinxXmlCliEnableAddr = DramMbAddr + LegMbOffset + MERLINX_XML_CLI_ENABLED_OFF
            return cli_spec_version
    return False


def GetDramMbAddr(display_spec=True):
    """
    Read DRAM shared Mailbox from CMOS location 0xBB [23:16] & 0xBC [31:24]

    :return:
    """
    global gDramSharedMbAddr, InterfaceType, LastErrorSig
    LastErrorSig = 0x0000
    InitInterface()
    writeIO(0x72, 1, 0xF0)  # Write a byte to cmos offset 0xF0
    result0 = int(readIO(0x73, 1) & 0xFF)  # Read a byte from cmos offset 0xBB [23:16]
    writeIO(0x72, 1, 0xF1)  # Write a byte to cmos offset 0xF1
    result1 = int(readIO(0x73, 1) & 0xFF)  # Read a byte from cmos offset 0xBC [31:24]
    dram_shared_mb_address = int((result1 << 24) | (result0 << 16))  # Get bits [31:24] of the Dram MB address
    if IsLegMbSigValid(dram_shared_mb_address):
        CloseInterface()
        return dram_shared_mb_address

    writeIO(0x70, 1, 0x78)  # Write a byte to cmos offset 0x78
    result0 = int(readIO(0x71, 1) & 0xFF)  # Read a byte from cmos offset 0xBB [23:16]
    writeIO(0x70, 1, 0x79)  # Write a byte to cmos offset 0x79
    result1 = int(readIO(0x71, 1) & 0xFF)  # Read a byte from cmos offset 0xBC [31:24]
    dram_shared_mb_address = int((result1 << 24) | (result0 << 16))  # Get bits [31:24] of the Dram MB address
    if IsLegMbSigValid(dram_shared_mb_address):
        CloseInterface()
        log.debug(f'CLI Spec Version = {GetCliSpecVersion(dram_shared_mb_address)}')
        log.debug(f'DRAM_MbAddr = 0x{dram_shared_mb_address:X}')
        return dram_shared_mb_address

    if gDramSharedMbAddr != 0:
        dram_shared_mb_address = int(gDramSharedMbAddr)
        if IsLegMbSigValid(dram_shared_mb_address):
            CloseInterface()
            log.debug(f'CLI Spec Version = {GetCliSpecVersion(dram_shared_mb_address)}')
            log.debug(f'DRAM_MbAddr = 0x{dram_shared_mb_address:X}')
            return dram_shared_mb_address
    CloseInterface()
    LastErrorSig = 0xD9FD  # Dram Shared MailBox Not Found

    return 0


def verify_xmlcli_support():
    InitInterface()
    if not GetDramMbAddr() :
        raise XmlCliNotSupported()
    log.debug('XmlCli is Enabled..')
    CloseInterface()


def readxmldetails(dram_shared_mailbox_buffer):
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
    SharedMbSig1 = ReadBuffer(dram_shared_mailbox_buffer, SHAREDMB_SIG1_OFF, 4, HEX)
    SharedMbSig2 = ReadBuffer(dram_shared_mailbox_buffer, SHAREDMB_SIG2_OFF, 4, HEX)
    GBT_XML_Addr = 0
    GBT_XML_Size = 0
    if (SharedMbSig1 == SHAREDMB_SIG1) and (SharedMbSig2 == SHAREDMB_SIG2):
        ShareMbEntry1Sig = ReadBuffer(dram_shared_mailbox_buffer, LEGACYMB_SIG_OFF, 4, HEX)
        if ShareMbEntry1Sig == LEGACYMB_SIG:
            LegMbOffset = ReadBuffer(dram_shared_mailbox_buffer, LEGACYMB_OFF, 4, HEX)
            if LegMbOffset > 0xFFFF:
                GBT_XML_Addr = memread(LegMbOffset + LEGACYMB_XML_OFF, 4) + 4
            else:
                GBT_XML_Addr = ReadBuffer(dram_shared_mailbox_buffer, LegMbOffset + LEGACYMB_XML_OFF, 4, HEX) + 4
            GBT_XML_Size = memread(GBT_XML_Addr - 4, 4)
    return GBT_XML_Addr, GBT_XML_Size


def isxmlvalid(gbt_xml_address, gbt_xml_size):
    """
    Check if Target XML is Valid or not

    :param gbt_xml_address: Address of GBT XML
    :param gbt_xml_size: Size of GBT XML
    :return:
    """
    global LastErrorSig
    LastErrorSig = 0x0000
    try:
        temp_buffer = read_mem_block(gbt_xml_address, 0x08)  # Read/save parameter buffer
        SystemStart = ReadBuffer(temp_buffer, 0, 0x08, ASCII)
        temp_buffer = read_mem_block(gbt_xml_address + gbt_xml_size - 0xB, 0x09)  # Read/save parameter buffer
        SystemEnd = ReadBuffer(temp_buffer, 0, 0x09, ASCII)
        if (SystemStart == XML_START) and (SystemEnd == XML_END):
            return True
        else:
            LastErrorSig = 0x8311  # Xml data is in-valid
            return False
    except Exception as e:
        log.error(f'Exception detected when determining if xml is valid.\n {e}')
        LastErrorSig = 0xEC09  # Exception detected
        return False


# TODO this seems helpful in some way, it can/should be used to determine if
# everything is setup properly on the platform
def IsXmlGenerated():
    global LastErrorSig
    LastErrorSig = 0x0000
    Status = 0
    InitInterface()
    DRAM_MbAddr = GetDramMbAddr()  # Get DRam Mailbox Address from Cmos.
    log.debug(f'CLI Spec Version = {GetCliSpecVersion(DRAM_MbAddr)}')
    log.debug(f'DRAM_MbAddr = 0x{DRAM_MbAddr:X}')
    if (DRAM_MbAddr == 0x0):
        log.error('Dram Shared Mailbox not Valid, hence exiting')
        CloseInterface()
        return 1
    DramSharedMBbuf = read_mem_block(DRAM_MbAddr, 0x200)  # Read/save parameter buffer
    (XmlAddr, XmlSize) = readxmldetails(DramSharedMBbuf)  # read GBTG XML address and Size
    if (XmlAddr == 0):
        log.error('Platform Configuration XML not yet generated, hence exiting')
        CloseInterface()
        LastErrorSig = 0x8AD0  # Xml Address is Zero
        return 1
    if (isxmlvalid(XmlAddr, XmlSize)):
        log.debug('Xml Is Generated and it is Valid')
    else:
        log.error(f'XML is not valid or not yet generated XmlAddr = 0x{XmlAddr:X}, XmlSize = 0x{XmlSize:X}')
        Status = 1
    CloseInterface()
    return Status


EFI_IFR_ONE_OF_OP = 0x05
EFI_IFR_CHECKBOX_OP = 0x06
EFI_IFR_NUMERIC_OP = 0x07
EFI_IFR_STRING_OP = 0x1C
BIOS_KNOBS_DATA_BIN_HDR_SIZE_OLD = 0x10
INVALID_KNOB_SIZE = 0xFF
BIOS_KNOBS_DATA_BIN_HDR_SIZE = 0x40
BIOS_KNOBS_DATA_BIN_HDR_SIZE_V03 = 0x50
BIOS_KNOB_BIN_REVISION_OFFSET = 0x0F
NVAR_NAME_OFFSET = 0x0E
NVAR_SIZE_OFFSET = 0x10
BIOS_KNOB_BIN_GUID_OFFSET = 0x12

ZeroGuid = [0x00000000, 0x0000, 0x0000, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
SetupTypeHiiDict = {EFI_IFR_ONE_OF_OP: 'oneof', EFI_IFR_NUMERIC_OP: 'numeric', EFI_IFR_CHECKBOX_OP: 'checkbox',
                    EFI_IFR_STRING_OP: 'string', 0xF: 'ReadOnly'}
SetupTypeBinDict = {0x5: 'oneof', 0x7: 'numeric', 0x6: 'checkbox', 0x8: 'string', 0xF: 'ReadOnly'}
SetupTypeBin2ValDict = {0x5: EFI_IFR_ONE_OF_OP, 0x7: EFI_IFR_NUMERIC_OP, 0x6: EFI_IFR_CHECKBOX_OP,
                        0x8: EFI_IFR_STRING_OP}
OldBinNvarNameDict = {0: 'Setup', 1: 'ServerMgmt'}
OldBinNvarNameDictPly = {0: 'Setup', 1: 'SocketIioConfig', 2: 'SocketCommonRcConfig', 3: 'SocketMpLinkConfig',
                         4: 'SocketMemoryConfig', 5: 'SocketMiscConfig', 6: 'SocketPowerManagementConfig',
                         7: 'SocketProcessorCoreConfig', 8: 'SvOtherConfiguration', 9: 'SvPchConfiguration'}


def get_xml():
    InitInterface()

    # TODO add verification of DRAM address using verify_xmlcli_support
    dram_mb_addr = GetDramMbAddr()  # Get DRam MAilbox Address from Cmos.

    dram_shared_memory_buf = read_mem_block(dram_mb_addr, 0x200)  # Read/save parameter buffer
    xml_addr, xml_size = readxmldetails(dram_shared_memory_buf)  # read GBTG XML address and Size

    if not xml_addr:
        CloseInterface()
        raise BiosKnobsDataUnavailable()

    if isxmlvalid(xml_addr, xml_size):
        xml_bytearray = read_mem_block(xml_addr, int(xml_size))
        defused_xml = ET.fromstring(xml_bytearray.decode())

        # we're converting an element to a tree, we can safely use built-in xml
        # module because, at this point, it's already being parsed by defusedxml
        xml_data = ElementTree(defused_xml)
    else:
        CloseInterface()
        raise InvalidXmlData(f'XML is not valid or not yet generated xml_addr = 0x{xml_addr:X}, xml_size = 0x{xml_size:X}')

    CloseInterface()
    return xml_data


# TODO I see potential on this, but the implementation was really bad
def getBiosDetails():
    """
    Extract BIOS Version details from XML.

    Bios details will give detailed description of BIOS populated on platform.
    This description involves Platform Name, Bios Name, BIOS Time Stamp.

    Design Description:
    Get DRAM Mailbox address from CMOS then Read and save parameters buffer.
    After validating xml; first 512 bytes will be copied in temporary buffer
    assuming BIOS attributes will be found within first 512 bytes.

    Then respective attributes will be copied in already allocated temporary buffers.

    :return: Tuple of (Platform name, Bios Name, Bios Timestamp)
    """


def getEfiCompatibleTableBase():
    """Search for the EFI Compatible tables in 0xE000/F000 segments

    Use-case would be to find DramMailbox in legacy way
    :return:
    """
    global LastErrorSig
    LastErrorSig = 0x0000
    EfiComTblSig = 0x24454649
    for Index in range(0, 0x1000, 0x10):
        Sig1 = memread(0xE0000 + Index, 4)
        Sig2 = memread(0xF0000 + Index, 4)
        if (Sig1 == EfiComTblSig):
            BaseAddress = 0xE0000 + Index;
            log.debug(f'Found EfiCompatibleTable Signature at 0x{BaseAddress:X}')
            return BaseAddress
        if (Sig2 == EfiComTblSig):
            BaseAddress = 0xF0000 + Index;
            log.debug(f'Found EfiCompatibleTable Signature at 0x{BaseAddress:X}')
            return BaseAddress
    log.debug(hex(Index))
    LastErrorSig = 0xEFC9  # EfiCompatibleTable Not Found
    return 0


def SearchForSystemTableAddress():
    for Address in range(0x20000000, 0xE0000000, 0x400000):  # EFI_SYSTEM_TABLE_POINTER address is 4MB aligned
        Signature = memread(Address, 8)
        if (Signature == 0x5453595320494249):  # EFI System Table Signature = 'IBI SYST'
            Address = memread((Address + 8), 8)
            return Address
    return 0


# TODO this also seems kind of helpful
def readDramMbAddrFromEFI():
    DramSharedMailBoxGuidLow = 0x4D2C18789D99A394
    DramSharedMailBoxGuidHigh = 0x3379C48E6BC1E998
    log.debug('Searching for Dram Shared Mailbox address from gST EfiConfigTable..')
    gST = SearchForSystemTableAddress()
    if (gST == 0):
        EfiCompatibleTableBase = getEfiCompatibleTableBase()
        if (EfiCompatibleTableBase == 0):
            return 0
        gST = memread(EfiCompatibleTableBase + 0x14, 4)
    Signature = memread(gST, 8)
    if (Signature != 0x5453595320494249):  # EFI System Table Signature = 'IBI SYST'
        return 0
    log.debug(
        f'EFI SYSTEM TABLE Address = 0x{gST:X}  Signature = \"{UnHexLiFy(Signature)[::-1]}\"    Revision = {memread(gST + 8, 2):d}.{memread(gST + 0xA, 2):d}')
    count = 0
    FirmwarePtr = memread(gST + 0x18, 8)
    FirmwareRevision = memread(gST + 0x20, 4)
    BiosStr = ''
    while (1):
        Value = int(memread(FirmwarePtr + count, 2))
        if (Value == 0):
            break
        BiosStr = BiosStr + chr((Value & 0xFF))
        count = count + 2
    log.debug(f'Firmware : {BiosStr}')
    log.debug(f'Firmware Revision: 0x{FirmwareRevision:X}')
    EfiConfigTblEntries = memread(gST + 0x68, 8)
    EfiConfigTbl = memread(gST + 0x70, 8)
    log.debug(f'EfiConfigTblEntries = {EfiConfigTblEntries:d}  EfiConfigTbl Addr = 0x{EfiConfigTbl:X}')
    Offset = 0
    DramMailboxAddr = 0
    for Index in range(0, EfiConfigTblEntries):
        GuidLow = memread(EfiConfigTbl + Offset, 8)
        GuidHigh = memread(EfiConfigTbl + 8 + Offset, 8)
        if ((GuidLow == DramSharedMailBoxGuidLow) and (GuidHigh == DramSharedMailBoxGuidHigh)):
            DramMailboxAddr = int(memread(EfiConfigTbl + 16 + Offset, 8))
            log.info(f'Found Dram Shared MailBox Address = 0x{DramMailboxAddr:X} from EfiConfigTable')
            break
        Offset = Offset + 0x18
    return DramMailboxAddr


# TODO I want to revisit this method to learn about this legacy memory map
def PrintE820Table():
    """Legacy function for printing E820 table for memory type identification using
    legacy efi compatible table

    EFI ST offset = 0x14
    ACPI table offset = 0x1C
    E820 Table offset = 0x22
    E820 table Length = 0x26

    :return:
    """
    Offset = 0
    Index = 0
    E820TableList = {}
    EfiCompatibleTableBase = getEfiCompatibleTableBase()
    E820Ptr = memread(EfiCompatibleTableBase + 0x22, 4)
    Size = memread(EfiCompatibleTableBase + 0x26, 4)
    log.debug(',,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,')
    log.debug('E820[no]: Start Block Address ---- End Block Address , Type = Mem Type')
    log.debug('``````````````````````````````````````````````````````````````````````')
    while (1):
        BaseAddr = memread(E820Ptr + Offset, 8)
        Length = memread(E820Ptr + Offset + 8, 8)
        Type = memread(E820Ptr + Offset + 16, 4)
        log.debug(f'E820[{Index:2d}]:  0x{BaseAddr:16X} ---- 0x{(BaseAddr + Length):<16X}, Type = 0X{Type:x} ')
        E820TableList[Index] = [BaseAddr, Length, Type]
        Index = Index + 1
        Offset = Offset + 20
        if (Offset >= Size):
            break
    log.debug(',,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,')
    return E820TableList
