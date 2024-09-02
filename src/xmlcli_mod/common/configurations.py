import os
import sys
import tempfile


# Platform Details
PLATFORM = sys.platform
PY_VERSION = f"_py{sys.version_info.major}.{sys.version_info.minor}"
SYSTEM_VERSION = (sys.version_info.major, sys.version_info.minor)

# Current directory src/common
CURRENT_DIRECTORY = os.path.dirname(os.path.abspath(__file__))

# XmlCli source directory
XMLCLI_DIR = os.path.dirname(CURRENT_DIRECTORY)
# Tools directory
TOOL_DIR = os.path.join(XMLCLI_DIR, "tools")
# directory in OS temporary location
TEMP_DIR = os.path.join(tempfile.gettempdir(), "XmlCliOut")

# Configuration parser object

ENCODING = "utf-8"
ACCESS_METHOD = "Linux"
PERFORMANCE = False
# BIOS Knobs Configuration file
BIOS_KNOBS_CONFIG = os.path.join(XMLCLI_DIR, 'cfg', 'BiosKnobs.ini')

OUT_DIR = TEMP_DIR
os.makedirs(OUT_DIR, exist_ok=True)

# Tools and Utilities
TIANO_COMPRESS_BIN = ""
BROTLI_COMPRESS_BIN = ""

STATUS_CODE_RECORD_FILE = os.path.join(XMLCLI_DIR, "messages.json")

# Reading other configuration parameters
CLEANUP = True
ENABLE_EXPERIMENTAL_FEATURES = True
