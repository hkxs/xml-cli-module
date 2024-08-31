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


import logging
import os
from defusedxml.ElementTree import parse
from tempfile import TemporaryDirectory

from xmlcli_mod import XmlCliLib
from xmlcli_mod.common.errors import BiosKnobsDataUnavailable
from xmlcli_mod.common.errors import XmlCliNotSupported


log = logging.getLogger(__name__)

class XmlCli:
    def __init__(self)->None:
        self.xml_knobs = None
        XmlCliLib._setCliAccess("Linux")
        xmlcli_not_supported = XmlCliLib.ConfXmlCli()
        if xmlcli_not_supported:
            raise XmlCliNotSupported(xmlcli_not_supported)
        self._get_xml_knobs()

    def _get_xml_knobs(self)->None:
        with TemporaryDirectory() as tmpdir:
            temp_file = os.path.join(tmpdir, "temp.xml")
            rc = XmlCliLib.SaveXml(temp_file)
            if rc:
                raise BiosKnobsDataUnavailable()
            with open(temp_file) as f:
                self.xml_knobs = parse(temp_file)
