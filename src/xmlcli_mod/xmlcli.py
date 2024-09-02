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

from xmlcli_mod import xmlclilib
from xmlcli_mod.common.utils import is_root
from xmlcli_mod.common.errors import RootError
from xmlcli_mod.dataclasses.knobs import Knob


log = logging.getLogger(__name__)

class XmlCli:
    def __init__(self) -> None:
        if not is_root():
            raise RootError()

        self.xml_data = None
        self._knobs = None
        xmlclilib.set_cli_access("Linux")
        xmlclilib.verify_xmlcli_support()
        self._get_xml_knobs()

    def _get_xml_knobs(self) -> None:
          self.xml_data = xmlclilib.get_xml()

    def save_xml_knobs(self, filename: str) -> None:
        self.xml_data.write(filename)

    @property
    def bios_knobs(self):
        if not self._knobs:
            self._knobs = self._extract_knobs()
        return self._knobs

    def _extract_knobs(self):
        knobs_dict = {}
        bios_knobs = self.xml_data.getroot().find("biosknobs")
        for knob in bios_knobs.findall("knob"):
            knob_name = knob.attrib["name"]
            knob_attributes = {
                "name": knob_name,
                "type": knob.attrib.get("type", ""),
                "description": knob.attrib.get("description", ""),
                "value": knob.attrib.get("description", ""),
                "default": knob.attrib.get("description", ""),
                "_size": knob.attrib["size"],
                "_offset": knob.attrib["offset"],
            }
            if knob_attributes["type"] == "scalar":
                knob_attributes["value"] = int(knob_attributes["value"])
                knob_attributes["default"] = int(knob_attributes["default"])

            knobs_dict[knob_name] = Knob(**knob_attributes)
        return knobs_dict
