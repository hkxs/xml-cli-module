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

import pytest
from pathlib import Path

from xmlcli_mod import xmlcli
from xmlcli_mod import xmlclilib

import xmlcli_mod.common.errors as err
# import xmlcli_mod.common.utils as utils

class TestXmlCli:
    @pytest.fixture
    def xmlcli(self, mocker):
        test_xml = """
        <SYSTEM>
            <biosknobs>
                <knob type="scalar" name="TestKnob" description="Test Description" CurrentVal="1" default="0" size="1" offset="0x10" />                
                <knob type="string" name="StringKnob" description="Test Description" CurrentVal="b" default="a" size="1" offset="0x20" />                
            </biosknobs>
        </SYSTEM>
        """
        mocker.patch.object(xmlcli, "is_root", return_value=True)
        mocker.patch.object(xmlclilib, "set_cli_access")
        mocker.patch.object(xmlclilib, "verify_xmlcli_support")
        mocker.patch.object(xmlclilib, "get_xml", return_value=test_xml)

        return xmlcli.XmlCli()

    def test_xmlcli_not_root_init(self, mocker):
        mocker.patch.object(xmlcli, "is_root", return_value=False)

        with pytest.raises(err.RootError):
            xmlcli.XmlCli()

    def test_get_knob(self, xmlcli):
        assert xmlcli.get_knob("TestKnob").name == "TestKnob"
        assert xmlcli.get_knob("StringKnob").name == "StringKnob"

        with pytest.raises(KeyError) as e:
            xmlcli.get_knob("InvalidKnob")
        assert "InvalidKnob" in str(e.value)

    def test_compare_knob(self, xmlcli):
        assert not xmlcli.compare_knob("TestKnob", 0)
        assert xmlcli.compare_knob("TestKnob", 1)

        assert not xmlcli.compare_knob("StringKnob", "a")
        assert xmlcli.compare_knob("StringKnob", "b")

    def test_save_xml_knobs(self, xmlcli):
        test_file = Path("test.xml")
        assert not test_file.exists()
        xmlcli.save_xml_knobs(test_file)
        assert test_file.exists()
        os.remove(test_file)
