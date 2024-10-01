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


def test_get_knob(xmlcli_obj):
    assert xmlcli_obj.get_knob("TestKnob").name == "TestKnob"
    assert xmlcli_obj.get_knob("StringKnob").name == "StringKnob"

    with pytest.raises(KeyError) as e:
        xmlcli_obj.get_knob("InvalidKnob")
    assert "InvalidKnob" in str(e.value)


def test_compare_knob(xmlcli_obj):
    assert not xmlcli_obj.compare_knob("TestKnob", 0)
    assert xmlcli_obj.compare_knob("TestKnob", 1)

    assert not xmlcli_obj.compare_knob("StringKnob", "a")
    assert xmlcli_obj.compare_knob("StringKnob", "b")


def test_save_xml_knobs(xmlcli_obj):
    test_file = Path("test.xml")
    assert not test_file.exists()
    xmlcli_obj.save_xml_knobs(test_file)
    assert test_file.exists()
    os.remove(test_file)
