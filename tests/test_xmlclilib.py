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
