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
import platform
import sys

from pathlib import Path
from setuptools import Extension
from setuptools.command.build_ext import build_ext


access_path = Path(".").resolve() / "src" / "xmlcli_mod" / "access" / "linux"
com_args = ["-fPIC"]

ext_modules = [
    Extension("xmlcli_mod.access.linux.mem", sources=[str(access_path / "mem.c")], extra_compile_args=com_args),
    Extension("xmlcli_mod.access.linux.port", sources=[str(access_path / "port.c")], extra_compile_args=com_args)
]


class ExtBuilder(build_ext):
    """ Extends base builder

    Originally used to rename the compiled artifacts, leave it in case we need
    to update binaries later on
    """
    def build_extension(self, ext):
        super().build_extension(ext)


def build(setup_kwargs):
    """
    This function is mandatory in order to build the extensions.
    """
    os_platform = platform.system()
    if os_platform != "Linux":
        logging.error(f"Unsupported platform '{os_platform}', XmlCli-Module only supported for Linux")
        sys.exit(1)

    setup_kwargs.update({"ext_modules": ext_modules})
    setup_kwargs.update({"cmdclass": {"build_ext": ExtBuilder}})
