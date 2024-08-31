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
from pyexpat.errors import messages

class RootError(OSError):
    def __init__(self):
        self.message = "XmlCli Module requires Root"
        super().__init__(self.message)

class XmlCliNotSupported(SystemError):
    def __init__(self, xmlcli_status):
        if xmlcli_status == 1:
            self.message = "XmlCli not supported on the Current BIOS"
        elif xmlcli_status == 2:
            self.message = "XmlCli not enabled"
        else:
            self.message = "Unknown XmlCli error"
        super().__init__(self.message)

class BiosKnobsDataUnavailable(SystemError):
    def __init__(self):
        self.message = "unable to get Xml Cli data from the system"
        super().__init__(self.message)
