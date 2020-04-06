"""
Compile the stuffz
"""

import os

class Binary(object):
    def __init__(self):
        super(Binary, self).__init__()

    def compile(self, path, outfile):
        os.system(f"x86_64-w64-mingw32-gcc {path} -o {outfile} -static")
        return
