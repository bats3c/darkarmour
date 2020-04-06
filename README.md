# Windows AV Evasion Tool

Store and execute an encrypted windows binary from inside memory, without a single bit touching disk.

## Usage

```

          _,.
        ,` -.)
       ( _/-\-._
      /,|`--._,-^|           ,¡
      \_| |`-._/||          / /
        |  `-, / |         /  /
        |     || |        /  /  ______           _     ___
         `r-._||/   __   /  /   |  _  \         | |   / _ \
     __,-<_     )`-/  `./  /    | | | |__ _ _ __| | _/ /_\ \_ __ _ __ ___   ___  _   _ _ __
    '  \   `---'     \ /  /     | | | / _` | '__| |/ /  _  | '__| '_ ` _ \ / _ \| | | | '__|
        |           |./  /      | |/ / (_| | |  |   <| | | | |  | | | | | | (_) | |_| | |
        /            /  /       |___/ \__,_|_|  |_|\_\_| |_/_|  |_| |_| |_|\___/ \__,_|_|
    \_/' \       |  /  /
     |    |   _,^-'/  /
     |    , `` (\ /  /_                    By Dylan Halls     |     Version 0.3
    \,.->._     \X-=/^
      (  /   `-._//^`
       `Y-.____(__}
        |     {__)
               ()



usage: darkarmour.py [-h] [-f FILE] -e ENCRYPT [-S SHELLCODE] [-b] [-d] [-u]
                     [-j] [-r] [-s] [-k KEY] [-l LOOP] [-o OUTFILE]

optional arguments:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  file to crypt, assumed as binary if not told otherwise
  -e ENCRYPT, --encrypt ENCRYPT
                        encryption algorithm to use (xor)
  -S SHELLCODE, --shellcode SHELLCODE
                        file contating the shellcode, needs to be in the
                        'msfvenom -f raw' style format
  -b, --binary          provide if file is a binary exe
  -d, --dll             use reflective dll injection to execute the binary
                        inside another process
  -u, --upx             pack the executable with upx
  -j, --jmp             use jmp based pe loader
  -r, --runpe           use runpe to load pe
  -s, --source          provide if the file is c source code
  -k KEY, --key KEY     key to encrypt with, randomly generated if not
                        supplied
  -l LOOP, --loop LOOP  number of levels of encryption
  -o OUTFILE, --outfile OUTFILE
                        name of outfile, if not provided then random filename
                        is assigned
```

## Usage

- Generate an undetectable version of a pe executable

      ./darkarmour.py -f bins/meter.exe --encrypt xor --jmp -o bins/legit.exe --loop 5

- Execute shellcode (x86/64) inside memory without detection, just provide the raw shellcode

      ./darkarmour.py -S -f bins/meter.bin --encrypt xor --jmp -o bins/legit.exe --loop 5

## Installation

It uses the python stdlib so no need to worry about any python dependencies, so the only issue you could come accoss are binary dependencies. The required binarys are: i686-w64-mingw32-g++, i686-w64-mingw32-gcc and upx (probly osslsigncode soon as well).
These can all be installed via apt.

```
sudo apt install mingw-w64-tools mingw-w64-common g++-mingw-w64 gcc-mingw-w64 upx-ucl osslsigncode
```

## TODO

  - Intergrate into PowerUp
  - Optional signing of binarys
  - Load pe image over a socket so not stored inside the binary
