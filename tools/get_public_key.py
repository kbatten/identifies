#!/usr/bin/env python

import sys
import re


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print '''
./get_public_key.py <option> <file>'

options:
 -f <file>    file is just cut and paste from firefox: Subject's Public Key
'''
        sys.exit(1)

    if sys.argv[1] == '-f':
        # cut and paste from firefox public key info
        modulus_hex = ""
        exponent = ""
        with open(sys.argv[2]) as f:
            for line in f.readlines():
                r = re.search('''^[0-9a-f]{2} [0-9a-f]{2}''', line.strip())
                if r:
                    modulus_hex += line.strip()
                r = re.search('''^[0-9]+$''', line.strip())
                if r:
                    exponent += line.strip()
        modulus_hex = "".join(modulus_hex.split())
        modulus = int(modulus_hex, 16)
        print modulus, exponent
