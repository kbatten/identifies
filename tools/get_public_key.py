#!/usr/bin/env python
'''
converts a public key into the format browserid expects
'''

import sys
import re


def key_firefox(keyfile):
    '''
    keyfile is a cut and paste from firefox public key info
    '''
    modulus_hex = ""
    exponent = ""
    for line in keyfile.readlines():
        modulus_line = re.search('''^[0-9a-f]{2} [0-9a-f]{2}''', line.strip())
        if modulus_line:
            modulus_hex += line.strip()
        exponent_line = re.search('''^[0-9]+$''', line.strip())
        if exponent_line:
            exponent += line.strip()
    modulus_hex = "".join(modulus_hex.split())
    modulus = int(modulus_hex, 16)
    return modulus, exponent


def main():
    '''
    main
    '''
    if len(sys.argv) < 3:
        print '''
./get_public_key.py <option> <file>'

options:
 -f <file>    file is just cut and paste from firefox: Subject's Public Key
'''
        sys.exit(1)

    if sys.argv[1] == '-f':
        with open(sys.argv[2]) as keyfile:
            modulus, exponent = key_firefox(keyfile)
        print "\"n\": \"%s\"" % modulus
        print "\"e\": \"%s\"" % exponent


if __name__ == '__main__':
    main()
