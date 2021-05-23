import argparse
import json
import pefile
import sys
from termcolor import colored

def parse_pe(filename):
    try:
        pe = pefile.PE(filename)
    except OSError as e:
        print(e)
        sys.exit()
    except pefile.PEFormatError as e:
        print("[-] PEFormatError: %s" % e.value)
        sys.exit()
    
    attributes = {'IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE': pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE,
                  'IMAGE_DLLCHARACTERISTICS_GUARD_CF': pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_GUARD_CF,
                  'IMAGE_DLLCHARACTERISTICS_NX_COMPAT': pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_NX_COMPAT,
                  'IMAGE_DLLCHARACTERISTICS_NO_SEH': pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_NO_SEH}

    #import pdb; pdb.set_trace()

    print("===== %s Attributes =====" % filename)

    # ref: https://docs.microsoft.com/en-us/windows/win32/debug/pe-format?redirectedfrom=MSDN
    if pe.FILE_HEADER.IMAGE_FILE_32BIT_MACHINE:
        print("\t*** x86 Binary ***")
    elif pe.FILE_HEADER.Machine == 0x8664:		# x64 binary
        print("\t*** x64 Binary ***")

    for attr in attributes.keys():
        if attributes[attr] == True:
            print("\t%s: %s" % (attr, colored(attributes[attr], 'red')))
        else:
            print("\t%s: %s" % (attr, colored(attributes[attr], 'green')))
    print("\tImage Base: %x" % pe.OPTIONAL_HEADER.ImageBase)

    if args.optional_header:
        print(json.dumps(pe.OPTIONAL_HEADER.dump_dict(), indent=4))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--filename', action='store', help="Filename of PE file to parse", required=True)
    parser.add_argument('-o', '--optional-header', action='store_true', help="Print the optional header")
    args = parser.parse_args()
    parse_pe(args.filename)
