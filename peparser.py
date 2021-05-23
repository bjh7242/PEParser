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
    
    import pdb; pdb.set_trace()

    attributes = {'IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE': pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE,
                  'IMAGE_DLLCHARACTERISTICS_GUARD_CF': pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_GUARD_CF,
                  'IMAGE_DLLCHARACTERISTICS_NX_COMPAT': pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_NX_COMPAT,
                  'IMAGE_DLLCHARACTERISTICS_NO_SEH': pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_NO_SEH}

    print("===== Attributes =====")
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
    parser.add_argument('-f', action='store', help="Filename of PE file to parse", required=True)
    parser.add_argument('-o', '--optional-header', action='store_true', help="Print the optional header")
    args = parser.parse_args()
    parse_pe(args.f)
