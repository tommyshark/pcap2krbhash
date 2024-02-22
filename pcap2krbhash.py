#!/usr/bin/env python3

import sys
import re
from scapy.all import *

def main(args):
    if len(args) == 0:
        print("You didn't specified the path to a .pcap file\nExample: python3 extractkrbhashfrompcap.py dump.pcap")
        return 1

    pcap_file = args[0]

    try:
        packets = rdpcap(pcap_file)
        for packet in packets:
            if packet.haslayer(KRB_AS_REQ):
                for p in packet:
                    padata_str = str(p[KRB_AS_REQ].padata)
                    pd = re.search(r"padataValue=(.*)", padata_str)
                    padata_value = pd.group(1)
                    etype = re.search(r"<ASN1_INTEGER\[(\d+|\w+)\]>", padata_value)
                    if etype:
                        et = etype.group(1)
                        cipher = re.search(r"\[b'(.*?)'\]", padata_value)
                        if cipher:
                            c = cipher.group(1)
                            unescaped_string = bytes(c, "utf-8").decode("unicode_escape")
                            raw_bytes = unescaped_string.encode('latin1')
                            hexres = raw_bytes.hex()
                            reqbody = str(p[KRB_AS_REQ].reqBody.show(dump=True))
                            usrnm = re.search(r"nameString= \[<ASN1_GENERAL_STRING\[b\'([^']+?)\'\]>\]", reqbody)
                            if usrnm:
                                u = usrnm.group(1)
                                domain = re.search(r"realm\s+=\s+<ASN1_GENERAL_STRING\[b\'([^\']+?)\'\]>", reqbody)
                                if domain:
                                    d = domain.group(1)
                                    krbhash = "$krb5pa$" + et + "$" + u + "$" + d + "$" + hexres
                                    print("Kerberos hash: ", krbhash)
                                
                    
                    
                    
    except FileNotFoundError:
        print("File not found:", pcap_file)
        return 1
    
    return 0

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
