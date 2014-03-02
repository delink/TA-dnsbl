#!/usr/bin/env python

import csv
import sys
import socket

""" This takes a CSV of IP addresses in and does DNSBL lookups on each
    DNSBL in the dnsbl_config_lookup CSV file. It tries as hard as
    possible to only call out to the OS DNS lookup facility when it has
    to, taking advantage of any possible local caching and deduplication.

    It is based somewhat on the external_lookup.py that is shipped with
    Splunk Enterprise.

"""

def makeip4r(ip):
    ip_array = ip.split(".")
    return ip_array[3]+"."+ip_array[2]+"."+ip_array[1]+"."+ip_array[0]

def lookup(ip4r):
    dnsbl_fqdn = "dnsbl.delink.net"
    try:
        hostname, aliaslist, iplist = socket.gethostbyname_ex(ip4r+"."+dnsbl_fqdn)
        return iplist[0]
    except:
        return ""

def main():
    # Verify that all field names have been passed in
    if len(sys.argv) != 4:
        print "Usage: external_dnsbl_lookup.py [ip field] [is_listed field] [dnsbl field]"
        sys.exit(1)

    # Setup file paths. Main input and output will be via stdin/stdout.
    # Configuration comes from the lookup table defined in transforms.
    # For now this is hardcoded to the original name. Don't change it!
    inf = sys.stdin
    outf = sys.stdout
    config = "./lookups/dnsbl.csv"

    r = csv.DictReader(inf)

    ipf = sys.argv[1]
    islf = sys.argv[2]
    dbf = sys.argv[3]

    w = csv.DictWriter(outf,fieldnames=r.fieldnames)
    w.writeheader()

    for addr in r:
        if addr[islf]:
            w.writerow(addr)

        else:
            result = lookup(makeip4r(addr[ipf]))
            if len(result) > 0:
                addr[islf] = "True"

            else:
                addr[islf] = "False"

            w.writerow(addr)

# Why do python programs always define main and then call it?
# The world may never know.
main()
