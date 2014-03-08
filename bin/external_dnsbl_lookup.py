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

# This function reverses an IP address for use in an ip4r lookup.
def makeip4r(ip):
    ip_array = ip.split(".")
    return ip_array[3]+"."+ip_array[2]+"."+ip_array[1]+"."+ip_array[0]

# This function takes in a reversed IP and a FQDN and performs the DNS lookup
def lookup(ip4r,dnsbl_fqdn):
    try:
        hostname, aliaslist, iplist = socket.gethostbyname_ex(ip4r+"."+dnsbl_fqdn)
        return iplist[0]
    except:
        return ""

def main():
    # Verify that all field names have been passed in
    if len(sys.argv) != 4:
        print "Usage: external_dnsbl_lookup.py [ip field] [is_listed field] [dnsbl_name field]"
        sys.exit(1)

    # Setup file paths. Main input and output will be via stdin/stdout.
    # Configuration comes from the lookup table defined in transforms.
    inf = sys.stdin
    outf = sys.stdout
    config = "../lookups/dnsbl.csv"

    # Open the configuration lookup and tie it to a CSV Reader.
    try:
        configf = open(config,'rb')
        confr = csv.DictReader(configf)
    except:
        print "Unable to read the configuration lookup table from "+config
        sys.exit(3)

    # Tie stdin to the CSV reader to process the incoming CSV from Splunk
    addrr = csv.DictReader(inf)

    # Shortnames for all of the field names we are using. See the usage line
    # for details.
    ipf = sys.argv[1]
    islf = sys.argv[2]
    dbnf = sys.argv[3]
    dbff = "dnsbl_fqdn"

    # Tie stdout to a CSV Writer to dump results back to Splunk.
    w = csv.DictWriter(outf,fieldnames=addrr.fieldnames)
    w.writeheader()

    # Process each original line from Splunk, one line per IP address
    for addr in addrr:
        # This resets the seek pointer on the inner for loop below. Deals with
        # the oddity of how CSV.DictReader works.
        configf.seek(0)
        # Process each DNSBL listed in the dnsbl.csv lookup table.
        for dnsbl in confr:
            # Do not process the header name.
            if dnsbl[dbnf] == dbnf:
                continue
            # The actual work. Reverse the IP, tack on the FQDN, do some DNS.
            result = lookup(makeip4r(addr[ipf]),dnsbl[dbff])
            # If result isn't blank, we have a winner!
            if len(result) > 0:
                addr[islf] = "True"
                addr[dbnf] = dnsbl[dbnf]

            # Nothing to see here, set False and move along.
            else:
                addr[islf] = "False"
                addr[dbnf] = ""

            # Output the newly assembled CSV row to stdout.
            w.writerow(addr)

# Run the lookups
if (__name__ == "__main__"):
    main()
