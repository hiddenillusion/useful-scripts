#!/usr/bin/env python

# PCAPrewrite.py was created by Glenn P. Edwards Jr.
#	http://hiddenillusion.blogspot.com
#		@hiddenillusion
# Date: 03/26/2014
# version = 0.0.1
"""
Notes: This uses the first IPs as the values to rewrite the data with;
        therefore, if there are multiple conversations within the PCAP
        they are most likely going to become one.  Also, this is only
        looking at TCP/UDP packets so something like ICMP won't have 
        its data rewritten either.
"""
import sys
import argparse
from scapy.all import *

def main():
    """ Get program args"""
    parser = argparse.ArgumentParser(description='Rewrite/anonymize some data within a PCAP')   
    parser.add_argument('--debug', action='store_true', help='Print verbose output.', required=False)
    #parser.add_argument('-d', '--domain', metavar='Domain to change to', help='Change the domain name in the packet', required=False)
    parser.add_argument('-i', '--input', metavar='Input PCAP', help='PCAP to ingest.', required=True)
    parser.add_argument('-o', '--output', metavar='Output PCAP', help='Output PCAP file to write the new packets to.', required=True)
    parser.add_argument('--sip', metavar='Source IP address', help='IPv4 address to use as the source IP.')    
    parser.add_argument('--dip', metavar='Destination IP address', help='IPv4 address to use as the destination IP.')
    parser.add_argument('--smac', metavar='Source MAC address', help='MAC address to use for the source IP; "random" creates a random one.')
    parser.add_argument('--dmac', metavar='Destination MAC address', help='MAC address to use for the destination IP;  "random" creates a random one.')    

    args = vars(parser.parse_args())

    in_pcap = args['input']
    out_pcap = args['output']  
    if not args['debug'] == True:
        simple_debug = False
    else:
        print "[+] Debug enabled"
        simple_debug = True

    """Validate input file exists or die"""
    if not os.path.exists(in_pcap):
        print "[!] Input file doesn't seem to exist..."    	
        sys.exit()        
  
    """Read in the packets from the supplied PCAP file and set the SIP/DIP"""
    pkts = rdpcap(in_pcap)  
    src_ip = args['sip']
    src_mac = args['smac']    
    dst_ip = args['dip']    
    dst_mac = args['dmac']
    #domain = args['domain']    

    """Get the first instance of SIP/DIP addresses from the packets and use for 
    reference (assumption this layer exists)"""
    sip = pkts[0][IP].src
    dip = pkts[0][IP].dst  
    
    if simple_debug == True:
        print "[+] Original values  | Changed values"
        print "-------------------------------------"
        print "[-] SIP: {0} -> {1}".format(sip,src_ip)
        print "[-] DIP: {0} -> {1}".format(dip,dst_ip)

    """Rewrite the packets with the new data"""
    for pkt in pkts:  
        if pkt.haslayer(Ether):
            if simple_debug == True:
                smac = pkts[0][Ether].src
                dmac = pkts[0][Ether].dst
                print "[-] SMAC: {0} -> {1}".format(smac,src_mac)
                print "[-] DMAC: {0} -> {1}".format(dmac,dst_mac)
            if src_mac:
                if src_mac == 'random':
                    src_mac = RandMAC()
            else:
                src_mac = pkts[0][Ether].src

            if dst_mac:
                if dst_mac == 'random':
                    dst_mac = RandMAC()
            else:
                dst_mac = pkts[0][Ether].dst        	

            if pkt[Ether].src == src_mac:
                pkt[Ether].src = src_mac
		pkt[Ether].dst = dst_mac
            if pkt[Ether].dst == src_mac:
		pkt[Ether].src = dst_mac
		pkt[Ether].dst = src_mac    	
        if pkt.haslayer(IP):    	
            del pkt[IP].chksum
            #del pkt[TCP].chksum

            if not src_ip:
                src_ip = sip
            if not dst_ip:
                dst_ip = dip

            if pkt[IP].src == sip:
                pkt[IP].src = src_ip		    
		pkt[IP].dst = dst_ip
            if pkt[IP].dst == sip:
		pkt[IP].src = dst_ip
		pkt[IP].dst = src_ip     

        if pkt.haslayer(DNS):
            """Testing of DNS layer attribs"""
            if simple_debug == True:
                print "[+] DNS fields"
                for f in pkt[DNS].fields_desc:
                    print f
                print ""
                print "answers:",pkt[DNS].answers
                print ""
                print "qname:",pkt[DNSQR].qname #e.g. - sub.domain.org
                print "qtype:",pkt[DNSQR].qtype 
                print "summary:",pkt[DNS].summary() #e.g. - DNS Qry "sub.domain.org"
                print "id:",pkt[DNS].id 

                if pkt.haslayer(DNSRR):
                    print "rrname:",pkt[DNSRR].rrname
                    print "rdata:",pkt[DNSRR].rdata

            """
            pkt[DNS].summary(), pkt[DNSRR].rrname & pkt[DNSRR].rdata  may still 
            display original data (e.g. DNS Ans) so if you want to change that 
            so it doesn't show up in the 'info' column within Wireshark you need 
            to change it as well
            """
            if pkt.haslayer(DNSRR):
                if pkt[DNSRR].rdata == dip:
                    pkt[DNSRR].rdata = dst_ip

    """Write the packets out to the new file provided"""
    wrpcap(out_pcap, pkts)
		
if __name__ == "__main__":
	main()  
