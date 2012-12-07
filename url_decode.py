#!/usr/bin/env python
'''
This script takes a line or file and decodes the HTML encoded values - if after the HTML decoding
there is a match for character substitution then it coverts them to their character representation.

From:
"/some/sites/page%29%20AND%202=%28SELECT%20UPPER%28
%28CHR%2860%29%7C%7CCHR%2858%29%7C%7CCHR%2898%29%7C%7CCHR%28101%29%7C%7CCHR%28115%29%7C%7CCHR
%2858%29%7C%7C%28SELECT%20%28CASE%20WHEN%20%282=2%29%20THEN%201%20ELSE%200%20END%29%20FROM%20DUAL%29
%7C%7CCHR%2858%29%7C%7CCHR%28100%29%7C%7CCHR%28110%29%7C%7CCHR%28104%29%7C%7CCHR%2858%29%7C%7CCHR%28
62%29%29%29%20FROM%20DUAL%29%20AND%20%281=1"

To:
[-] HTML Decoded version:
/some/sites/page) AND 2=(SELECT UPPER((CHR(60)||CHR(58)||CHR(98)||CHR(101)||CHR(115)||CHR(58)
||(SELECT (CASE WHEN (2=2) THEN 1 ELSE 0 END) FROM DUAL)||CHR(58)||CHR(100)||CHR(110)||CHR(104)||CHR
(58)||CHR(62))) FROM DUAL) AND (1=1

To:
[-] HTML & CHR values Decoded version:
/some/sites/page) AND 2=(SELECT UPPER((<||:||b||e||s||:||(SELECT (CASE WHEN (2=2) THEN 1 ELSE
 0 END) FROM DUAL)||:||d||n||h||:||>)) FROM DUAL) AND (1=1
'''
# url_decode.py was created by Glenn P. Edwards Jr.
#	 	http://hiddenillusion.blogspot.com
# 				@hiddenillusion
# Version 0.1
# Date: 12-07-2012

import os
import sys
import re
import urllib as ul

def main():
    # Get program args
    if not len(sys.argv) > 1:
        print "This file decodes HTML urls to view them as they normally are before being encoded."
        sys.exit()
    else:
        input = sys.argv[1]
        chr_regex = re.compile('CHR\\((\\d+)\\)')

    def pretty(line):
        return ul.unquote_plus(line)

    def chr_replace(match):
        char_number = match.group(1)
        return (chr(int(char_number)))

    # Verify supplied path exists or die
    if os.path.isfile(input):
        if not os.path.exists(input):
            print "[!] I need a file to process."
            sys.exit()
        else:
            c = 1
            with open(input, 'r') as f:
                for line in f:
                    if not line.strip(): continue
                    else:
                        print "[+] Line (%d)" % c
                        print ('-' * 15)
                        print "[-] HTML Decoded version:"
                        print pretty(line)
                        if re.search(chr_regex, pretty(line)):
                            print "[-] HTML & CHR values Decoded version:"
                            print chr_regex.sub(chr_replace, pretty(line))
                        c += 1
    else:
        """
        This is meant to be used if a single line is just passed/pasted to this script so not
        keeping track of empty lines or line count.
        """
        print "[-] HTML Decoded version:"
        print pretty(input)
        if re.search(chr_regex, pretty(input)):
            print
            print "[-] HTML & CHR values Decoded version:"
            print chr_regex.sub(chr_replace, pretty(input))

if __name__ == "__main__":
    main()
