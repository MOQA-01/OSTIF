#!/usr/bin/env python

import re
import sys

# IPv4 regex
ip = re.compile(r'((?:(?:[12]\d?\d?|[1-9]\d|[1-9])\.){3}(?:[12]\d?\d?|\d{1,2}))')

if len(sys.argv) != 3:
    print("Usage: python script.py input_file output_file")
    sys.exit(1)

input_file = sys.argv[1]
output_file = sys.argv[2]

def regex(input):
    # Grab only the IPs out of the file
    ip_list = re.findall(ip, input)
    return '\n'.join(ip_list)

try:
    with open(input_file, 'r') as file1:
        text = file1.read()
        ip_list = regex(text)
except FileNotFoundError:
    print(f"Error: Input file '{input_file}' not found.")
    sys.exit(1)

try:
    with open(output_file, 'w') as file2:
        file2.write(ip_list)
except Exception as e:
    print(f"Error writing to output file: {e}")
    sys.exit(1)

print("IPs extracted and written to the output file successfully.")
