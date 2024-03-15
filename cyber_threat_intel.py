import re
import os
import sys
import shutil
import requests

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 5_1 like Mac OS X) \
    AppleWebKit/534.46 (KHTML, like Gecko) Version/5.1 Mobile/9B179 Safari/7534.48.3',
}

# IPs
if sys.platform == "win32":
    file_path = os.environ['HOMEPATH'] + "/Users/moqa/Desktop/OSTIF/dev/outputs/threat_sources"
    output_file = os.environ['HOMEPATH'] + "/Users/moqa/Desktop/OSTIF/dev/outputs/threats.csv"
    output_dir = os.environ['HOMEPATH'] + "/Users/moqa/Desktop/OSTIF/dev/outputs/"
else:
    file_path = os.environ['HOME'] + "/Users/moqa/Desktop/OSTIF/dev/outputs/threat_sources"
    output_file = os.environ['HOME'] + "/Users/moqa/Desktop/OSTIF/dev/outputs/threats.csv"
    output_dir = os.environ['HOME'] + "/Users/moqa/Desktop/OSTIF/dev/outputs/"


# AlienVault
ALIEN = "https://reputation.alienvault.com/reputation.generic"

# Abuse.ch
FEODO = "https://feodotracker.abuse.ch/blocklist/?download=ipblocklist"

# Emerging Threats
ETHREAT_BLOCKEDIP = "http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt"
ETHREAT_COMPROMISEDIP = "http://rules.emergingthreats.net/blockrules/compromised-ips.txt"

# Malc0de Black List
MALCODE = "https://github.com/stamparm/ipsum/tree/master/levels"

# OpenBL.org
OPENBL = "http://www.openbl.org/lists/base.txt"

'''NoThink.org -- DNS, HTTP and IRC'''
NTTELENT = "http://www.nothink.org/honeypots/honeypot_telnet_blacklist_2019.txt"
NTSSH = "http://www.nothink.org/honeypots/honeypot_ssh_blacklist_2019.txt"

# Project Honey Pot
HONEY_POT = "http://www.projecthoneypot.org/list_of_ips.php?rss=1"

# CI Army
CI_ARMY = "http://www.ciarmy.com/list/ci-badguys.txt"

# danger.rules.sk
DANGER_RULES = "http://danger.rulez.sk/projects/bruteforceblocker/blist.php"

# SANS
SANS_IP = "https://isc.sans.edu/ipsascii.html"

# charles.the-haleys.org -- SSH dictionary attack
SSH_DICT_ATTACK = "https://charles.the-haleys.org/ssh_dico_attack_hdeny_format.php/hostsdeny.txt"

# TOR  nodes
TOR_EXIT_NODES = "https://check.torproject.org/exit-addresses"


open_source_threat_intel = {
    "AlienVault_blacklist": ALIEN,
    "malc0de_blacklist": MALCODE,
    "feodo_black_list": FEODO,
    "emerging_threats_compromised_ips": ETHREAT_COMPROMISEDIP,
    "noThink_SSH_blacklist": NTSSH,
    "noThink_Telnet_blacklist": NTTELENT,
    "ci_army": CI_ARMY,
    "danger_rules": DANGER_RULES,
    "isc_SANS": SANS_IP,
    "ssh_bruteforce": SSH_DICT_ATTACK,
    "tor_exit_nodes": TOR_EXIT_NODES
}

# Regular expression for IPv4 Addresses
ip = re.compile(
    r'((?:(?:[12]\d?\d?|[1-9]\d|[1-9])\.){3}(?:[12]\d?\d?|[\d+]{1,2}))')


def regex(threat_list, pattern):
    # Filter pattern from threat_list
    threat_intel = re.findall(pattern, str(threat_list))
    return '\n'.join(threat_intel)


def urlgrab(host, pattern):
    # Grab threat intel from host
    try:
        response = requests.get(host, headers=HEADERS, timeout=5)
        response.raise_for_status()
        threat_list = response.content
        return regex(threat_list, pattern)
    except requests.exceptions.HTTPError as err:
        print(err)
        sys.exit(1)
    except requests.exceptions.RequestException as err:
        print(err)
        sys.exit(1)


def write_to_file(source_path, threat_list, filename):
    # Write updated threat intel to correct file and directory
    # check if file already exists, if it does, overwrite it. If the file
    # doesn't exist, create it.
    if os.path.isfile(source_path + filename):
        f_handle = open(source_path + filename, 'r+', encoding='ascii')
        f_handle.writelines(threat_list)
        f_handle.truncate()
        f_handle.close()
    else:
        f_handle = open(source_path + filename, 'w+', encoding='ascii')
        f_handle.writelines(threat_list)
        f_handle.close()


def create_csv(source_path, directory, out_file, header):
    # Create a two column csv file with threat and source for the columns
    # Make sure the directory is mounted
    if not os.path.isdir(directory):
        print("\t [-] Output directory does not exist or is not mounted\n")
        sys.exit()

    # copy old file for diff--then remove to create new file
    if os.path.isfile(out_file):
        shutil.copyfile(out_file, out_file + ".old")
        os.remove(out_file)

    # create header for first line
    file_handle = open(out_file, 'w+', encoding='ascii')
    file_handle.write(header)

    for header_file in os.listdir(source_path):
        with open(source_path + header_file, encoding='ascii') as infile:
            for line in infile:
                file_handle.write(line.rstrip() + "," + header_file + "\n")
    file_handle.close()


def main():
    # main Fucntion
    # check to see if needed directories exist. If not, create them
    if os.path.isdir(file_path):
        pass
    else:
        print("[+] Creating directory: " + file_path)
        os.makedirs(file_path)

    if os.path.isdir(output_dir):
        pass
    else:
        print("[+] Creating output directory: " + output_dir)
        os.makedirs(output_dir)

    # Loop through open source threat intelligence sources
    # Pull them down from the interwebs and format them
    # Write them to file.
    for filename, source in open_source_threat_intel.items():
        print("[+] Grabbing: " + source)
        threat_list = urlgrab(source, ip)
        write_to_file(file_path, threat_list, filename)

    # Create CSV
    print(f'[+] Creating CSV {output_file}...\n')
    create_csv(file_path, output_dir, output_file, "IP,Threat_Feed\n")


if __name__ == "__main__":
    main()
