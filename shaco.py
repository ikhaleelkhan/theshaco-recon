# TheShaco Recon Tool - Simplified Version

from os import system, getcwd
import subprocess
import nmap
import sys

# Define helper functions
def break_and_help():
    '''
    Quit and show help message
    '''
    print("\n[?] Usage example: python3 shaco.py <target_url>")
    exit()

def remove_tmp_files(extension):
    '''
    Remove any file that starts with "tmp"
    '''
    system("rm -rf .tmp*.%s" % extension)

# Welcome screen
def print_welcome():
    system("clear")
    print("""
    __________________________________________________________________________
                              TheShaco Recon Tool
                            Coded by Khaleel Khan
    __________________________________________________________________________
    """)

# Start recon
def start_recon(URL_TARGET):
    print(f"\n[*] Starting recon on {URL_TARGET}:")

    # 1. Detect WAF
    detect_waf(URL_TARGET)
    
    # 2. Scan ports
    scan_ports(URL_TARGET)

    # 3. Subdomain enumeration
    get_subdomains(URL_TARGET)
    
    # 4. Bruteforce directories
    bruteforce_directories(URL_TARGET)

def detect_waf(URL_TARGET):
    get_host = subprocess.check_output(f"echo {URL_TARGET} | httprobe -prefer-https", shell=True, text=True).strip()
    detect_waf = subprocess.check_output(f"wafw00f {get_host}", shell=True, text=True)

    if "is behind" in detect_waf:
        which_waf = detect_waf.split('is behind')[-1].split()[0]
        print(f"\n[+] WAF: DETECTED [{which_waf}]")
    elif "No WAF detected" in detect_waf:
        print("\n[+] WAF: NOT DETECTED")
    else:
        print("\n[!] FAIL TO DETECT WAF")

def scan_ports(URL_TARGET):
    system(f"nmap {URL_TARGET} -o .tmp_NMAP.txt > /dev/null")
    system("cat .tmp_NMAP.txt | grep open > .tmp_PORTS.txt")
    
    try:
        with open(".tmp_PORTS.txt", encoding="utf-8") as file:
            ports_list = file.read().splitlines()
    except FileNotFoundError:
        print("\n[!] Port scan failed.")
        return
    
    remove_tmp_files("txt")
    print(f"\n[+] OPENED PORTS: {len(ports_list)}")
    for p in ports_list:
        print(f"\t ↳ {p}")

def get_subdomains(URL_TARGET):
    system(f"subfinder -d {URL_TARGET} -o .tmp_subfinder.txt -silent > /dev/null")
    system(f"sublist3r -d {URL_TARGET} -o .tmp_sublist3r.txt > /dev/null")
    system(f"assetfinder {URL_TARGET} > .tmp_assetfinder.txt")
    system(f"amass enum -d {URL_TARGET} -o .tmp_amass.txt -silent")

    system("cat .tmp*.txt > .tmp_subdomains.txt")
    
    try:
        with open(".tmp_subdomains.txt", encoding="utf-8") as file:
            subdomain_raw_list = file.read().splitlines()
    except FileNotFoundError:
        print("\n[!] Subdomain enumeration failed.")
        return

    subdomain_list = set(subdomain_raw_list)
    remove_tmp_files("txt")

    print(f"\n[+] SUBDOMAINS DETECTED: {len(subdomain_list)}")
    port_scan = nmap.PortScanner()

    for s in subdomain_list:
        quick_scan = port_scan.scan(hosts=s, arguments="-F")
        host = list(quick_scan["scan"].keys())

        if host:
            tcp_open = str(list(quick_scan["scan"][host[0]]["tcp"].keys()))
            print(f"\t ↳ {s} | {tcp_open}")
        else:
            print(f"\t ↳ {s} | FAIL")

def bruteforce_directories(URL_TARGET):
    system(f"dirsearch -u {URL_TARGET} -o .tmp_json_directory.json --format=json > /dev/null")
    
    try:
        with open(".tmp_json_directory.json", encoding="utf-8") as file:
            json_directory = json.load(file)
    except FileNotFoundError:
        print("\n[!] Directory brute-forcing failed.")
        return

    remove_tmp_files("json")
    
    directories = json_directory.get('results', [])
    if not directories:
        return
    
    host = list(directories[0].keys())[0]
    directory_list = directories[0][host]
    
    dir_list = [(d["status"], d["path"]) for d in directory_list if d["status"] in [200, 403]]
    sorted_directories = sorted(dir_list)
    
    print(f"\n[+] DIRECTORIES: {len(sorted_directories)}")
    for d in sorted_directories:
        formatted_host = host.replace("\n", "")
        print(f"\t ↳ {d[0]} | {formatted_host}{d[1]}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        URL_TARGET = sys.argv[1]
        print_welcome()
        start_recon(URL_TARGET)
    else:
        break_and_help()
