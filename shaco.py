# Enhanced Recon Tool - TheShaco
from os import path, system, getcwd
import subprocess
import nmap
import json
import sys
import threading
import logging
from termcolor import colored

# Setup logger
logging.basicConfig(filename='recon_log.log', level=logging.DEBUG, 
                    format='%(asctime)s:%(levelname)s:%(message)s')

# Colors
class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    PURPLE = "\033[35m"
    CYAN = "\033[36m"

# Define error handling for system commands
def run_command(command):
    try:
        return subprocess.check_output(command, shell=True, text=True)
    except subprocess.CalledProcessError as e:
        logging.error(f"Command failed: {command}")
        return None

# Multi-threading function for faster execution
def threaded_function(target, args):
    thread = threading.Thread(target=target, args=args)
    thread.start()
    return thread

# Clean up temporary files
def remove_tmp_files(extension):
    system(f"rm -rf .tmp*.{extension}")

# Welcome screen
def print_welcome():
    system("clear")
    print(colored("""
    ________________________________________________________________________________
    Coded by Khaleel Khan
    ________________________________________________________________________________
    """, 'purple', attrs=['bold']))

# Start recon
def start_recon(URL_TARGET):
    print(colored(f"\n\t[*] Starting recon on {URL_TARGET}:", 'cyan', attrs=['bold']))

    # 1. Detect WAF
    detect_waf(URL_TARGET)
    
    # 2. Scan ports
    scan_ports(URL_TARGET)

    # 3. Subdomain enumeration
    subdomain_threads = []
    subdomain_threads.append(threaded_function(get_subdomains, (URL_TARGET,)))
    
    # 4. Bruteforce directories
    bruteforce_directories(URL_TARGET)
    
    # Wait for threads to finish
    for t in subdomain_threads:
        t.join()

def detect_waf(URL_TARGET):
    get_host = run_command(f"echo {URL_TARGET} | httprobe -prefer-https").strip()
    detect_waf = run_command(f"wafw00f {get_host}")
    
    if detect_waf and "is behind" in detect_waf:
        which_waf = detect_waf.split('is behind')[-1].split()[0]
        print(colored(f"\n\t[+] WAF: DETECTED [{which_waf}]", 'blue', attrs=['bold']))
    elif detect_waf and "No WAF detected" in detect_waf:
        print(colored("\n\t[+] WAF: NOT DETECTED", 'blue', attrs=['bold']))
    else:
        print(colored("\n\t[!] FAIL TO DETECT WAF", 'red', attrs=['bold']))

def scan_ports(URL_TARGET):
    system(f"nmap {URL_TARGET} -o .tmp_NMAP.txt > /dev/null")
    system("cat .tmp_NMAP.txt | grep open > .tmp_PORTS.txt")
    
    try:
        with open(".tmp_PORTS.txt", encoding="utf-8") as file:
            ports_list = file.read().splitlines()
    except FileNotFoundError:
        print(colored("\n\t[!] Port scan failed.", 'red'))
        return
    
    remove_tmp_files("txt")
    print(colored(f"\n\t[+] OPENED PORTS: {len(ports_list)}", 'blue', attrs=['bold']))
    for p in ports_list:
        print(f"\t    {colored('↳', 'cyan')} {colored(p, 'bold')}")

def get_subdomains(URL_TARGET):
    subfinder_cmd = f"subfinder -d {URL_TARGET} -o .tmp_subfinder.txt -silent > /dev/null"
    sublist3r_cmd = f"sublist3r -d {URL_TARGET} -o .tmp_sublist3r.txt > /dev/null"
    assetfinder_cmd = f"assetfinder {URL_TARGET} > .tmp_assetfinder.txt"
    amass_cmd = f"amass enum -d {URL_TARGET} -o .tmp_amass.txt -silent"
    
    system(subfinder_cmd)
    system(sublist3r_cmd)
    system(assetfinder_cmd)
    system(amass_cmd)
    
    system("cat .tmp*.txt > .tmp_subdomains.txt")
    
    try:
        with open(".tmp_subdomains.txt", encoding="utf-8") as file:
            subdomain_raw_list = file.read().splitlines()
    except FileNotFoundError:
        print(colored("\n\t[!] Subdomain enumeration failed.", 'red'))
        return

    subdomain_list = set(subdomain_raw_list)
    remove_tmp_files("txt")

    print(colored(f"\n\t[+] SUBDOMAINS DETECTED: {len(subdomain_list)}", 'blue', attrs=['bold']))
    port_scan = nmap.PortScanner()

    for s in subdomain_list:
        quick_scan = port_scan.scan(hosts=s, arguments="-F")
        host = list(quick_scan["scan"].keys())

        if host:
            tcp_open = str(list(quick_scan["scan"][host[0]]["tcp"].keys()))
            print(f"{colored('↳', 'cyan')} {colored(s, 'bold')} | {colored(tcp_open, 'cyan')}")
        else:
            print(f"{colored('↳', 'cyan')} {colored(s, 'bold')} | {colored('FAIL', 'red')}")

def bruteforce_directories(URL_TARGET):
    system(f"dirsearch -u {URL_TARGET} -o .tmp_json_directory.json --format=json > /dev/null")
    
    try:
        with open(".tmp_json_directory.json", encoding="utf-8") as file:
            json_directory = json.load(file)
    except FileNotFoundError:
        print(colored("\n\t[!] Directory brute-forcing failed.", 'red'))
        return

    remove_tmp_files("json")
    
    directories = json_directory.get('results', [])
    if not directories:
        return
    
    host = list(directories[0].keys())[0]
    directory_list = directories[0][host]
    
    dir_list = [(d["status"], d["path"]) for d in directory_list if d["status"] in [200, 403]]
    sorted_directories = sorted(dir_list)
    
    print(colored(f"\n\t[+] DIRECTORIES: {len(sorted_directories)}", 'blue', attrs=['bold']))
    for d in sorted_directories:
        formatted_host = host.replace("\n", "")
        status_color = 'green' if d[0] == 200 else 'yellow'
        print(f"{colored('↳', 'cyan')} {colored(d[0], status_color)} | {colored(formatted_host + d[1], 'bold')}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        URL_TARGET = sys.argv[1]
        start_recon(URL_TARGET)
    else:
        print(colored("\n\t[!] Usage: python3 shaco.py <target_url>", 'yellow'))
