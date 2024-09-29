TheShaco Recon Tool
Description
TheShaco is a Python-based reconnaissance tool built for bug bounty hunters and penetration testers. It automates various recon techniques including WAF detection, subdomain enumeration, port scanning, and directory brute-forcing. The tool integrates popular open-source recon utilities like nmap, wafw00f, subfinder, sublist3r, assetfinder, amass, and dirsearch, streamlining the recon process into one script.

Features
WAF Detection: Detect if the target is behind a Web Application Firewall (WAF).
Port Scanning: Scan for open ports using Nmap.
Subdomain Enumeration: Discover subdomains using multiple tools for better coverage.
Directory Bruteforcing: Identify hidden directories and files using Dirsearch.
Parallel Execution: Runs tasks concurrently for faster results.
Custom Logging: All actions and errors are logged to recon_log.log for easy debugging.
Installation
Clone the repository:

bash
Copy code
git clone https://github.com/ikhaleelkhan/theshaco-recon.git
cd theshaco-recon
Install the required Python packages:

bash
Copy code
pip install -r requirements.txt
Install the following system dependencies:

nmap
wafw00f
subfinder
sublist3r
assetfinder
amass
dirsearch
httprobe
On Debian-based systems, you can install them with:

bash
Copy code
sudo apt install nmap wafw00f dirsearch amass
Ensure other tools (subfinder, sublist3r, assetfinder, httprobe) are installed and available in your PATH.

Usage
Run the tool by specifying the target URL:

bash
Copy code
python3 shaco.py <target_url>
Example:
bash
Copy code
python3 shaco.py example.com
Log File:
The tool generates a log file named recon_log.log that contains detailed information about the recon process, including any errors encountered.
Tool Output
WAF Detection: Detects if the target is protected by a WAF.
Port Scanning: Lists open ports on the target.
Subdomain Enumeration: Outputs discovered subdomains.
Directory Bruteforcing: Lists accessible directories and files, including HTTP status codes.
