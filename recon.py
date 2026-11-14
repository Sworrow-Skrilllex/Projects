import os
import sys
import ipaddress
import subprocess
import time
import re

def display_banner():
    """Displays the tool's banner."""
    print("=" * 60)
    print("      Automated Reconnaissance Tool (For Educational Use Only)      ")
    print("=" * 60)
    print("\nIMPORTANT: This tool is designed for use in isolated lab")
    print("environments against authorized targets ONLY.\n")

def setup_results_folder():
    """Prompts the user for a folder to save results and creates it."""
    while True:
        folder_path = input("[+] Enter the full path for the results folder: ")
        if not folder_path.strip():
            print("[!] Error: Folder path cannot be empty. Please try again.")
            continue
        try:
            if not os.path.exists(folder_path):
                os.makedirs(folder_path)
                print(f"[+] Successfully created results folder: {folder_path}")
            else:
                print(f"[+] Results folder already exists: {folder_path}")
            return folder_path
        except OSError as e:
            print(f"[!] Error creating directory: {e}. Please check permissions and path.")
            sys.exit(1)

def get_target_ip():
    """Prompts the user for a target IP."""
    while True:
        target_ip = input("[+] Enter the target IP address: ")
        if target_ip.strip():
            return target_ip
        else:
            print("[!] Target IP address cannot be empty. Please try again.")

def get_wordlist_path():
    """Prompts the user for a wordlist path and validates it."""
    default_path = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
    prompt = (
        f"\n[+] Enter the full path to your wordlist for GoBuster.\n"
        f"    Example: {default_path}\n"
        f"[+] Press Enter to use the default path shown above: "
    )
    while True:
        user_path = input(prompt)
        # If user presses Enter, use the default path
        if not user_path.strip():
            selected_path = default_path
            print(f"[*] No path entered. Using default wordlist: {selected_path}")
        else:
            selected_path = user_path

        # Validate if the file exists
        if os.path.exists(selected_path):
            print(f"[+] Wordlist found: {selected_path}")
            return selected_path
        else:
            print(f"\n[!] ERROR: The file '{selected_path}' does not exist.")
            print("[!] Please check the path and try again.\n")


def run_nmap_scan(target_ip, results_folder):
    """
    Runs an Nmap scan with service detection and vulnerability scripts.
    """
    print("\n" + "="*60)
    print("               Starting Nmap Scan                ")
    print("="*60)
    print(f"[*] Target: {target_ip}")
    print("[*] Scan Type: Service Detection (-sV) and Vulnerability Scripts (--script vuln)")
    print("[*] This may take several minutes...")

    output_file = os.path.join(results_folder, "nmap_scan.txt")
    command = ["nmap", "-sV", "--script", "vuln", "-oN", output_file, target_ip]

    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        print(f"\n[+] Nmap scan completed successfully.")
        print(f"[+] Results saved to: {output_file}")
        
        print("\n--- Nmap Scan Summary ---")
        for line in result.stdout.splitlines():
            if "/tcp" in line and "open" in line:
                print(line)
        print("-------------------------\n")

    except FileNotFoundError:
        print("\n[!] ERROR: 'nmap' command not found.")
        print("[!] Please ensure Nmap is installed and in your system's PATH.")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"\n[!] ERROR: Nmap scan failed with return code {e.returncode}.")
        print(f"[!] Error Output:\n{e.stderr}")
        sys.exit(1)


def find_web_ports(results_folder):
    """
    Parses the nmap_scan.txt file to find open ports related to web services.
    Returns a list of strings, where each string is a port number.
    """
    print("[*] Parsing Nmap results to identify web services...")
    nmap_file = os.path.join(results_folder, "nmap_scan.txt")
    web_ports = []
    
    common_web_ports = ["80", "443", "8000", "8080", "8443"]

    try:
        with open(nmap_file, 'r') as f:
            for line in f:
                if "/tcp" in line and "open" in line:
                    port_info = line.split()[0]
                    port_number = port_info.split('/')[0]
                    
                    if port_number in common_web_ports:
                        web_ports.append(port_number)
                        print(f"[+] Found potential web service on port: {port_number}")
        
        return web_ports

    except FileNotFoundError:
        print(f"[!] ERROR: Nmap results file not found at {nmap_file}.")
        return []


def run_gobuster(target_ip, port, results_folder, wordlist_path):
    """Runs GoBuster against a target IP and port."""
    print("\n" + "-"*60)
    print(f"               Starting GoBuster on port {port}               ")
    print("-"*60)
    
    output_file = os.path.join(results_folder, f"gobuster_scan_port_{port}.txt")
    url = f"http://{target_ip}:{port}"
    command = ["gobuster", "dir", "-u", url, "-w", wordlist_path, "-o", output_file]

    print(f"[*] Target URL: {url}")
    print("[*] This may take a while...")

    try:
        subprocess.run(command, check=True, capture_output=True, text=True)
        print(f"[+] GoBuster scan on port {port} completed.")
        print(f"[+] Results saved to: {output_file}")
    except FileNotFoundError:
        print("\n[!] ERROR: 'gobuster' command not found. Skipping GoBuster scan.")
    except subprocess.CalledProcessError as e:
        print(f"\n[!] ERROR: GoBuster scan failed on port {port}.")

def run_nikto(target_ip, port, results_folder):
    """Runs Nikto against a target IP and port."""
    print("\n" + "-"*60)
    print(f"               Starting Nikto on port {port}               ")
    print("-"*60)
    
    output_file = os.path.join(results_folder, f"nikto_scan_port_{port}.txt")
    command = ["nikto", "-h", f"http://{target_ip}:{port}", "-o", output_file, "-Format", "txt"]

    print(f"[*] Target: http://{target_ip}:{port}")
    print("[*] This may also take a while...")

    try:
        subprocess.run(command, check=True, capture_output=True, text=True)
        print(f"[+] Nikto scan on port {port} completed.")
        print(f"[+] Results saved to: {output_file}")
    except FileNotFoundError:
        print("\n[!] ERROR: 'nikto' command not found. Skipping Nikto scan.")
    except subprocess.CalledProcessError as e:
        print(f"\n[!] ERROR: Nikto scan failed on port {port}.")

def get_severity(vulnerability_text):
    """Assigns a severity level based on keywords in vulnerability text."""
    text = vulnerability_text.lower()
    if any(keyword in text for keyword in ["critical", "rce", "remote code execution", "backdoor", "command execution"]):
        return "CRITICAL"
    if any(keyword in text for keyword in ["high", "sqli", "sql injection", "path traversal", "upload"]):
        return "HIGH"
    if any(keyword in text for keyword in ["medium", "xss", "cross-site scripting", "csrf"]):
        return "MEDIUM"
    if any(keyword in text for keyword in ["low", "disclosure", "directory indexing", "version"]):
        return "LOW"
    return "INFO"

def create_report(target_ip, results_folder, web_ports):
    """Creates a final summary report from all the scan results."""
    print("\n" + "="*60)
    print("             Generating Final Summary Report             ")
    print("="*60)
    
    report_file_path = os.path.join(results_folder, "Report.txt")

    with open(report_file_path, 'w') as report:
        report.write("="*135 + "\n")
        report.write(f"      Reconnaissance Report for Target: {target_ip}      \n")
        report.write("="*135 + "\n\n")
        report.write(f"Report generated on: {time.ctime()}\n\n")

        # --- Nmap Summary ---
        nmap_file_path = os.path.join(results_folder, 'nmap_scan.txt')
        report.write("-" * 135 + "\n")
        report.write("### Nmap Scan Results: Open Ports & Vulnerabilities ###\n")
        report.write("-" * 135 + "\n\n")
        try:
            with open(nmap_file_path, 'r') as nmap_file:
                nmap_results = []
                current_port_details = None
                for line in nmap_file:
                    port_line_match = re.match(r'^(\d+\/tcp)\s+open\s+([^\s]+)\s+(.*)', line)
                    if port_line_match:
                        if current_port_details: nmap_results.append(current_port_details)
                        current_port_details = { "port": port_line_match.group(1), "service_version": port_line_match.group(3).strip(), "vulnerabilities": "" }
                    elif line.strip().startswith(('|', '_')) and current_port_details:
                        clean_line = line.strip().lstrip('|_ ').strip()
                        if clean_line: current_port_details["vulnerabilities"] += clean_line + "\n"
                if current_port_details: nmap_results.append(current_port_details)

            if not nmap_results:
                report.write("No open ports found in Nmap scan.\n")
            else:
                header = "| {:<10} | {:<30} | {:<12} | {:<75} |".format("Port", "Service & Version", "Severity", "Vulnerability Details")
                report.write(header + "\n")
                report.write("|{:-<12}|{:-<32}|{:-<14}|{:-<77}|\n".format("", "", "", ""))
                for res in nmap_results:
                    vuln_details = res['vulnerabilities'].strip() or "(No vulnerabilities found by scripts)"
                    severity = get_severity(vuln_details)
                    vuln_lines = vuln_details.split('\n')
                    first_line = True
                    for v_line in vuln_lines:
                        if first_line:
                            report.write("| {:<10} | {:<30} | {:<12} | {:<75} |\n".format(res['port'], res['service_version'], severity, v_line))
                            first_line = False
                        else:
                            report.write("| {:<10} | {:<30} | {:<12} | {:<75} |\n".format("", "", "", v_line))

        except FileNotFoundError:
            report.write("Nmap results file not found.\n")
        report.write("\n\n")

        # --- Web Scans Summary ---
        if web_ports:
            report.write("-" * 135 + "\n")
            report.write("### Web Server Scan Results ###\n")
            report.write("-" * 135 + "\n\n")
            for port in web_ports:
                report.write(f"--- Results for Web Server on Port {port} ---\n\n")

                # GoBuster Table
                gobuster_file_path = os.path.join(results_folder, f'gobuster_scan_port_{port}.txt')
                report.write(f"[*] GoBuster: Discovered Directories & Files\n\n")
                try:
                    with open(gobuster_file_path, 'r') as f:
                        gobuster_results = []
                        for line in f:
                            match = re.match(r'^(/\S+)\s+\(Status: (\d+)\)', line)
                            if match:
                                gobuster_results.append({"path": match.group(1), "status": match.group(2)})
                        
                        if not gobuster_results:
                            report.write("No directories or files found by GoBuster.\n")
                        else:
                            header = "| {:<60} | {:<20} |".format("Path Found", "Status Code")
                            report.write(header + "\n")
                            report.write("|{:-<62}|{:-<22}|\n".format("", ""))
                            for res in gobuster_results:
                                report.write("| {:<60} | {:<20} |\n".format(res['path'], res['status']))
                except FileNotFoundError:
                    report.write("GoBuster results file not found for this port.\n")
                report.write("\n")

                # Nikto Table
                nikto_file_path = os.path.join(results_folder, f'nikto_scan_port_{port}.txt')
                report.write(f"[*] Nikto: Web Application Vulnerability Scan\n\n")
                try:
                    with open(nikto_file_path, 'r') as f:
                        nikto_results = []
                        for line in f:
                            if line.startswith('+'):
                                line = line.lstrip('+ ').strip()
                                osvdb_match = re.match(r'(OSVDB-\d+):\s+(\S+):\s+(.*)', line)
                                if osvdb_match:
                                    nikto_results.append({"id": osvdb_match.group(1), "uri": osvdb_match.group(2), "desc": osvdb_match.group(3)})
                                else:
                                    nikto_results.append({"id": "-", "uri": "/", "desc": line})
                        
                        if not nikto_results:
                            report.write("No vulnerabilities found by Nikto.\n")
                        else:
                            header = "| {:<12} | {:<15} | {:<30} | {:<70} |".format("Severity", "ID / Reference", "URI", "Finding Description")
                            report.write(header + "\n")
                            report.write("|{:-<14}|{:-<17}|{:-<32}|{:-<72}|\n".format("", "", "", ""))
                            for res in nikto_results:
                                severity = get_severity(res['desc'])
                                report.write("| {:<12} | {:<15} | {:<30} | {:<70} |\n".format(severity, res['id'], res['uri'], res['desc']))
                except FileNotFoundError:
                    report.write("Nikto results file not found for this port.\n")
                report.write("\n\n")

    print(f"[+] Final report created successfully: {report_file_path}")


if __name__ == "__main__":
    display_banner()
    results_folder = setup_results_folder()
    wordlist = get_wordlist_path()
    target = get_target_ip()
    
    print("\n" + "="*60)
    print("                      Initial Setup Complete                      ")
    print("="*60)
    print(f"\n[+] Tool is ready to proceed.")
    print(f"[+] Target IP: {target}")
    print(f"[+] Results will be saved in: {results_folder}")

    run_nmap_scan(target, results_folder)
    open_web_ports = find_web_ports(results_folder)

    if open_web_ports:
        print("\n[+] Web services detected! Proceeding with web-focused scans.")
        for port in open_web_ports:
            run_gobuster(target, port, results_folder, wordlist)
            run_nikto(target, port, results_folder)
    else:
        print("\n[*] No open web ports found in the scan results.")
        print("[*] Skipping web-focused scans.")
    
    create_report(target, results_folder, open_web_ports)

    print("\n[+] All scans and reporting complete. Check the results folder for output files.")
    print("\n[+] Reconnaissance complete.")
