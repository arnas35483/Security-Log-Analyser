import os
import re
import csv
from collections import Counter

def load_data(filename):
    lines = []
    try:
        f = open(filename, 'r', encoding='utf-8')
        for line in f:
            lines.append(line.strip())
        f.close()
    except:
        print("Error reading file:", filename)
    return lines

def analyse_data(data):
    results = {
        'fw_valid': 0, 'fw_malformed': 0, 'allow': 0, 'block': 0,
        'fw_ips': Counter(), 'blocked_ips': Counter(), 'ports': Counter(),
        'auth_valid': 0, 'auth_malformed': 0, 'success': 0, 'fail': 0, 'lockout': 0,
        'auth_ips': Counter(), 'users': Counter()
    }
    
    fw_reg = r'^([\d-]+ [\d:]+)\s+(ALLOWED|BLOCKED)\s+src=([\d\.]+)?\s*dst=([\d\.]+)?\s*proto=\w+\s+port=(\d+|\w+)'
    auth_reg = r'^([\d-]+ [\d:]+)\s+(LOGIN_SUCCESS|LOGIN_FAILED|ACCOUNT_LOCKOUT)\s+user=(\S+)?\s*src=([\d\.]+)?'
   
    for filename, lines in data.items():
        if 'firewall' in filename.lower():
            for line in lines:
                if not line or line.startswith("MALFORMED"):
                    results['fw_malformed'] += 1
                    continue
                match = re.match(fw_reg, line)
                if match:
                    action = match.group(2)
                    src_ip = match.group(3) or "Unknown"
                    dst_port = match.group(5) or "Unknown"
                    
                    results['fw_valid'] += 1
                    results['fw_ips'][src_ip] += 1
                    
                    if dst_port.isdigit():
                        results['ports'][dst_port] += 1
                    
                    if action == 'ALLOWED':
                        results['allow'] += 1
                    elif action == 'BLOCKED':
                        results['block'] += 1
                        results['blocked_ips'][src_ip] += 1
                else:
                    results['fw_malformed'] += 1
                    
        elif 'authentication' in filename.lower():
            for line in lines:
                if not line or line.startswith("MALFORMED"):
                    results['auth_malformed'] += 1
                    continue
                match = re.match(auth_reg, line)
                if match:
                    results['auth_valid'] += 1
                    event = match.group(2)
                    username = match.group(3)
                    src_ip = match.group(4)
                    
                    if event == 'LOGIN_SUCCESS':
                        results['success'] += 1
                    elif event == 'LOGIN_FAILED':
                        results['fail'] += 1
                        results['auth_ips'][src_ip] += 1
                        results['users'][username] += 1
                    elif event == 'ACCOUNT_LOCKOUT':
                        results['lockout'] += 1
                else:
                    results['auth_malformed'] += 1
                    
    return results

def calculate_risk(result):
    analysis = {}
    analysis['firewall'] = {
        'total_valid': result['fw_valid'],
        'total_malformed': result['fw_malformed'],
        'allowed': result['allow'],
        'blocked': result['block'],
        'unique_source_ips_count': len(result['fw_ips']),
        'top_blocked_ips': result['blocked_ips'].most_common(5),
        'top_destination_ports': result['ports'].most_common(5)
    }
    
    analysis['authentication'] = {
        'total_valid': result['auth_valid'],
        'total_malformed': result['auth_malformed'],
        'login_success': result['success'],
        'login_failed': result['fail'],
        'account_lockout': result['lockout'],
        'top_failed_login_ips': result['auth_ips'].most_common(5),
        'top_targeted_usernames': result['users'].most_common(5)
    }
    return analysis

def generate_report(results):
    fw = results['firewall']
    auth = results['authentication']
    
    print("FIREWALL METRICS:")
    print("Total Valid:", fw['total_valid'])
    print("Total Malformed:", fw['total_malformed'])
    print("Allowed:", fw['allowed'])
    print("Blocked:", fw['blocked'])
    print("Unique Source IPs:", fw['unique_source_ips_count'])
    print("Top Blocked IPs:", fw['top_blocked_ips'])
    print("Top Ports:", fw['top_destination_ports'])
    print()
    
    print("AUTHENTICATION METRICS:")
    print("Total Valid:", auth['total_valid'])
    print("Total Malformed:", auth['total_malformed'])
    print("Success:", auth['login_success'])
    print("Failed:", auth['login_failed'])
    print("Lockouts:", auth['account_lockout'])
    print("Top Failed IPs:", auth['top_failed_login_ips'])
    print("Top Targeted Users:", auth['top_targeted_usernames'])
    print()
    
    print("SECURITY OBSERVATIONS:")
    obs = []
    
    if fw['blocked'] > 0 and fw['top_blocked_ips']:
        top_ip = fw['top_blocked_ips'][0]
        obs1 = f"Lots of firewall blocks. Top blocked IP is {top_ip[0]} with {top_ip[1]} blocks. Likely to be a port scan attack."
        print(obs1)
        obs.append(obs1)
        
    if auth['login_failed'] > 0 and auth['top_failed_login_ips']:
        top_auth = auth['top_failed_login_ips'][0]
        obs2 = f"Brute force alert: {auth['login_failed']} failed logins. {top_auth[0]} hit the server {top_auth[1]} times."
        print(obs2)
        obs.append(obs2)
        
    try:
        f = open("investigation_summary.txt", "w", encoding="utf-8")
        f.write("LOG ANALYSIS SUMMARY:\n\n")
        f.write(str(results))
        f.write("\n\nOBSERVATIONS:\n")
        f.write(str(obs))
        f.close()
    except Exception as e:
        print("error saving txt:", e)

    try:
        with open("investigation_summary.csv", "w", newline="", encoding="utf-8") as csv_f:
            writer = csv.writer(csv_f)
            writer.writerow(["Category", "Metric", "Value"])
            for cat in ['firewall', 'authentication']:
                for k, v in results[cat].items():
                    writer.writerow([cat, k, str(v)])
    except Exception as e:
        print("error saving csv:", e)

def main():
    raw_data = {}
    fw_file = "firewall.log"
    auth_file = "authentication.log"
    
    if os.path.exists(fw_file):
        raw_data[fw_file] = load_data(fw_file)
    else:
        raw_data[fw_file] = []
        
    if os.path.exists(auth_file):
        raw_data[auth_file] = load_data(auth_file)
    else:
        raw_data[auth_file] = []
        
    extracted = analyse_data(raw_data)
    processed = calculate_risk(extracted)
    generate_report(processed)

if __name__ == "__main__":
    main()
