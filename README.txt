A python-based, small SOC-style analysis tool that turns the supplied firewall and authentication logs into a clear
investigation summary.

# Scenario Overview
The project aims to analyze automated network logging data to detect security incidents. It analyzes incoming traffic data to detect possible port scan attacks. It analyzes authentication events to monitor failed login attempts and possible brute-force attacks.

# Setup & Dependencies
- Python Version: Python 3
- Dependencies: "os", "re", "csv", "json", "collections.Counter"

# Input Files
The script expects the following log files to be present in the same directory:
1. "firewall.log" – Network traffic logs tracking actions (ALLOWED/BLOCKED), source/destination IPs, protocols, and port connections.
2. "authentication.log" – User login records tracking events (LOGIN_SUCCESS/LOGIN_FAILED/ACCOUNT_LOCKOUT), usernames, source IPs, hostnames, and access methods.

#How to Run the Project

1. Place Files Together: Verify that your script "main.py", "firewall.log", and "authentication.log" are all sitting in the same folder.
2. Execute via Terminal: Open your command line or terminal, navigate to your folder path, and run the script:
   
python main.py

3. View Live Summary: The script will output a clean breakdown of security metrics and high-priority analyst observations directly onto your console screen.
4. Browse Generated Artifacts: After running, the script automatically exports its comprehensive risk calculations into three new physical tracking files in the directory:
- "investigation_summary.txt" (Human-readable plaintext brief)
- "investigation_summary.json" (Structured object layout for external tools)
- "investigation_summary.csv" (Tabular view for spreadsheet analysis)

#Explainable Design Choices
-Functions: Modularized into "load_data()", "analyse_data()", "calculate_risk()", and "generate_report()" to create a clear separation of code.
-Data Structures: Uses built-in "collections.Counter” to track the top 5 most occurring security outliers.
-Validation & Error Handling: Safe column parsing using defensive regular expressions. Lines with missing attributes or intentional explicit errors do not break the execution pipeline, but are cleanly bucketed into malformed data counters to ensure full integrity of analyst data.
