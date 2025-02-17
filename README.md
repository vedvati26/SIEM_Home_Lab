# SIEM_Home_Lab

Requirements

Hardware:

Ubuntu Server 22.04 (for Splunk Enterprise)

Windows 11 Machine

Software:

Splunk Enterprise

Splunk Universal Forwarder

Investigating Web-based Attacks

SQL Injection:

Analyzed web logs to detect potential SQL injection attempts.

Hint: Look for unusual characters or SQL keywords used in URI parameters, such as ' or 1=1.

Cross-Site Scripting (XSS):

Monitored web logs for signs of XSS attacks.

Hint: Search for requests containing suspicious JavaScript keywords like "script", "", or "onload".

Cross-Site Request Forgery (CSRF):

Identified CSRF attacks in web logs.

Hint: Look for requests with unexpected or unauthorized actions.

Directory Traversal:

Searched for indications of Directory Traversal attacks.

Hint: Check for requests containing ../ or %2e%2e/ sequences.

Brute Force:

Monitored access logs for brute force attack patterns.

Hint: Look for repeated login attempts from the same IP address.

Session Hijacking:

Detected session hijacking attempts by analyzing web logs.

Hint: Look for multiple logins from different IPs for the same user account.

Remote Code Execution (RCE):

Identified potential RCE attempts in web logs.

Hint: Look for unusual file extensions or commands.

XML External Entity (XXE):

Searched for XML External Entity attacks.

Hint: Look for XML payloads referencing external entities.

Insecure Deserialization:

Detected Insecure Deserialization attempts.

Hint: Look for serialized data or references to vulnerable libraries.

Server-Side Request Forgery (SSRF):

Monitored web logs for SSRF attacks.

Hint: Look for URLs pointing to internal or sensitive resources.


Investigating Network-based Attacks

Port Scanning:

Detected port scanning activities in network logs.

Hint: Look for multiple connection attempts from the same source IP to different destination ports.

DDoS Attack:

Identified Distributed Denial of Service attacks.

Hint: Watch for a sudden increase in traffic volume.

Brute Force SSH Attack:

Detected brute force SSH login attempts.

Hint: Check for repeated failed login attempts from the same source IP.

DNS Tunneling:

Identified DNS tunneling activities.

Hint: Look for DNS queries with abnormally large query sizes.

Malicious Payload:

Detected known malicious payloads using Suricata or Zeek IDS.

Hint: Search for signatures associated with malware.

Malicious File Download:

Detected malicious file downloads in HTTP server logs.

Hint: Search for requests with file extensions like .exe or .dll.

Network Reconnaissance:

Identified network reconnaissance activities using Suricata IDS.

Hint: Look for multiple connection attempts from the same source IP.

Man-in-the-Middle (MitM) Attack:

Detected potential MitM attacks.

Hint: Look for rejected connections or incomplete TCP handshakes.

Data Exfiltration:

Identified data exfiltration attempts.

Hint: Look for large outbound data transfers or high volumes of data sent to external destinations.
