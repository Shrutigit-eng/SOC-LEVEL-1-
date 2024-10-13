SOC Level 1

Pyramid of Pain in Cybersecurity

The Pyramid of Pain illustrates the various levels of Indicators of Compromise (IOCs) in cybersecurity. Each level represents different types of threat intelligence that can help organizations understand and mitigate risks:
          +---------------------+
          |   Threat Actors     |      // Highest level, understanding who is behind the attacks
          +---------------------+
          |  Tactics, Techniques,|   // Analyzing the methods and strategies used by attackers
          |    and Procedures    |
          +---------------------+
          |        Tools        |      // Identifying the tools and software used in attacks
          +---------------------+
          |   Email Addresses    |    // Monitoring email addresses used in phishing and spam campaigns
          +---------------------+
          |        URLs         |     // Tracking URLs that may lead to malicious content
          +---------------------+
          |     Domain Names     |   // Examining suspicious domain names associated with attacks
          +---------------------+
          |     IP Addresses     |     // Analyzing IP addresses to identify malicious traffic
          +---------------------+
          |     Hash Values      |     // Using hash values to identify known malicious files
          +---------------------+

Open-Source Databases
Open-source databases provide valuable resources for detecting and preventing malicious activities involving IP addresses. Some notable databases include:
AbuseIPDB: A project aimed at helping to report and track abusive IP addresses.
Cisco Talos Intelligence: A threat intelligence service that provides insights into potential threats and vulnerabilities.
Shodan: A search engine for Internet-connected devices, useful for identifying vulnerable systems.
IP-SCANNER.THM: A tool for scanning IP addresses and finding open ports or services.

Hashing Tools
Hashing Algorithms
MD5 and SHA-1 are considered outdated and insecure due to vulnerabilities that can be exploited.
SHA-2 (such as SHA-256) is currently regarded as a strong and secure hashing algorithm, widely adopted for various applications, including password hashing and data integrity verification.
Hash Lookup Tools
Tools for identifying malicious files by uploading a file, hash, or URL include:
VirusTotal: An online service that analyzes files and URLs for malware and other security threats using multiple antivirus engines.
MetaDefender Cloud (by OPSWAT): A cloud-based service for file and URL analysis, providing multi-scanning for malware detection.

IP Address Tools
Malware Behavior Analysis
Any.run: An interactive malware analysis sandbox that allows users to analyze the behavior of malware in real time, providing insights into its actions and potential impacts.

Domain Name Tools
Identifying Suspicious Domains
Proxy Logs or Web Server Logs: These logs can help identify and analyze suspicious domain names that may be linked to malicious activities.
Short Link Services
Services that create short links, often used to disguise malicious URLs:
bit.ly: A URL shortening service that can obscure the destination of links.
tinyurl.com: Another popular service for creating short URLs, often used in phishing attacks.

Host and Network Artifacts
Network Artifacts
Wireshark: A powerful network protocol analyzer that allows users to capture and interactively browse the traffic running on a computer network, aiding in the investigation of suspicious activities.
Malware and Threat Databases
Platforms to understand real malware and threats include:
MalwareBazaar: A repository for malware samples that allows researchers and analysts to share and download malware samples for analysis.
Malshare: A free malware repository providing access to malware samples for security research and analysis.

Additional Resources
For further insights into digital forensics and incident response, visit The DFIR Report, which offers valuable resources and reports on various cybersecurity incidents.
