# Phishing/Email Analysis

## Project Description

This project focused on understanding and analyzing phishing email attacks, a common form of social engineering used to steal sensitive information or deploy malware. Through this analysis, I examined a real phishing email found in my spam folder, identified key red flags within both the email header and body. While setting up a secure environment (using Windows 11 on VMware Fusion) I extracted and analyzed email meta data, verifying inconsistencies in sender details, authentication failures (SPF, DKIM, DMARC), and suspicious IP addresses using tools like MXToolbox, VirusTotal, and AbuseIPDB. The findings revealed clear signs of phishing, including impersonation of Coinbase, mismatched domains, and lack of authentication protocols. This project highlights the importance of email security awareness and demonstrates practical techniques to detect and mitigate phishing threats effectively.

## Understanding Phishing

Phishing is a fraudulent attempt to obtain sensitive information such as usernames, passwords, and credit card details by disguising as a trustworthy entity. Attackers use deceptive emails, messages, or websites to trick users into revealing confidential data.

## Analysis Steps

### 1. Identifying Phishing Indicators
- **Suspicious Sender Address**: The sender's domain did not match the legitimate Coinbase domain.
- **Urgency & Threats**: The email pressured the recipient to take immediate action to avoid account suspension.
- **Poor Grammar & Formatting**: Phishing emails often contain typos and inconsistent formatting.

### 2. Email Header Analysis
- Extracted email headers to analyze SPF, DKIM, and DMARC authentication results.
- Identified a mismatch between the "From" address and the return path.
- Traced the originating IP and checked its reputation using AbuseIPDB.

### 3. URL and Attachment Inspection
- Hovered over links to verify discrepancies between displayed URLs and actual destinations.
- Scanned suspicious URLs using VirusTotal to check for malicious domains.
- Checked for unexpected attachments and used a sandbox environment for further analysis.

## Tools Used
- **MXToolbox** (Email Header Analysis)
- **VirusTotal** (URL and File Scanning)
- **AbuseIPDB** (IP Address Reputation)
- **Windows 11 on VMware Fusion** (Secure Testing Environment)

## Key Findings
- The email attempted to impersonate Coinbase with a fraudulent login page.
- SPF and DKIM failed authentication checks, indicating spoofed sender details.
- The included link redirected to a phishing website designed to steal credentials.
- The originating IP address had a high abuse score on AbuseIPDB.

## Conclusion
By analyzing the phishing email, I identified multiple red flags that indicated a fraudulent attempt to steal sensitive information. This project reinforces the importance of email security awareness and the need for verification before interacting with suspicious emails.

## Prevention Tips
- Always verify the sender’s email address.
- Hover over links before clicking to check the actual destination.
- Do not download unexpected attachments.
- Report phishing emails to IT/security teams or services like PhishTank.
- Use multi-factor authentication (MFA) to protect accounts from unauthorized access.

## References
- [MXToolbox](https://mxtoolbox.com/)
- [VirusTotal](https://www.virustotal.com/)
- [AbuseIPDB](https://www.abuseipdb.com/)
- [Coinbase Security](https://www.coinbase.com/security)
