# Phishing/Email Analysis

_**Project Overview**_:

This project focused on understanding and **analyzing phishing email attacks**, a common form of **social engineering** used to steal sensitive information or deploy malware. Through this analysis, I examined a real phishing email found in my spam folder, identified key **red flags** within both the email header and body. While setting up a secure environment (using Windows 11 on VMware Fusion) I extracted and analyzed email meta data, verifying inconsistencies in sender details, authentication failures (**SPF, DMK, DMARC**), and suspicious IP address using tools like **MXToolbox**, **VirusTotal**, and **AbuseIPDB**. The findings revealed clear signs of phishing, including impersonation of Coinbase, mismatched domains, and lack of authentication protocols. This project highlights the importance of email security awareness and demonstrates practical techniques to detect and mitigate phishing treats effectively. 


---

<p align="center">
  <img src="https://github.com/user-attachments/assets/5296c065-6e95-41ff-9c1f-3c9a68d0d945" />
</p>




# Technology Utilized
- **VMware Fusion**: Windows VM for safe email anaysis
- **Threat Intel and Analysis**: VirusTotal, Abuse IPDB, MxToolBox
- **Email Security Protocols**: SPF, DKIM, DMARC

---


# Table of Contents

- [Understanding Phishing](#vulnerability-management-policy-draft-creation)
- [Analyzing the Email Header](#step-2-mock-meeting-policy-buy-in-stakeholders)
- [Analyzing the Email Body](#step-3-policy-finalization-and-senior-leadership-sign-off)
- [Analysis of Phising Email](#step-4-mock-meeting-initial-scan-permission-server-team)

---

## Understanding Phishing

Phishing is a type of social engineering attack in which an attacker/hacker will send fake emails that appear to be from reputable sources with the intent to gain access (via malicious links or files) for data theft, personal information, or install malware. There are several different types of phishing attacks: 

- **Phishing**: often referred to as a “spay and pray”. As previously mentioned, it is sending fake emails that appear to be from reputable sources with the aim of convincing individuals within a company or across a network to reveal personal information like passwords or credit cards or to deliver malware.
- **Spear Phishing**: More targeted form of phishing that is used by cybercriminals who are more tightly focused on a specific group of individuals or organizations.
- **Whaling**: Form of spear phishing that targets high-profile individuals, like CEOs or CFOs.
- **Business Email Compromise (BEC)**: sophisticated type of phishing attacks taking over a company’s internal email account to conduct malicious activities like unauthorized fund transfers, redirect payments, or steal company data.
- **Vishing (Voice Phishing)**: Attacker tricks their victims into sharing personal or financial information over the phone.
- **Smishing (SMS Phishing)**: Involves the use of text messages to trick individuals into providing their personal information. 

Since this project will primarily cover Phishing Email Attacks, I will focus on what to look for within a perspective phishing email. The primary goal of a phishing email is to look as legitimate as possible to increase the chances of a victim to either click on links or open malicious files attached to the email. When looking at an email, we can look at either the Header or the Body of the email to analyze signs of a phishing attack. 

- **Header**: The header of the email will contain the technical details of the email that include, the sender, recipient, and routing information. *See below for analysis*
- **Body**: The main body of the email contains the main content of the email which include, the text, images, or links. *See below for analysis*


---

## Analyzing the Email Header

- **"From" Address** :
  - Check the sender's email address for inconsistencies or slight misspellings that mimic legitimate domains (e.g., "support@paypa1.com" instead of "support@paypal.com").
  - Verify if the domain matches the supposed sender's official domain.
- **"Reply-To" Address**
  - Inspect the "Reply-To" field. Phishing emails often use a different reply address than the "From" address, redirecting replies to the scammer.
- **"Received" Fields**:
  - Check the "Received" headers to trace the path of the email. Compare the IP addresses and domains to ensure they originate from a legitimate source.
  - If the email claims to be from a well-known service but the IP belongs to an unrelated provider, this is suspicious.

- **IP Address and Domain Reputation:**
  - Analyze the IP addresses in the "Received" fields. Use tools like MXToolbox or IPVoid to check if the IP is associated with phishing or spam.
  - Look up the sending domain for any blacklists or warnings using domain reputation tools like Whois or MXToolbox.

- **External Links and Attachments:**
  - Hover over any links to inspect their true destination. Ensure they match the expected domain (e.g., "delivero[.]com"). Use tools like VirusTotal or PhishTank to scan URLs for malware or phishing attempts.
  - Do not download or open any attachments unless you are certain of their legitimacy. Suspicious attachments should be scanned using antivirus software or online services like VirusTotal to check for malware.

- **DKIM Signature (DomainKeys Identified Mail):**
  - DKIM verifies if the email was sent by the legitimate domain. Check if the DKIM signature in the header is valid and aligned with the domain of the email sender.

- **SPF Record (Sender Policy Framework):**
  - Look for an SPF record result in the header, indicating if the email passed or failed SPF authentication. A pass means the email came from an authorized server for that domain.
  - If it fails, it's a sign the email may be forged.

- **DMARC Authentication:**
  - DMARC (Domain-based Message Authentication, Reporting & Conformance) ensures the email’s authenticity. Look for pass or fail results, which indicate whether the message aligns with SPF and DKIM policies.

- **Message-ID:**
  - Every legitimate email has a unique Message-ID. Check for strange patterns in this field, such as missing, repeated, or generic message IDs, which can indicate spoofing.

- **Subject Encoding and Language:**
  - Review the subject line for suspicious characters, encoding issues, or misspellings. Malicious actors often use strange encoding or poorly constructed subjects to bypass filters.

- **MIME-Version:**
  - Check the MIME-Version field to see how the email’s format is structured. Irregular MIME types or missing headers may indicate an attempt to manipulate the format for malicious purposes.


---

## Analyzing the Email Body

- **Unfamiliar sender or email address:**  
  The email is from someone you don't recognize, or the domain is slightly misspelled (e.g., "support@paypa1.com" instead of "support@paypal.com").

- **Urgent or alarming language:**  
  The email pressures you to act immediately, often threatening consequences if you don’t.

- **Suspicious attachments or links:**  
  Unexpected attachments or links that request sensitive information or lead to unfamiliar websites.

- **Generic greetings:**  
  Using broad salutations like "Dear Customer" instead of addressing you by name.

- **Spelling and grammar mistakes:**  
  Phishing emails often contain poor grammar, awkward language, or spelling errors.

- **Request for personal or financial information:**  
  Asking for passwords, credit card numbers, or other sensitive information.

- **Mismatch between display name and email address:**  
  The name shown in the email may not match the actual email address.

- **Inconsistent or suspicious URLs:**  
  Hover over links without clicking to check if the destination URL matches the claimed website.

- **Unexpected request for payment:**  
  An email asking for payment for a service you don't recognize or weren't expecting.

- **Too good to be true offers:**  
  Promises of large rewards, cash prizes, or free gifts that seem unrealistic.

- **Unfamiliar or odd attachments:**  
  Unexpected file attachments, especially if they have unusual extensions like `.exe`, `.zip`, or `.rar`.

- **Lack of company branding:**  
  Legitimate companies typically include professional logos, branding, and consistent formatting.

- **Unusual sender’s email domain:**  
  The email might come from a suspicious or untrusted domain, rather than an official company email (e.g., "info@gmail.com" instead of "support@company.com").

- **No signature or contact information:**  
  Legitimate companies usually include proper signatures and contact details at the end of their emails.

----

## Analysis of Phishing Email

To ensure a safe and controlled environment, I used a virtual machine (VM) for the analysis. I installed and ran Windows 11 via VMware Fusion on my 
macOS. I then used my own personal email inbox and went digging through my spam folder to find a prospective phishing email.  


### Step 1: Installing and Running Windows 11 via VMware Fusion


- **VMware Fusion:**
  - To install Windows 11 via VMware Fusion, I began by navigating to [VMware's website](https://www.vmware.com/products/desktop-hypervisor/workstation-and-fusion) to download Fusion.
  - This redirected me to the Broadcom website, where I created an account to access the downloads.
  - I downloaded VMware Fusion version 13.6.2.
  - After downloading, I opened the application and proceeded through the installation process.

- **Windows 11:**
  - During installation, I selected **“Get Windows from Microsoft”** to download the Windows 11 distribution and generate an ISO file.
  - I allocated resources and adjusted the settings as required for the VM.
  - Booted the VM and completed the Windows 11 installation process.
  - Once installed, I installed **VMware Tools** via the *Virtual Machine* tab to enable graphics drivers and compatibility layers. This allowed me to use different screen resolutions within the VM. I then rebooted the machine.


### Step 2: Opening and Analyzing Email Body

- **Used the VM to open the following email:**
![image](https://github.com/user-attachments/assets/25ae1cbe-2f8d-41be-9469-8536b33e2ad9)



- **Identifying the Red Flags within the Body:**
  - **Unfamiliar Sender:** The email was from `no-reply info@elevatedentalmo.com`, which is unknown to me.
  - **Suspicious Email Address:** It appeared to be from Elevated Dental, which has no connection to my Coinbase account.
  - **Urgent Language:** The subject was titled:  
    *“Action Required: Confirm your info to Unlocked your Coinbase. Mon. February 24, 2025 3:50 PM”*  
    It attempted to create urgency.
  - **Suspicious Links:** Each link appeared to not go anywhere or led to sketchy sites.
  - **Spelling/Grammar Mistakes:** There were grammar errors in the subject.
  - **Mismatched Display Name vs. Email Address:** The display name was “CoinBase” but the email came from Elevated Dental Mo.
  - **Requesting Sensitive Information:** The email asked for personal verification information.
  - **Lack of Branding:** There were no logos or branding elements in the email.


### Step 3: Extracting Email Header

- **Extract the Header:**
  - I clicked `More > View Raw Message` to access the email header:
  - ![image](https://github.com/user-attachments/assets/b5fd0b17-f692-4264-a127-c9f99c16305d)
- Although raw headers include all necessary metadata, they're difficult to read.
- I used **MXToolBox Header Analyzer** to format the header for easier analysis:
![image](https://github.com/user-attachments/assets/650bf900-9f5f-49a5-9e8c-a5ff12a49115)


### Step 4: Analyzing the Email Header

- **Key Findings:**
  - **Not DMARC Compliant:**  
    - The header revealed that the email lacked DMARC, SPF, and DKIM authentication.
  - **From Domain Mismatch:**  
    - The sending domain `<universaljunkhauling.com>` does not match the claimed sender `<info@elevatedentalmo.com>`.
  - **Reply-To Mismatch:**  
    - The reply-to address `<do3wzg58sej4tl9hxv@universaljunkhauling.com>` differs from the sender.
  - **IP Address:**  
    - The originating IP `<209.85.214.229>` and the internal IP `<10.217.151.10>` did not match.  
    - According to AbuseIPDB, these IPs are flagged for spam, phishing, fraud, and spoofing.
  - **Relaying Domain:**  
    - The domain used to relay the message was `universaljunkhauling.com`.



### Step 5: Summary of Findings and Takeaways

- This email exhibits multiple phishing indicators, including impersonation of Coinbase, mismatching domains, lack of authentication protocols, and suspicious sender details. The presence of malicious IPs further confirms this is a phishing attempt designed to steal sensitive user information.


- **Recommended Actions:**
  - Do not click on any links or open attachments.
  - Report the email to Coinbase.
  - Block the sender and domain to prevent future phishing attempts.

- **Preventing Phishing Attacks:**
  - **Implementing email filtering solutions like DMARC, DKIM, and SPF:**
    - **DMARC** (Domain-based Message Authentication, Reporting, and Conformance):  
      Detects and prevents spoofing by enforcing policies for email validation.
    - **DKIM** (DomainKeys Identified Mail):  
      Verifies if the email was sent by a valid source using a digital signature.
    - **SPF** (Sender Policy Framework):  
      Verifies that the sender's IP address is authorized to send emails on behalf of the domain.

  - **Other Measures:**
    - Implement anti-phishing awareness campaigns.
    - Provide regular user security training.
    - Enable Multi-Factor Authentication (MFA).
      - MFA
      - 2FA
    - Perform continuous software patching and updates.


---

### Summary:

The above project focused on identifying and analyzing a phishing email impersonating Coinbase, highlighting key red flags such as mismatched domains, authentication failures (SPF, DKIM, DMARC), and suspicious links. Using a Windows 11 virtual machine on VMware Fusion, I examined the email header and body with tools like MXToolbox, VirusTotal, and AbuseIPDB to verify sender authenticity and detect malicious content. The analysis reinforced the importance of recognize phishing tactics, leveraging threat intelligence, and implementing preventive measures such as email filtering, MFA, and user awareness training. This hands-on investigation showcased practical techniques to detect, analyze, and mitigate phishing threats effectively.


