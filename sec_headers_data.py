import time
import subprocess
import random
import requests
import dns.resolver
from urllib.parse import urlparse

# ANSI escape codes for text color
colors = ["\033[1;31m", "\033[1;32m", "\033[1;33m", "\033[1;34m", "\033[1;35m", "\033[1;36m", "\033[1;37m"]
random_color = random.choice(colors)
reset = '\033[0m'

# Banner text
banner = """
                             █████                         █████                                  █████         █████           
                            ░░███                         ░░███                                  ░░███         ░░███            
  █████  ██████ ██████       ░███████   ██████ ██████   ███████  ██████ ████████ █████         ███████  ██████ ███████  ██████  
 ███░░  ███░░█████░░███      ░███░░███ ███░░██░░░░░███ ███░░███ ███░░██░░███░░█████░░         ███░░███ ░░░░░██░░░███░  ░░░░░███ 
░░█████░██████░███ ░░░       ░███ ░███░███████ ███████░███ ░███░███████ ░███ ░░░░█████       ░███ ░███  ███████ ░███    ███████ 
 ░░░░██░███░░░░███  ███      ░███ ░███░███░░░ ███░░███░███ ░███░███░░░  ░███    ░░░░███      ░███ ░███ ███░░███ ░███ █████░░███ 
 ██████░░█████░░█████████████████ ████░░█████░░███████░░███████░░██████ █████   █████████████░░███████░░████████░░████░░████████
░░░░░░  ░░░░░░ ░░░░░░░░░░░░░░░░░ ░░░░░ ░░░░░░ ░░░░░░░░ ░░░░░░░░ ░░░░░░ ░░░░░   ░░░░░░░░░░░░░░ ░░░░░░░░ ░░░░░░░░  ░░░░░ ░░░░░░░░ 
                                                                                                                                
_"""

# Print banner
print(random_color + banner + reset)
print(random_color + "sec_headers_data V2.0 script by: Dark_Shadow04" + reset)
print(random_color + "https://github.com/DarkShadow04" + reset)
print(random_color + "Copyright 2024 Dark_Shadow04" + reset)

# Define the list of security headers to check
HEADERS = {
    "Content-Security-Policy": ("Controls resources the user agent is allowed to load for a given page.", "Very Critical"),
    "X-Content-Type-Options": ("Prevents browsers from MIME-sniffing a response away from the declared content-type.", "Very Important"),
    "X-Frame-Options": ("Prevents your webpage from being put in an iframe.", "Important"),
    "X-XSS-Protection": ("Enables the Cross-site scripting (XSS) filter built into most recent web browsers.", "Important"),
    "Strict-Transport-Security": ("Instructs web browsers to access your website only over HTTPS.", "Very Important"),
    "Referrer-Policy": ("Controls how much referrer information should be included with requests.", "Important"),
    "Feature-Policy": ("Allows web developers to selectively enable and disable use of various browser features.", "Optional"),
    "Public-Key-Pins": ("Associates a specific cryptographic public key with a certain web server to decrease the risk of MITM attacks.", "Optional"),
    "Expect-CT": ("Allows sites to opt in to reporting and/or enforcement of Certificate Transparency requirements.", "Optional"),
    "Content-Security-Policy-Report-Only": ("Allows web developers to experiment with policies by monitoring (but not enforcing) their effects.", "Optional"),
    "Access-Control-Allow-Origin": ("Indicates whether the response can be shared with requesting code from the given origin.", "Important"),
    "Access-Control-Allow-Methods": ("Indicates which HTTP methods are allowed on a particular endpoint.", "Important"),
    "Access-Control-Allow-Headers": ("Indicates which headers can be used during the actual request.", "Important"),
    "Access-Control-Allow-Credentials": ("Indicates whether the response can be exposed when the credentials flag is true.", "Important"),
    "Access-Control-Expose-Headers": ("Lets a server whitelist headers that browsers are allowed to access.", "Optional"),
    "Access-Control-Max-Age": ("Indicates how long the results of a preflight request can be cached.", "Optional"),
    "X-Permitted-Cross-Domain-Policies": ("Controls whether Flash and other plugins may access resources from other domains.", "Optional"),
    "Clear-Site-Data": ("Gives a web developer the ability to clear out a user’s local data for a particular website.", "Optional"),
    "Content-Disposition": ("Indicates if the browser should display a save/download dialog for the response.", "Optional"),
    "Cross-Origin-Opener-Policy": ("Allows a web page to opt into the same-origin policy.", "Important"),
    "Cross-Origin-Embedder-Policy": ("Allows a web page to control whether and how a cross-origin document may embed itself.", "Important"),
    "X-Content-Security-Policy": ("Controls resources the user agent is allowed to load for a given page.", "Very Critical"),
    "X-DNS-Prefetch-Control": ("Controls DNS prefetching, which performs domain name resolution in the background.", "Optional"),
    "Content-Language": ("Specifies the language(s) of the intended audience for the enclosed content.", "Optional"),
    "Cache-Control": ("Tells all caching mechanisms from server to client whether they may cache this object.", "Important"),
    "Expires": ("Gives the date/time after which the response is considered stale.", "Optional"),
    "Pragma": ("Provides directives for cache handling in client-server communication.", "Optional"),
    "Report-To": ("Allows the server to specify where to send reports when a Content Security Policy violation is detected.", "Optional")
}

# Function to check the presence of headers and their statuses
def check_security_headers(url):
    response = requests.get(url)
    headers = response.headers

    result = []
    for header, (description, level) in HEADERS.items():
        status = "Present" if header in headers else "Not Present"
        result.append(f"Header: {header}\nDescription: {description}\nStatus: {status}\nIntegration Level: {level}\n\n")
    
    return result

# Function to check DMARC, SPF, and DKIM records
def check_email_security(domain):
    # Remove 'www' prefix from the domain
    domain = domain.replace("www.", "")
    
    def get_txt_record(record_name):
        try:
            result = dns.resolver.resolve(record_name, 'TXT')
            return [str(r).strip('"') for r in result], "Record Present"
        except dns.resolver.NoAnswer:
            return [f"No TXT record found for {record_name}."], "Record Not Present"
        except dns.resolver.NXDOMAIN:
            return [f"The DNS query name does not exist: {record_name}."], "Record Not Present"
        except Exception as e:
            return [str(e)], "Needs Update"
    
    dmarc, dmarc_status = get_txt_record(f"_dmarc.{domain}")
    spf, spf_status = get_txt_record(domain)
    dkim, dkim_status = get_txt_record(f"default._domainkey.{domain}")

    dmarc_details = "DMARC (Domain-based Message Authentication, Reporting, and Conformance) helps prevent email spoofing by validating that incoming messages come from the domain they claim to come from."
    spf_details = "SPF (Sender Policy Framework) helps prevent email spoofing by specifying which mail servers are allowed to send email on behalf of your domain."
    dkim_details = "DKIM (DomainKeys Identified Mail) allows the receiver to check that an email was indeed sent and authorized by the owner of that domain."

    dmarc_report = f"DMARC: {dmarc_status}\nDetails: {dmarc_details}\n" + "\n".join(dmarc) + "\n\n"
    spf_report = f"SPF: {spf_status}\nDetails: {spf_details}\n" + "\n".join(spf) + "\n\n"
    dkim_report = f"DKIM: {dkim_status}\nDetails: {dkim_details}\n" + "\n".join(dkim) + "\n\n"

    return dmarc_report, spf_report, dkim_report

# Main function to generate the security report
def generate_report(url):
    parsed_url = urlparse(url)
    target_domain = parsed_url.netloc
    dmarc_report, spf_report, dkim_report = check_email_security(target_domain)
    headers_report = check_security_headers(url)

    report = [
        "Security Headers Security Report\n",
        f"Target: {url}\n\n",
        "-------------------------------------------\n\n",
        "Email Security Checks:\n",
        "-------------------------------------------\n\n",
        dmarc_report,
        spf_report,
        dkim_report,
        "-------------------------------------------\n\n",
        "Headers Security Checks:\n",
        "-------------------------------------------\n\n",
        *headers_report
    ]
    return report

def save_to_txt(data, filename):
    with open(filename, 'w') as file:
        file.write(''.join(data))

def main():
    while True:
        choice = input(random_color + "Enter '1' to enter a single target URL or '2' to enter a file containing a list of target URLs, or 'exit' to quit: ")
        if choice == '1':
            target_url = input(random_color + "Enter the target URL (e.g., https://example.com): ")
            result = generate_report(target_url)
            domain = target_url.replace("https://", "").replace("http://", "").replace("www.", "").split('/')[0]
            save_to_txt(result, f"security_report_{domain}.txt")
            print(random_color + "Security check completed. Results saved to security_report.txt\nScript executed successfully with the blessing of Dark_Shadow04." + reset)
        elif choice == '2':
            target_file = input("Enter the path to the file containing a list of target URLs: ")
            with open(target_file, 'r') as file:
                target_urls = file.readlines()
                for url in target_urls:
                    url = url.strip()
                    result = generate_report(url)
                    domain = url.replace("https://", "").replace("http://", "").replace("www.", "").split('/')[0]
                    save_to_txt(result, f"security_report_{domain}.txt")
            print(random_color + "Security check completed. Results saved to security_report.txt\nScript executed successfully with the blessing of Dark_Shadow04." + reset)
        elif choice.lower() == 'exit':
            print(random_color + "Script executed successfully with the blessing of Dark_Shadow04." + reset)
            break
        else:
            print(random_color + "Invalid choice. Please enter '1', '2', or 'exit'.")

if __name__ == "__main__":
    main()
