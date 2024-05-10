import time
import subprocess
import random

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
print(random_color + "sec-head script by: Dark_Shadow04" + reset)
print(random_color + "https://github.com/DarkShadow04" + reset)
print(random_color + "Copyright 2023 Dark_Shadow04" + reset)


# Define the list of security headers to check
HEADERS = {
    "Content-Security-Policy": "Controls resources the user agent is allowed to load for a given page.",
    "X-Content-Type-Options": "Prevents browsers from MIME-sniffing a response away from the declared content-type.",
    "X-Frame-Options": "Prevents your webpage from being put in an iframe.",
    "X-XSS-Protection": "Enables the Cross-site scripting (XSS) filter built into most recent web browsers.",
    "Strict-Transport-Security": "Instructs web browsers to access your website only over HTTPS.",
    "Referrer-Policy": "Controls how much referrer information should be included with requests.",
    "Feature-Policy": "Allows web developers to selectively enable and disable use of various browser features.",
    "Public-Key-Pins": "Associates a specific cryptographic public key with a certain web server to decrease the risk of MITM attacks.",
    "Expect-CT": "Allows sites to opt in to reporting and/or enforcement of Certificate Transparency requirements.",
    "Content-Security-Policy-Report-Only": "Allows web developers to experiment with policies by monitoring (but not enforcing) their effects.",
    "Access-Control-Allow-Origin": "Indicates whether the response can be shared with requesting code from the given origin.",
    "Access-Control-Allow-Methods": "Indicates which HTTP methods are allowed on a particular endpoint.",
    "Access-Control-Allow-Headers": "Indicates which headers can be used during the actual request.",
    "Access-Control-Allow-Credentials": "Indicates whether the response can be exposed when the credentials flag is true.",
    "Access-Control-Expose-Headers": "Lets a server whitelist headers that browsers are allowed to access.",
    "Access-Control-Max-Age": "Indicates how long the results of a preflight request can be cached.",
    "X-Permitted-Cross-Domain-Policies": "Controls whether Flash and other plugins may access resources from other domains.",
    "Clear-Site-Data": "Gives a web developer the ability to clear out a user’s local data for a particular website.",
    "Content-Disposition": "Indicates if the browser should display a save/download dialog for the response.",
    "Cross-Origin-Opener-Policy": "Allows a web page to opt into the same-origin policy.",
    "Cross-Origin-Embedder-Policy": "Allows a web page to control whether and how a cross-origin document may embed itself.",
    "X-Content-Security-Policy": "Controls resources the user agent is allowed to load for a given page.",
    "X-DNS-Prefetch-Control": "Controls DNS prefetching, which performs domain name resolution in the background.",
    "Content-Language": "Specifies the language(s) of the intended audience for the enclosed content.",
    "Cache-Control": "Tells all caching mechanisms from server to client whether they may cache this object.",
    "Expires": "Gives the date/time after which the response is considered stale.",
    "Pragma": "Provides directives for cache handling in client-server communication.",
    "Report-To": "Allows the server to specify where to send reports when a Content Security Policy violation is detected."
}

def check_security_headers(url):
    print(f"Checking security headers for {url}...\n")
    result = []
    for header, description in HEADERS.items():
        print(f"Scanning header: {header}...")
        time.sleep(5)  # Wait for 5 seconds before scanning to prevent rate limiting
        cmd = f"curl -sI {url} | grep -i {header.lower()}"
        output = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if output.returncode == 0:
            result.append(f"Header: {header}\nDescription: {description}\nStatus: Present\n\n")
        else:
            result.append(f"Header: {header}\nDescription: {description}\nStatus: Not Present\n\n")
    return result

def save_to_txt(data, filename):
    with open(filename, 'w') as file:
        file.write('\n'.join(data))

def main():
    target_url = input("Enter the target URL (e.g., https://example.com): ")
    result = check_security_headers(target_url)
    report_content = [
        "Security Headers Security Report\n",
        f"Target: {target_url}\n\n",
        "-------------------------------------------\n\n",
        *result
    ]
    save_to_txt(report_content, "security_headers.txt")
    print("Security headers check completed. Results saved to security_headers.txt")

if __name__ == "__main__":
    main()

# Script execution confirmation
print(random_color + "Script executed successfully with the blessing of Dark_Shadow04." + reset)
