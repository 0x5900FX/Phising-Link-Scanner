import requests
import validators
import tldextract


# Step 1: Get URL from user and validate it
def get_url():
    url = input("Enter a URL to scan: ").strip()
    if not validators.url(url):
        print("Invalid URL format! Example: http://example.com or https://example.com")
        return None
    return url


# Step 2: Unshorten the URL
def unshorten_url(url):
    try:
        response = requests.head(url, allow_redirects=True, timeout=10)
        if response.status_code != 200:
            print("Warning: Site is down or unreachable.")
        return response.url  # Return the final URL after following redirects
    except requests.exceptions.RequestException as e:
        print(f"Error unshortening URL: {e}")
        return url  # Return the original URL if unshortening fails


# Step 3: Analyze the domain for typosquatting
def analyze_domain(url):
    extracted = tldextract.extract(url)
    domain = f"{extracted.domain}.{extracted.suffix}"

    # List of trusted domains (add more as needed)
    trusted_domains = ["cisco.com", "paypal.com", "facebook.com", "twitter.com", "yahoo.com"]

    # Check if the domain mimics a trusted domain
    for trusted in trusted_domains:
        if domain != trusted and trusted in domain:
            return f"Suspicious domain: {domain} mimics {trusted}"
    return None


# Step 4: Check for phishing indicators in the URL
def analyze_url(url):
    # Analyze the domain for typosquatting
    domain_warning = analyze_domain(url)
    if domain_warning:
        print(domain_warning)

    # Check for IP address in URL
    if "://" in url:
        path = url.split("://")[1]
        if any(part.replace(".", "").isdigit() for part in path.split("/")[0].split(".")):
            print("Warning: URL contains an IP address instead of a domain name.")

    # Check for suspicious keywords in the URL path
    suspicious_keywords = ["login", "verify", "account", "banking", "password"]
    for keyword in suspicious_keywords:
        if keyword in url.lower():
            print(f"Warning: Suspicious keyword '{keyword}' found in URL.")

    # Check if the URL uses HTTPS
    if not url.startswith("https://"):
        print("Warning: URL does not use HTTPS (not secure).")


# Step 5: Main function to tie everything together
def main():
    # Get URL from user
    url = get_url()
    if not url:
        return  # Exit if URL is invalid

    # Unshorten the URL
    final_url = unshorten_url(url)
    print(f"Scanning URL: {final_url}")

    # Analyze the URL for phishing indicators
    analyze_url(final_url)


# Run the program
if __name__ == "__main__":
    main()