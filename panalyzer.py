# --- Imports ---
import requests
import ssl
import socket
import whois
from urllib.parse import urlparse, unquote
import datetime
import re
import idna
import Levenshtein # For typosquatting check
import matplotlib.pyplot as plt
import os
import time
import urllib3 # To suppress specific warnings

# Suppress only the InsecureRequestWarning from urllib3 needed for potential HTTP checks
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# --- Configuration ---
# List of common legitimate domains to check against for typosquatting
# Add more as needed! Focus on financial, email, social media, shopping sites.
COMMON_LEGIT_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "baidu.com", "wikipedia.org",
    "yahoo.com", "amazon.com", "twitter.com", "instagram.com", "linkedin.com",
    "microsoft.com", "apple.com", "paypal.com", "netflix.com", "ebay.com",
    "reddit.com", "bing.com", "office.com", "twitch.tv", "chase.com",
    "wellsfargo.com", "bankofamerica.com", "aliexpress.com", "live.com",
    "gmail.com", "outlook.com", "hotmail.com", "aol.com", "icloud.com",
    "github.com", "stackoverflow.com", "wordpress.com", "dropbox.com",
    "whatsapp.com", "telegram.org", "signal.org"
]

# Keywords often found in registrant info for privacy services
WHOIS_PRIVACY_KEYWORDS = ['privacy protect', 'whoisguard', 'domains by proxy',
                          'whois privacy', 'domain privacy', 'contact privacy',
                          'redacted for privacy', 'private registration',
                          'whoisproxy', 'domain name proxy']

# Keywords often used in phishing URLs (check domain, path, query)
SUSPICIOUS_KEYWORDS = ['login', 'signin', 'verify', 'secure', 'account', 'update',
                       'confirm', 'password', 'banking', 'ebayisapi', 'activity',
                       'support', 'admin', 'recover', 'credential', 'webscr', 'cmd']


# --- Helper Functions ---

def get_final_url(url, max_redirects=5, timeout=10):
    """
    Follows redirects to find the final destination URL.
    Returns the final URL or the original URL if no redirects/error.
    """
    current_url = url
    try:
        # Use HEAD request to be faster and consume less data
        # `allow_redirects=True` handles following redirects automatically
        # Use a session object to persist parameters like headers across redirects
        session = requests.Session()
        session.max_redirects = max_redirects
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'} # Mimic browser
        response = session.head(current_url, allow_redirects=True, timeout=timeout, verify=False, headers=headers) # verify=False needed sometimes, but less secure

        # `response.url` contains the final URL after redirects
        final_url = response.url
        if final_url != url:
            print(f"Redirect Check: URL redirected from {url} to {final_url}")
        else:
            print("Redirect Check: No redirection detected.")
        return final_url

    except requests.exceptions.TooManyRedirects:
        print(f"Redirect Check: Failed - Exceeded max redirects ({max_redirects})")
        return url # Return original if too many redirects
    except requests.exceptions.RequestException as e:
        print(f"Redirect Check: Error during redirection check: {e}")
        return url # Return original URL on error
    except Exception as e:
        print(f"Redirect Check: Unexpected error: {e}")
        return url

def get_domain_parts(domain):
    """
    Splits domain into subdomain, main domain (SLD), and top-level domain (TLD).
    Handles simple cases like 'www.google.com' and 'google.co.uk'.
    Returns (subdomain, sld, tld) or (None, None, None)
    """
    if not domain:
        return None, None, None

    parts = domain.lower().split('.')
    if len(parts) < 2:
        return None, None, None # Not a valid domain structure (e.g., 'localhost')

    # Common multi-part TLDs (add more if needed for specific regions)
    multi_part_tlds = {'co.uk', 'com.au', 'org.uk', 'gov.uk', 'com.br', 'net.au', 'org.au', 'com.cn', 'net.cn', 'org.cn', 'co.jp', 'co.za'}

    tld = parts[-1]
    sld = parts[-2]
    subdomain_parts = parts[:-2]

    # Check if the last two parts form a known multi-part TLD
    potential_multi_tld = f"{parts[-2]}.{parts[-1]}"
    if potential_multi_tld in multi_part_tlds and len(parts) > 2:
        tld = potential_multi_tld
        sld = parts[-3]
        subdomain_parts = parts[:-3]

    subdomain = ".".join(subdomain_parts) if subdomain_parts else None
    # print(f"Domain Parts: Full='{domain}', Sub='{subdomain}', SLD='{sld}', TLD='{tld}'") # Debug print
    return subdomain, sld, tld


def get_main_domain(domain):
    """Extracts the main domain part (e.g., 'google.com' from 'www.google.com')."""
    subdomain, sld, tld = get_domain_parts(domain)
    if sld and tld:
        return f"{sld}.{tld}"
    return domain # Fallback to returning the original if parsing fails

def get_domain_from_url(url):
    """Extracts the network location (domain) from a full URL."""
    try:
        return urlparse(url).netloc
    except Exception as e:
        print(f"Error parsing URL to get domain: {e}")
        return None

def check_https_and_cert(url):
    """Checks HTTPS and basic certificate validity."""
    result = {'uses_https': False, 'cert_valid': None, 'issuer': None}
    domain = get_domain_from_url(url)
    if not domain:
        return result

    if url.lower().startswith('https://'):
        result['uses_https'] = True
        context = ssl.create_default_context()
        try:
            # Connect directly using sockets for more control over cert info
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    result['cert_valid'] = True # If connection succeeds, requests/ssl considers it valid at this basic level
                    # Try to get issuer info
                    issuer_info = dict(x[0] for x in cert.get('issuer', []))
                    result['issuer'] = issuer_info.get('organizationName', 'Unknown Issuer')
                    print(f"HTTPS Check: Connection successful. Cert appears valid. Issuer: {result['issuer']}")
        except ssl.SSLCertVerificationError as e:
            print(f"HTTPS Check: Certificate validation failed! Error: {e}")
            result['cert_valid'] = False
            result['issuer'] = "Invalid Certificate"
        except ssl.SSLError as e:
            print(f"HTTPS Check: An SSL error occurred (may include cert issues): {e}")
            result['cert_valid'] = False # Treat generic SSL errors as potentially invalid certs
        except socket.timeout:
            print(f"HTTPS Check: Connection timed out.")
            # Cannot determine cert validity
        except socket.gaierror:
             print(f"HTTPS Check: Could not resolve domain name.")
             # Cannot determine cert validity
        except ConnectionRefusedError:
             print(f"HTTPS Check: Connection refused by server.")
             # Cannot determine cert validity
        except Exception as e:
            print(f"HTTPS Check: An unexpected error occurred: {e}")
            # Cannot determine cert validity
    else:
        print("HTTPS Check: URL does not use HTTPS.")
        # Optionally try an HTTP connection to see if the site is even up
        try:
            requests.get(url, timeout=5, verify=False) # Use verify=False for HTTP
            print("HTTP Check: Connection successful (but insecure).")
        except requests.RequestException:
            print("HTTP Check: Could not connect to the non-HTTPS URL.")

    return result


def get_domain_age_and_privacy(domain):
    """Gets domain age (days) and checks for WHOIS privacy indicators."""
    results = {'age_days': None, 'creation_date': None, 'registrar': None, 'whois_privacy': False}
    if not domain:
        return results

    try:
        domain_info = whois.whois(domain)

        # Age
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = min(creation_date) # Use the earliest date if multiple exist
        results['creation_date'] = creation_date

        if creation_date:
            now = datetime.datetime.now(creation_date.tzinfo) # Match timezone if available
            age = now - creation_date
            results['age_days'] = age.days
            print(f"Domain Age Check: Domain '{domain}' created on: {creation_date} ({results['age_days']} days ago)")
        else:
            print(f"Domain Age Check: Could not find creation date for '{domain}'.")

        # Registrar
        results['registrar'] = domain_info.registrar
        if results['registrar']:
            print(f"Domain Info: Registrar: {results['registrar']}")
        else:
            print("Domain Info: Registrar not found.")

        # WHOIS Privacy Check (basic keyword search in raw data)
        raw_whois = domain_info.text.lower() if hasattr(domain_info, 'text') and domain_info.text else ""
        if not raw_whois:
             # Sometimes raw data isn't available directly, try registrant fields
             registrant_org = str(domain_info.get('org', '')).lower()
             registrant_name = str(domain_info.get('name', '')).lower()
             admin_org = str(domain_info.get('admin_org', '')).lower() # Check admin too
             raw_whois = f"{registrant_org} {registrant_name} {admin_org}" # Combine relevant fields


        for keyword in WHOIS_PRIVACY_KEYWORDS:
            if keyword in raw_whois:
                results['whois_privacy'] = True
                print(f"Domain Privacy Check: Detected keyword '{keyword}' suggesting WHOIS privacy is enabled.")
                break
        if not results['whois_privacy']:
             print("Domain Privacy Check: No obvious WHOIS privacy keywords detected.")


    except whois.parser.PywhoisError as e:
        print(f"Domain Age/Privacy Check: WHOIS lookup failed for '{domain}'. Domain might not exist or data is private/unavailable. Error: {e}")
    except Exception as e:
        print(f"Domain Age/Privacy Check: An unexpected error during WHOIS lookup for '{domain}': {e}")

    return results

def check_punycode(domain):
    """Checks if the domain uses Punycode."""
    if not domain: return False
    try:
        # Check if the domain *as given* decodes to something different OR starts with xn--
        decoded_domain = idna.decode(domain.encode('idna')) # Decode from potential IDNA form
        # print(f"Punycode check: Original='{domain}', Decoded='{decoded_domain}'") # Debug
        is_punycode = domain.lower().startswith("xn--") or domain != decoded_domain

        if is_punycode:
             print(f"Punycode Check: Domain '{domain}' uses Punycode (decoded: '{decoded_domain}'). Potential homograph.")
             return True
        else:
             # Check if encoding forces Punycode (contains non-ASCII)
             encoded_ascii = domain.encode('idna').decode('ascii')
             if domain != encoded_ascii and encoded_ascii.startswith('xn--'):
                  print(f"Punycode Check: Domain '{domain}' contains non-ASCII chars requiring Punycode ('{encoded_ascii}'). Potential homograph.")
                  return True

        print(f"Punycode Check: Domain '{domain}' does not appear to use Punycode.")
        return False
    except idna.IDNAError as e:
         print(f"Punycode Check: Invalid domain characters for IDNA processing: {e}")
         return False # Treat invalid as non-punycode for this check, but could be suspicious itself
    except Exception as e:
        print(f"Punycode Check: An unexpected error occurred: {e}")
        return False

def calculate_similarity(domain1, domain2):
    """Calculates similarity ratio between two domains using Levenshtein distance."""
    try:
        distance = Levenshtein.distance(domain1, domain2)
        max_len = max(len(domain1), len(domain2))
        if max_len == 0: return 1.0 # Both empty
        similarity = 1.0 - (distance / max_len)
        return similarity
    except Exception as e:
        print(f"Similarity Calc Error: {e}")
        return 0.0 # Return low similarity on error

def check_typosquatting(domain):
    """Checks domain against common legit domains for typosquatting."""
    results = {'is_typosquatting': False, 'similar_to': None, 'similarity_score': 0.0}
    main_domain_to_check = get_main_domain(domain)
    if not main_domain_to_check: return results

    highest_similarity = 0.0
    most_similar_legit_domain = None

    for legit_domain in COMMON_LEGIT_DOMAINS:
        similarity = calculate_similarity(main_domain_to_check, legit_domain)
        if similarity > highest_similarity:
            highest_similarity = similarity
            most_similar_legit_domain = legit_domain

    # Define thresholds (these are subjective, adjust as needed)
    # High similarity (e.g., 1 character difference) -> likely typosquat
    # Moderate similarity -> potentially suspicious
    TYPO_THRESHOLD_HIGH = 0.90
    TYPO_THRESHOLD_MEDIUM = 0.80

    results['similarity_score'] = highest_similarity

    if highest_similarity >= TYPO_THRESHOLD_HIGH and main_domain_to_check != most_similar_legit_domain:
        results['is_typosquatting'] = True
        results['similar_to'] = most_similar_legit_domain
        print(f"Typosquatting Check: HIGH probability. Domain '{main_domain_to_check}' is {highest_similarity*100:.1f}% similar to '{most_similar_legit_domain}'.")
    elif highest_similarity >= TYPO_THRESHOLD_MEDIUM and main_domain_to_check != most_similar_legit_domain:
        # Moderate similarity could still be a flag, but lower confidence
        # results['is_typosquatting'] = True # Optionally flag medium ones too
        results['similar_to'] = most_similar_legit_domain
        print(f"Typosquatting Check: MEDIUM similarity. Domain '{main_domain_to_check}' is {highest_similarity*100:.1f}% similar to '{most_similar_legit_domain}'. Worth noting.")
    else:
        print(f"Typosquatting Check: Low similarity ({highest_similarity*100:.1f}% max) to known domains.")

    return results


def analyze_url_structure_and_keywords(url):
    """Enhanced analysis of URL structure and keywords."""
    findings = {
        'subdomain_count': 0,
        'path_depth': 0,
        'domain_hyphen_count': 0,
        'domain_digit_count': 0,
        'path_special_char_count': 0,
        'suspicious_keywords_present': False,
        'brand_in_subdomain_suspicious': False, # e.g., paypal.com.secure.net
        'brand_in_path': False,               # e.g., example.com/paypal/login
        'ip_address_in_domain': False,
        'url_length': len(url),
        'decoded_url': None
    }
    try:
        # Decode URL first (e.g., %20 -> space) for keyword analysis
        decoded_url = unquote(url)
        findings['decoded_url'] = decoded_url

        parsed_url = urlparse(decoded_url)
        domain = parsed_url.netloc
        path = parsed_url.path
        query = parsed_url.query

        if not domain: return findings

        # 1. IP Address Check
        ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
        if re.match(ip_pattern, domain.split(':')[0]): # Split port if present
            findings['ip_address_in_domain'] = True
            print("Structure Check: Domain part appears to be an IP address.")
            # If IP, skip most other domain checks
            return findings

        # 2. Domain structure
        subdomain, sld, tld = get_domain_parts(domain)
        main_domain = get_main_domain(domain) # e.g., google.com
        findings['domain_hyphen_count'] = domain.count('-')
        findings['domain_digit_count'] = sum(c.isdigit() for c in domain)
        domain_parts = domain.split('.')
        tld_guess_parts = 2 if main_domain and '.' in main_domain else 1
        findings['subdomain_count'] = max(0, len(domain_parts) - tld_guess_parts)


        print(f"Structure Check: Subdomains: {findings['subdomain_count']}, Hyphens in domain: {findings['domain_hyphen_count']}, Digits in domain: {findings['domain_digit_count']}.")

        # 3. Path Depth & Special Chars
        path_clean = path.strip('/')
        if path_clean:
            findings['path_depth'] = path_clean.count('/') + 1
        # Count non-alphanumeric chars in path (excluding /)
        findings['path_special_char_count'] = len(re.findall(r'[^a-zA-Z0-9/]', path))
        print(f"Structure Check: Path depth: {findings['path_depth']}, Special chars in path: {findings['path_special_char_count']}.")

        # 4. Keyword Analysis (Domain, Subdomain, Path, Query)
        full_check_string = f"{domain} {path} {query}".lower()
        found_keywords = set()
        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in full_check_string:
                findings['suspicious_keywords_present'] = True
                found_keywords.add(keyword)
        if found_keywords:
            print(f"Keyword Check: Found suspicious keywords: {', '.join(found_keywords)}")
        else:
            print("Keyword Check: No common suspicious keywords found.")

        # 5. Brand Name Misplacement Check
        if subdomain: # Only check if there IS a subdomain part
            for brand in COMMON_LEGIT_DOMAINS:
                brand_sld, _, _ = get_domain_parts(brand) # Get 'paypal' from 'paypal.com'
                if brand_sld and brand_sld in subdomain.lower().split('.'):
                    # Check if the *actual* main domain is NOT the brand itself
                    if main_domain != brand:
                        findings['brand_in_subdomain_suspicious'] = True
                        print(f"Structure Check: Potential Brand Misuse! Found '{brand_sld}' in subdomain ('{subdomain}') but main domain is '{main_domain}'.")
                        break # Found one, stop checking brands in subdomain

        # 6. Brand Name in Path Check
        path_lower = path.lower()
        for brand in COMMON_LEGIT_DOMAINS:
            brand_sld, _, _ = get_domain_parts(brand)
            if brand_sld and f'/{brand_sld}/' in path_lower or path_lower.endswith(f'/{brand_sld}'):
                 findings['brand_in_path'] = True
                 print(f"Structure Check: Found brand indicator '{brand_sld}' in the URL path.")
                 break # Found one, stop checking brands in path


        print(f"Structure Check: URL Length: {findings['url_length']} characters.")


    except Exception as e:
        print(f"Structure Check: Error analyzing URL structure/keywords: {e}")

    return findings


def generate_visual_report(url, results, risk_score, risk_category, filename="phishing_analysis_report.jpg"):
    """Generates a JPG image report using Matplotlib."""
    print(f"\nGenerating visual report: {filename}...")
    categories = []
    scores = []
    colors = []
    details = [] # Add more detailed text for the report

    # --- Compile data for the chart ---
    # HTTPS
    https_score = results.get('risk_scores', {}).get('https', 0)
    if https_score > 0:
        categories.append("HTTPS/Cert")
        scores.append(https_score)
        colors.append('red' if https_score >= 3 else 'orange')
        details.append(f"HTTPS/Cert Issue: {results.get('report_flags', {}).get('https', 'Warning')}")

    # Domain Age & Privacy
    age_privacy_score = results.get('risk_scores', {}).get('age_privacy', 0)
    if age_privacy_score > 0:
         categories.append("Domain Age/Privacy")
         scores.append(age_privacy_score)
         colors.append('orange' if results.get('whois_info',{}).get('whois_privacy') else 'yellow')
         details.append(f"Age/Privacy: {results.get('report_flags', {}).get('age_privacy', 'Info')}")

    # Punycode
    puny_score = results.get('risk_scores', {}).get('punycode', 0)
    if puny_score > 0:
         categories.append("Punycode/IDN")
         scores.append(puny_score)
         colors.append('red')
         details.append(f"Punycode Detected: Potential Homograph Attack.")

    # Typosquatting
    typo_score = results.get('risk_scores', {}).get('typosquatting', 0)
    if typo_score > 0:
         categories.append("Typosquatting")
         scores.append(typo_score)
         colors.append('red' if typo_score >= 2 else 'orange')
         details.append(f"Typosquatting: {results.get('report_flags', {}).get('typosquatting', 'Warning')}")

    # Structure
    structure_score = results.get('risk_scores', {}).get('structure', 0)
    if structure_score > 0:
         categories.append("URL Structure")
         scores.append(structure_score)
         colors.append('red' if structure_score >=3 else 'orange')
         details.append(f"Structure Issues: {results.get('report_flags', {}).get('structure', 'Warning')}")

    # Keywords
    keyword_score = results.get('risk_scores', {}).get('keywords', 0)
    if keyword_score > 0:
         categories.append("Keywords")
         scores.append(keyword_score)
         colors.append('yellow')
         details.append("Keywords: Suspicious terms found in URL.")

    # --- Create Plot ---
    fig, ax = plt.subplots(figsize=(10, 7)) # Make figure larger

    if categories:
        # Create horizontal bar chart
        y_pos = range(len(categories))
        ax.barh(y_pos, scores, color=colors, align='center')
        ax.set_yticks(y_pos)
        ax.set_yticklabels(categories)
        ax.invert_yaxis()  # labels read top-to-bottom
        ax.set_xlabel('Risk Contribution Score')
        ax.set_title(f'Phishing Analysis Risk Breakdown\nURL: {url[:60]}{"..." if len(url)>60 else ""}', fontsize=12) # Shorten long URLs

        # Add score labels to bars
        for i, v in enumerate(scores):
             ax.text(v + 0.1, i, str(v), color='blue', va='center', fontweight='bold')

    else:
         ax.text(0.5, 0.5, 'No significant risk factors detected.', horizontalalignment='center', verticalalignment='center', transform=ax.transAxes, fontsize=14)
         ax.set_title(f'Phishing Analysis\nURL: {url[:60]}{"..." if len(url)>60 else ""}', fontsize=12)


    # Add overall assessment text below chart
    plt.figtext(0.5, 0.15, f'Total Risk Score: {risk_score}', ha='center', fontsize=14, weight='bold')
    plt.figtext(0.5, 0.1, f'Assessment: {risk_category}', ha='center', fontsize=14, weight='bold', color='red' if risk_score >=7 else 'orange' if risk_score >=4 else 'green')

    # Add detailed flags text
    # details_text = "\n".join([f"- {d}" for d in details])
    # plt.figtext(0.05, 0.05, "Key Flags:\n" + details_text, ha='left', va='bottom', fontsize=8)


    plt.subplots_adjust(left=0.25, bottom=0.3) # Adjust layout to prevent overlap

    # --- Save and Close ---
    try:
        plt.savefig(filename, format='jpg', dpi=150, bbox_inches='tight')
        print(f"Visual report saved successfully as '{filename}'")
    except Exception as e:
        print(f"Error saving visual report: {e}")

    plt.close(fig) # Close the plot to free memory


def calculate_risk(results):
    """Calculates a risk score and category based on analysis results."""
    risk_score = 0
    risk_category = "Minimal Risk"
    report_flags = {} # Store text flags for the report
    risk_scores = {} # Store score breakdown per category

    # Scoring Weights (Adjust these based on perceived severity)
    weights = {
        'no_https': 3,
        'invalid_cert': 4,
        'unknown_cert_issuer': 1, # Slight penalty if issuer looks odd (e.g., Let's Encrypt might be okay, but 'Unknown' is iffy)
        'domain_age_very_new': 3, # < 60 days
        'domain_age_new': 2,      # < 180 days
        'domain_age_recent': 1,   # < 365 days
        'domain_age_unknown': 1,
        'whois_privacy': 1,       # Small penalty, as it's common but also used by phishers
        'punycode': 3,
        'typo_high_similarity': 4,
        'typo_medium_similarity': 1,
        'ip_domain': 5,
        'excessive_subdomains': 2, # > 2
        'multiple_subdomains': 1, # = 2
        'long_url': 1,            # > 75 chars
        'excessive_hyphens': 1,   # > 3 in domain
        'excessive_digits': 1,    # > 3 in domain
        'suspicious_keywords': 1,
        'brand_in_subdomain': 3,
        'brand_in_path': 1,
        'path_depth_high': 1,     # > 4
        'special_chars_path': 1,  # > 3
        'redirected': 1 # Add slight risk if URL was shortened/redirected
    }

    https_risk = 0
    https_info = results.get('https_check', {})
    if not https_info.get('uses_https', False):
        risk_score += weights['no_https']
        https_risk += weights['no_https']
        report_flags['https'] = "No HTTPS (Insecure)"
    elif https_info.get('cert_valid') == False:
        risk_score += weights['invalid_cert']
        https_risk += weights['invalid_cert']
        report_flags['https'] = "Invalid HTTPS Certificate"
    elif https_info.get('issuer', '').lower() in ['unknown issuer', 'invalid certificate']:
         risk_score += weights['unknown_cert_issuer']
         https_risk += weights['unknown_cert_issuer']
         report_flags['https'] = f"Suspicious Cert Issuer: {https_info.get('issuer')}"
    risk_scores['https'] = https_risk


    age_privacy_risk = 0
    whois_info = results.get('whois_info', {})
    domain_age = whois_info.get('age_days')
    if domain_age is not None:
        if domain_age < 60:
            risk_score += weights['domain_age_very_new']
            age_privacy_risk += weights['domain_age_very_new']
            report_flags['age_privacy'] = f"Domain Very New ({domain_age} days)"
        elif domain_age < 180:
            risk_score += weights['domain_age_new']
            age_privacy_risk += weights['domain_age_new']
            report_flags['age_privacy'] = f"Domain New ({domain_age} days)"
        elif domain_age < 365:
            risk_score += weights['domain_age_recent']
            age_privacy_risk += weights['domain_age_recent']
            report_flags['age_privacy'] = f"Domain Recent ({domain_age} days)"
    else:
        risk_score += weights['domain_age_unknown']
        age_privacy_risk += weights['domain_age_unknown']
        report_flags['age_privacy'] = "Domain Age Unknown"

    if whois_info.get('whois_privacy', False):
        risk_score += weights['whois_privacy']
        age_privacy_risk += weights['whois_privacy']
        report_flags['age_privacy'] = report_flags.get('age_privacy', '') + " + WHOIS Privacy"
    risk_scores['age_privacy'] = age_privacy_risk


    punycode_risk = 0
    if results.get('punycode_check', False):
        risk_score += weights['punycode']
        punycode_risk += weights['punycode']
        report_flags['punycode'] = "Uses Punycode/IDN"
    risk_scores['punycode'] = punycode_risk


    typo_risk = 0
    typo_info = results.get('typosquat_check', {})
    if typo_info.get('is_typosquatting', False):
        sim_score = typo_info.get('similarity_score', 0)
        similar_to = typo_info.get('similar_to', 'Unknown')
        if sim_score >= 0.90: # Corresponds to TYPO_THRESHOLD_HIGH
             risk_score += weights['typo_high_similarity']
             typo_risk += weights['typo_high_similarity']
             report_flags['typosquatting'] = f"High Similarity ({sim_score*100:.0f}%) to '{similar_to}'"
        elif sim_score >= 0.80: # Corresponds to TYPO_THRESHOLD_MEDIUM
             risk_score += weights['typo_medium_similarity']
             typo_risk += weights['typo_medium_similarity']
             report_flags['typosquatting'] = f"Medium Similarity ({sim_score*100:.0f}%) to '{similar_to}'"
    risk_scores['typosquatting'] = typo_risk


    structure_risk = 0
    struct = results.get('structure_analysis', {})
    if struct.get('ip_address_in_domain', False):
        risk_score += weights['ip_domain']
        structure_risk += weights['ip_domain']
        report_flags['structure'] = "Uses IP Address Domain"
    else: # Only apply other structure checks if not IP
        if struct.get('subdomain_count', 0) > 2:
            risk_score += weights['excessive_subdomains']
            structure_risk += weights['excessive_subdomains']
            report_flags['structure'] = "Excessive Subdomains"
        elif struct.get('subdomain_count', 0) == 2:
             risk_score += weights['multiple_subdomains']
             structure_risk += weights['multiple_subdomains']
             report_flags['structure'] = "Multiple Subdomains"

        if struct.get('domain_hyphen_count', 0) > 3:
             risk_score += weights['excessive_hyphens']
             structure_risk += weights['excessive_hyphens']
             report_flags['structure'] = report_flags.get('structure','')+ " + Many Hyphens"

        if struct.get('domain_digit_count', 0) > 3:
             risk_score += weights['excessive_digits']
             structure_risk += weights['excessive_digits']
             report_flags['structure'] = report_flags.get('structure','')+ " + Many Digits"

        if struct.get('brand_in_subdomain_suspicious', False):
            risk_score += weights['brand_in_subdomain']
            structure_risk += weights['brand_in_subdomain']
            report_flags['structure'] = report_flags.get('structure','')+ " + Brand in Subdomain"

    # Apply these even if IP based
    if struct.get('url_length', 0) > 75:
        risk_score += weights['long_url']
        structure_risk += weights['long_url']
        report_flags['structure'] = report_flags.get('structure','')+ " + Long URL"

    if struct.get('path_depth', 0) > 4:
        risk_score += weights['path_depth_high']
        structure_risk += weights['path_depth_high']
        report_flags['structure'] = report_flags.get('structure','')+ " + Deep Path"

    if struct.get('path_special_char_count', 0) > 3:
         risk_score += weights['special_chars_path']
         structure_risk += weights['special_chars_path']
         report_flags['structure'] = report_flags.get('structure','')+ " + Path Special Chars"

    risk_scores['structure'] = structure_risk


    keyword_risk = 0
    if struct.get('suspicious_keywords_present', False):
        risk_score += weights['suspicious_keywords']
        keyword_risk += weights['suspicious_keywords']
        report_flags['keywords'] = "Suspicious Keywords Found"

    if struct.get('brand_in_path', False):
        risk_score += weights['brand_in_path']
        keyword_risk += weights['brand_in_path'] # Count brand in path under keywords maybe?
        report_flags['keywords'] = report_flags.get('keywords','')+ " + Brand in Path"
    risk_scores['keywords'] = keyword_risk

    # Redirect Risk
    if results.get('final_url') != results.get('original_url'):
         risk_score += weights['redirected']
         # Add this risk to structure or create a new category? Let's add to structure for now
         risk_scores['structure'] = risk_scores.get('structure', 0) + weights['redirected']
         report_flags['structure'] = report_flags.get('structure','')+ " + Redirected URL"


    # Determine Category
    if risk_score >= 10:
        risk_category = "VERY HIGH RISK"
    elif risk_score >= 7:
        risk_category = "HIGH RISK"
    elif risk_score >= 4:
        risk_category = "MEDIUM RISK"
    elif risk_score >= 1:
        risk_category = "LOW RISK"

    results['risk_score'] = risk_score
    results['risk_category'] = risk_category
    results['report_flags'] = report_flags
    results['risk_scores'] = risk_scores # Store the breakdown

    print(f"\nRisk Assessment: Score = {risk_score}, Category = {risk_category}")
    if report_flags:
        print("Contributing Factors:")
        for category, flag in report_flags.items():
            print(f"- {flag} (Category: {category}, Score Impact: ~{risk_scores.get(category, '?')})")

    return risk_score, risk_category


# --- Main Execution ---
if __name__ == "__main__":
    target_url = input("Enter the URL to analyze: ")
    original_url = target_url # Keep track of the original input

    # Basic check: Add http:// if missing for parsing/initial connection attempt.
    if not target_url.startswith('http://') and not target_url.startswith('https://'):
        print("Warning: URL scheme missing. Assuming 'http://' initially.")
        target_url = 'http://' + target_url

    # --- Start Analysis ---
    print(f"\nAnalyzing URL: {original_url}")
    all_results = {'original_url': original_url}

    # 1. Follow Redirects (Crucial First Step!)
    print("\nRunning Redirect Check...")
    final_url = get_final_url(target_url)
    all_results['final_url'] = final_url
    # Use the *final* URL for most subsequent checks
    analysis_url = final_url

    # 2. Extract Domain from the *final* URL
    domain_name = get_domain_from_url(analysis_url)
    if not domain_name:
        print("FATAL: Could not extract domain name from the final URL. Aborting.")
        exit()
    all_results['domain'] = domain_name
    print(f"Using final domain for analysis: {domain_name}")


    # --- Run Analyses on Final URL/Domain ---
    # Need to ensure functions use the 'analysis_url' or 'domain_name' appropriately

    print("\nRunning HTTPS Check...")
    all_results['https_check'] = check_https_and_cert(analysis_url) # Pass final URL

    print("\nRunning Domain Age & Privacy Check...")
    all_results['whois_info'] = get_domain_age_and_privacy(domain_name) # Pass final domain

    print("\nRunning Punycode Check...")
    all_results['punycode_check'] = check_punycode(domain_name) # Pass final domain

    print("\nRunning Typosquatting Check...")
    all_results['typosquat_check'] = check_typosquatting(domain_name) # Pass final domain

    print("\nRunning URL Structure & Keyword Analysis...")
    # Pass the final, potentially decoded URL from structure analysis if needed elsewhere
    all_results['structure_analysis'] = analyze_url_structure_and_keywords(analysis_url) # Pass final URL

    # --- Calculate Risk ---
    print("\nCalculating Risk Score...")
    risk_score, risk_category = calculate_risk(all_results) # Pass the whole results dict

    # --- Generate Visual Report ---
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    report_filename = f"phishing_report_{domain_name}_{timestamp}.jpg"
    generate_visual_report(original_url, all_results, risk_score, risk_category, filename=report_filename)

    print("\n--- Analysis Complete ---")
    print(f"Original URL: {original_url}")
    if final_url != original_url:
        print(f"Final URL (after redirects): {final_url}")
    print(f"Overall Risk Assessment: {risk_category} (Score: {risk_score})")
    print(f"Visual report saved as: {report_filename}")
    print("\nDisclaimer: This tool uses heuristics and cannot guarantee 100% accuracy. Always exercise caution.")
    print("\nMade by https://github.com/sahibcode/")