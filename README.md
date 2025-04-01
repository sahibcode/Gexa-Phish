# Gexa-Phish

# Enhanced Phishing URL Analyzer 🎣

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) <!-- Optional: Add a license badge if you choose one -->

**A sophisticated Python tool that goes beyond simple blacklists to analyze URLs for potential phishing threats using multiple heuristic checks and generates a visual risk report.**

## The Problem

Phishing attacks are constantly evolving, using new domains, URL shorteners, and clever disguises to trick users. Basic security measures often fall short. This tool addresses the need for a deeper, more analytical approach to identify potentially malicious URLs before they cause harm.

## Overview

The Enhanced Phishing URL Analyzer takes a URL as input and performs a comprehensive assessment based on various technical and structural indicators. It aims to uncover suspicious characteristics often employed in phishing campaigns.

## ✨ Core Features & Capabilities

*   **🔗 Proactive URL Unshortening:** Follows redirects (e.g., `bit.ly`, `t.co`) to analyze the *final* destination URL.
*   **🔒 HTTPS & Certificate Check:** Verifies if the site uses HTTPS and performs basic validation of the SSL/TLS certificate, including checking the issuer.
*   **📅 Domain Age Analysis:** Uses WHOIS lookups to determine the domain's creation date. Very new domains are highly suspicious.
*   **🕵️ WHOIS Privacy Detection:** Checks if domain registration details are hidden behind privacy services (a common tactic for malicious actors).
*   **🅰️ Punycode/IDN Homograph Detection:** Identifies domains using Punycode (`xn--...`), which can be used to visually impersonate legitimate domains (e.g., using Cyrillic 'а' vs. Latin 'a').
*   **🎭 Typosquatting & Similarity Check:** Compares the domain against known legitimate brands (Google, PayPal, etc.) using Levenshtein distance to detect slight misspellings (`paypa1.com`, `micros0ft.com`).
*   **🏗️ In-Depth URL Structure Analysis:**
    *   Detects IP addresses used as domains.
    *   Counts subdomains (excessive levels are risky).
    *   Analyzes hyphen and digit frequency in the domain.
    *   Checks URL path depth and special character usage.
    *   Scans for suspicious keywords ('login', 'verify', 'secure', 'password', etc.).
    *   Flags brand names found in unusual places (e.g., `paypal.com.malicious.net`).
    *   Considers overall URL length.
*   **💯 Heuristic Risk Scoring:** Aggregates findings and applies weights to calculate a final risk score.
*   **📊 Categorical Assessment:** Classifies the URL risk as Minimal, Low, Medium, High, or Very High.
*   **🖼️ Automated Visual Report:** **Generates a JPG image** summarizing the risk breakdown by category for easy assessment and sharing.

## ⚙️ How It Works

The script performs the following steps:

1.  **Unshorten:** Resolves the input URL to its final destination.
2.  **Parse:** Breaks down the final URL into components (scheme, domain, path).
3.  **Analyze:** Runs checks across multiple modules:
    *   HTTPS/Certificate Status (`ssl`, `socket`)
    *   Domain Age & WHOIS Privacy (`python-whois`)
    *   Punycode Presence (`idna`)
    *   Typosquatting Similarity (`Levenshtein`)
    *   URL Structure & Keywords (`re`, `urllib.parse`)
4.  **Score:** Calculates a risk score based on the weighted findings.
5.  **Report:** Generates a visual JPG report using `matplotlib` and prints a summary to the console.

## 🛠️ Technology Stack

*   Python 3
*   Libraries:
    *   `requests` (HTTP requests, redirects)
    *   `python-whois` (WHOIS lookups)
    *   `python-Levenshtein` (String similarity/typosquatting)
    *   `matplotlib` (Visual report generation)
    *   `Pillow` (Image saving for matplotlib)
    *   `urllib3` (Dependency, warning management)
    *   Standard libraries: `ssl`, `socket`, `urllib.parse`, `datetime`, `re`, `idna`, `os`, `time`

## 🚀 Installation

1.  **Clone the repository (or download the script):**
    ```bash
    git clone <your-repo-url>
    cd <your-repo-directory>
    ```
2.  **Install required Python libraries:**
    ```bash
    pip install requests python-whois python-Levenshtein matplotlib Pillow urllib3
    ```
    *   **Note:** `python-Levenshtein` sometimes requires C++ build tools. If installation fails, you may need to install build essentials/tools for your operating system (e.g., `sudo apt-get install build-essential python3-dev` on Debian/Ubuntu, or install "Microsoft C++ Build Tools" on Windows). Alternatively, consider using `pip install fuzzywuzzy` and adapting the similarity function in the code.

## ▶️ Usage

1.  Navigate to the script's directory in your terminal.
2.  Run the script using Python:
    ```bash
    python phishing_analyzer.py
    ```
    *(Replace `phishing_analyzer.py` with the actual script filename if you renamed it.)*
3.  When prompted, enter the full URL you want to analyze and press Enter.
4.  The analysis results will be printed to the console.
5.  A visual report summarizing the findings will be saved as a JPG image (e.g., `phishing_report_example.com_YYYYMMDD-HHMMSS.jpg`) in the same directory.

    **(Example of a generated report - Consider adding a screenshot here!)**
    <!-- ![Example Report](path/to/example_report.jpg) -->

## ⚠️ Limitations & Disclaimer

*   **Heuristic-Based:** This tool uses rules of thumb and pattern matching. It **cannot guarantee 100% accuracy**. Clever phishing sites might evade detection, and legitimate sites might occasionally trigger warnings (false positives).
*   **No Real-time Blacklists:** This version does *not* connect to external blacklist services (like Google Safe Browsing), which would require API keys and further setup.
*   **WHOIS Data:** The accuracy of domain age and privacy checks depends on the availability and reliability of WHOIS data, which can sometimes be restricted or incomplete.
*   **Use Wisely:** This tool is intended as an aid for analysis and awareness. **Always exercise caution and critical thinking** when clicking links or entering sensitive information online.

## 🌱 Future Enhancements

*   Integration with real-time blacklist APIs (e.g., Google Safe Browsing, PhishTank, VirusTotal).
*   Website content analysis (checking for forms, suspicious scripts).
*   Screenshot generation and analysis.
*   Machine learning model integration for improved classification.
*   Graphical User Interface (GUI).

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details (Optional: Create a LICENSE file with the MIT license text).

## 🤝 Contributing (Optional)

Contributions, issues, and feature requests are welcome! Please feel free to fork the repository and submit pull requests.

---


Key changes for GitHub README:

Markdown Formatting: Uses #, ##, ### for headings, * for bullet points, bash ... for code blocks, `code` for inline code/commands/filenames.

Structure: Organized logically with clear sections like Overview, Features, Installation, Usage, etc.

Conciseness: Summarized longer explanations from the report while retaining key information.

Emphasis: Used bold (**) for key terms and features.

Badges: Added an optional MIT license badge (you can choose a different license or remove it).

Clarity for Users: Installation and Usage steps are clear and actionable.

Visual Report Highlight: Explicitly mentions the JPG report generation and includes a placeholder comment for potentially embedding an example image.

Standard Sections: Included common README sections like License and optional Contributing guidelines.
