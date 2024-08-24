# ScamTrail

ScamTrail is a powerful tool designed to assist in the investigation of scam and/or phishing websites. It provides valuable information about suspicious URLs, helping investigators gather leads on domain registrars and hosting providers to report malicious activities. Due to my lack of knowledge with Python I developed the script with help of OpenAI's [ChatGPT](https://chat.openai.com) and Anthropic's [Claude.ai](https://www.claude.ai).

## Features

- Follow and analyze URL redirects
- Retrieve WHOIS information for domains
- Perform DNS lookups (A, NS, and CNAME records)
- Get IP address information and geolocation
- Perform reverse DNS lookups
- Calculate domain age
- Detect Cloudflare usage
- Generate comprehensive PDF reports

## Installation

### Prerequisites

- Python 3.7+
- pip (Python package manager)

### Windows

1. Install Python from the [official website](https://www.python.org/downloads/windows/).
2. Open Command Prompt and run:
   ```
   pip install asyncio aiohttp aiodns python-whois weasyprint pycountry python-dotenv Jinja2 aiofiles requests
   ```

### Linux

1. Install Python and pip using your distribution's package manager. For Ubuntu/Debian:
   ```
   sudo apt update
   sudo apt install python3 python3-pip
   ```
2. Install the required packages:
   ```
   pip3 install asyncio aiohttp aiodns python-whois weasyprint pycountry python-dotenv Jinja2 aiofiles requests
   ```

## Usage

1. Clone the repository:
   ```
   git clone https://github.com/crispy78/ScamTrail.git
   cd scamtrail
   ```
2. Run the script:
   ```
   python scamtrail.py
   ```
3. Enter the URL you want to investigate when prompted.
4. The script will generate a PDF report with the results.

## GitHub Codespaces

To run ScamTrail in GitHub Codespaces:

1. Open the repository in GitHub Codespaces.
2. In the terminal, install the required packages:
   ```
   pip install asyncio aiohttp aiodns python-whois weasyprint pycountry python-dotenv Jinja2 aiofiles requests
   ```
3. Run the script:
   ```
   python scamtrail.py
   ```

## Intended Use

ScamTrail is designed for the investigation of suspected scam and phishing websites. It provides investigators with valuable information to:

- Identify the true destination of suspicious links
- Gather information about domain registration and hosting
- Locate potential perpetrators geographically
- Detect obfuscation techniques like Cloudflare usage

This information can be used to:
- Report malicious activities to domain registrars and hosting providers
- Assist law enforcement in their investigations
- Educate users about ongoing scams and phishing attempts

Remember to always use this tool ethically and in compliance with applicable laws and regulations.

## Contributing

Contributions to improve ScamTrail are welcome. Please feel free to submit pull requests or open issues to discuss potential enhancements.
