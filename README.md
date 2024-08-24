# ScamTrail

ScamTrail is a powerful tool designed to gather comprehensive information about potential phishing or scam websites. It provides users with detailed data to assist in reporting these sites to relevant organizations and authorities.

## Features

- URL redirection tracing
- WHOIS information retrieval
- DNS record analysis
- IP geolocation
- Cloudflare usage detection
- Domain age calculation
- Reverse DNS lookup
- Comprehensive PDF report generation

## Purpose

The primary goal of ScamTrail is to equip users with the necessary information to:

1. Identify potentially malicious websites
2. Gather evidence for reporting to hosting providers, domain registrars, and law enforcement
3. Understand the infrastructure behind suspicious URLs
4. Make informed decisions about the legitimacy of a website

## Installation

### Prerequisites

- Python 3.7+
- pip (Python package installer)

### Windows

1. Install Python from [python.org](https://www.python.org/downloads/windows/)
2. Open Command Prompt and run:

```
pip install -r requirements.txt
```

### Linux

1. Most Linux distributions come with Python pre-installed. If not, use your distribution's package manager to install Python 3.
2. Open a terminal and run:

```
pip3 install -r requirements.txt
```

## Usage

1. Clone the repository:

```
git clone https://github.com/yourusername/scamtrail.git
cd scamtrail
```

2. Run the script:

```
python scamtrail.py
```

3. Enter the URL when prompted.

4. The script will generate a PDF report in the same directory.

## Running from GitHub Codespaces

1. Open the repository in GitHub Codespaces.
2. In the terminal, run:

```
pip install -r requirements.txt
python scamtrail.py
```

3. Enter the URL when prompted.

## Configuration

You can configure some options by creating a `.env` file in the project root:

```
MAX_REDIRECTS=10
PDF_OUTPUT_FILE=scamtrail-report.pdf
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is for educational and investigative purposes only. Always respect privacy laws and terms of service when using this tool.
